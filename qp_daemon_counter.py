#!/usr/bin/env python3
"""
qp_daemon_counter.py  —— 技术路线 B：rdma statistic counter 定时轮询
=======================================================================

测量量: 每个 QP 的 **请求次数** + **DCQCN 拥塞信号** + **错误计数器** delta

原理:
  通过 `rdma statistic qp set auto type on` 让内核为每种 QP 类型分配
  硬件 counter 对象；再定期调用 `rdma -j statistic qp show` 读取 JSON，
  计算相邻两次采样间的 delta。

关于"不同操作原语是否需要不同 counter"：
  - **不需要**。mlx5 per-QP counter 对象内包含多个字段，不同原语
    对应不同字段（rx_write_requests / rx_read_requests / rx_atomic_requests），
    同一 counter 对象内并列存在。
  - `auto type on` 中的"type"指 **QP 类型**（RC / UC / UD），
    不是操作类型。同类型的 QP 共享一个 counter 对象。
  - 因此，你不需要为 WRITE / READ / SEND 分别部署 counter，
    一个 auto mode 开启即可同时捕获所有操作类型的 delta。

两端部署说明:
  Sender 侧  → tx 端可见: np_cnp_sent（作为 Notification Point 发出 CNP）
  Receiver 侧→ rx 端可见: rx_write_requests, rx_read_requests, rp_cnp_handled

优点:
  • 两端都可部署，无需特殊二进制符号
  • 同时输出 DCQCN 拥塞信号（CNP 发送/处理量），对调参有直接价值
  • 硬件计数器，无应用侧侵入

局限:
  • 子进程调用延迟 ~10–20ms → 最小可靠采样间隔 50ms
  • 仅给**请求次数**，不直接提供字节数
    （字节 = 请求次数 × 固定消息大小，在 Simulator 场景下可估算）
  • `rdma statistic` 计数器粒度为 counter 对象（可能覆盖多个 QP）

用法:
  sudo python3 qp_daemon_counter.py                    # 每 100ms 采样一次
  sudo python3 qp_daemon_counter.py -c 200             # 改为每 200ms
  sudo python3 qp_daemon_counter.py -d mlx5_1 -p 1    # 指定设备
  sudo python3 qp_daemon_counter.py -q                 # 静默
"""

import argparse
import ctypes
import datetime
import json
import os
import signal
import subprocess
import time
from collections import OrderedDict
from bcc import BPF

# ──────────────────────────── 常量 ────────────────────────────

LIBIBVERBS_PATH          = "/lib/x86_64-linux-gnu/libibverbs.so"
DEFAULT_RDMA_DEVICE      = "mlx5_0"
DEFAULT_RDMA_PORT        = 1
DEFAULT_COUNTER_MS       = 100   # rdma statistic 轮询间隔 (ms)
DEFAULT_REPORT_INTERVAL_S= 5     # 活跃 QP 汇总间隔 (s)
PERF_POLL_MS             = 50    # perf buffer 超时 (ms)

# 重点关注的 counter 字段（其余非零字段也会打印）
HIGHLIGHT_FIELDS = {
    # DCQCN 拥塞信号
    "np_cnp_sent", "np_ecn_marked_roce_packets",
    "rp_cnp_handled", "rp_cnp_ignored",
    "roce_slow_restart", "roce_slow_restart_cnps",
    # 吞吐 / 操作类型
    "rx_write_requests", "rx_read_requests", "rx_atomic_requests",
    # 错误
    "packet_seq_err", "rnr_nak_retry_err", "out_of_buffer",
    "req_transport_retries_exceeded", "resp_cqe_error",
}

EVENT_QP_MODIFY  = 2
EVENT_QP_DESTROY = 3
NO_STATE_CHANGE  = 0xFFFFFFFF
QP_STATE_NAMES   = {0:"RESET",1:"INIT",2:"RTR",3:"RTS",4:"SQD",5:"SQE",6:"ERR"}

# ──────────────────────────── BPF 生命周期追踪（与 uprobe 版相同） ────────────────────────────

BPF_PROGRAM = r"""
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include <linux/ptrace.h>

#define IBV_QP_STATE    (1 <<  0)
#define IBV_QP_AV       (1 <<  7)
#define IBV_QP_DEST_QPN (1 << 20)
#define EVENT_QP_MODIFY   2
#define EVENT_QP_DESTROY  3
#define NO_STATE_CHANGE   0xFFFFFFFF

struct ibv_qp_stub {
    void *context, *qp_context, *pd, *send_cq, *recv_cq, *srq;
    uint32_t handle, qp_num;
};
union ibv_gid {
    uint8_t raw[16];
    struct { __be64 subnet_prefix; __be64 interface_id; } global;
};
struct ibv_global_route { union ibv_gid dgid; uint32_t flow_label;
                          uint8_t sgid_index, hop_limit, traffic_class; };
struct ibv_ah_attr { struct ibv_global_route grh; uint16_t dlid;
                     uint8_t sl, src_path_bits, static_rate, is_global, port_num; };
struct ibv_qp_cap { uint32_t max_send_wr,max_recv_wr,max_send_sge,max_recv_sge,max_inline_data; };
struct ibv_qp_attr_stub {
    int qp_state, cur_qp_state, path_mtu, path_mig_state;
    uint32_t qkey, rq_psn, sq_psn, dest_qp_num;
    unsigned int qp_access_flags;
    struct ibv_qp_cap cap;
    struct ibv_ah_attr ah_attr;
};
struct qp_event {
    uint32_t event_type, qp_num, dest_qp_num, qp_state, dest_ip, pid;
    uint64_t timestamp_ns;
};
BPF_PERF_OUTPUT(events);

int trace_modify_qp(struct pt_regs *ctx) {
    struct ibv_qp_stub      qp   = {};
    struct ibv_qp_attr_stub attr = {};
    int attr_mask = (int)PT_REGS_PARM3(ctx);
    bpf_probe_read_user(&qp,   sizeof(qp),   (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read_user(&attr, sizeof(attr),  (void *)PT_REGS_PARM2(ctx));
    struct qp_event ev = {};
    ev.event_type   = EVENT_QP_MODIFY;
    ev.qp_num       = qp.qp_num;
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.qp_state     = NO_STATE_CHANGE;
    if (attr_mask & IBV_QP_STATE)    ev.qp_state    = attr.qp_state;
    if (attr_mask & IBV_QP_DEST_QPN) ev.dest_qp_num = attr.dest_qp_num;
    if (attr_mask & IBV_QP_AV) {
        uint32_t dIP = (uint32_t)(attr.ah_attr.grh.dgid.global.interface_id >> 32);
        ev.dest_ip = bpf_ntohl(dIP);
    }
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
int trace_destroy_qp(struct pt_regs *ctx) {
    struct ibv_qp_stub qp = {};
    bpf_probe_read_user(&qp, sizeof(qp), (void *)PT_REGS_PARM1(ctx));
    struct qp_event ev = {};
    ev.event_type = EVENT_QP_DESTROY;
    ev.qp_num     = qp.qp_num;
    ev.qp_state   = NO_STATE_CHANGE;
    ev.pid        = bpf_get_current_pid_tgid() >> 32;
    ev.timestamp_ns = bpf_ktime_get_ns();
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

# ──────────────────────────── 用户态数据结构 ────────────────────────────

class QPEvent(ctypes.Structure):
    _fields_ = [
        ("event_type",  ctypes.c_uint32), ("qp_num",      ctypes.c_uint32),
        ("dest_qp_num", ctypes.c_uint32), ("qp_state",    ctypes.c_uint32),
        ("dest_ip",     ctypes.c_uint32), ("pid",         ctypes.c_uint32),
        ("timestamp_ns",ctypes.c_uint64),
    ]

class QPRecord:
    __slots__ = ("qp_num","pid","state","dest_qp_num","dest_ip","created_ns","last_modified_ns")
    def __init__(self, qp_num, pid, created_ns):
        self.qp_num=qp_num; self.pid=pid; self.state="RESET"
        self.dest_qp_num=0; self.dest_ip=0
        self.created_ns=created_ns; self.last_modified_ns=created_ns
    def __repr__(self):
        ip = _ip_str(self.dest_ip) if self.dest_ip else "N/A"
        return (f"QP(num={self.qp_num}, pid={self.pid}, state={self.state}, "
                f"dest_qpn={self.dest_qp_num}, dest_ip={ip})")

def _ip_str(ip):
    return f"{ip>>24&0xFF}.{ip>>16&0xFF}.{ip>>8&0xFF}.{ip&0xFF}"

def _pid_alive(pid):
    try:    os.kill(pid, 0); return True
    except ProcessLookupError: return False
    except PermissionError:    return True

# ──────────────────────────── rdma statistic Counter 管理器 ────────────────────────────

class CounterManager:
    """
    通过 `rdma statistic` CLI 读取 per-QP hardware counter。

    关键说明——操作原语与 counter 的关系
    ─────────────────────────────────────
    mlx5 per-QP counter 对象（由 `auto type on` 按 QP 类型分配）内包含多个字段：
      rx_write_requests   ← RDMA WRITE 到达次数（Receiver 侧可见）
      rx_read_requests    ← RDMA READ  到达次数
      rx_atomic_requests  ← Atomic 到达次数
      np_cnp_sent         ← 本机作为 NP（中间节点）发送的 CNP 数
      rp_cnp_handled      ← 本机作为 RP（发送端）处理的 CNP 数
      ... 以及各类错误计数

    不同操作原语 **不需要** 分配不同的 counter 对象——它们共享同一 counter，
    各自是不同字段。因此，一个 `auto type on` 即可覆盖所有操作类型。
    """

    def __init__(self, device=DEFAULT_RDMA_DEVICE, port=DEFAULT_RDMA_PORT):
        self.link        = f"{device}/{port}"
        self._prev_qp    = {}    # cntn_id → {field: value}
        self._prev_port  = {}

    def enable_auto(self):
        cmd = ["rdma","statistic","qp","set","link",self.link,"auto","type","on"]
        try: subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e: print(f"[counter] WARNING auto mode failed: {e}")

    def bind_qp(self, qp_num):
        """手动为 QP 绑定一个 counter（auto mode 未及时绑定时的补充）。"""
        cmd = ["rdma","statistic","qp","bind","link",self.link,"lqpn",str(qp_num)]
        try: subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception: pass

    def unbind_qp(self, qp_num):
        """QP 销毁时解绑（内核通常自动清理，此处仅做显式清理）。"""
        cmd = ["rdma","statistic","qp","unbind","link",self.link,"lqpn",str(qp_num)]
        try: subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception: pass

    def read_qp_stats(self):
        """
        返回 dict: cntn_id → { 'lqpns': [qp_num,...], field: value, ... }
        注意：同一 counter 对象可能对应多个 QP（auto mode 按类型合并）。
        """
        cmd = ["rdma","-j","-p","statistic","qp","show","link",self.link]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode != 0 or not r.stdout.strip(): return {}
            data = json.loads(r.stdout)
        except Exception: return {}
        result = {}
        for entry in data:
            cntn = entry.get("cntn", -1)
            lqpns = entry.get("lqpn", [])
            if isinstance(lqpns, int): lqpns = [lqpns]
            counters = {k: v for k, v in entry.items()
                        if k not in ("ifname","port","cntn","lqpn") and isinstance(v,(int,float))}
            result[cntn] = {"lqpns": lqpns, **counters}
        return result

    def read_port_stats(self):
        """读取端口级 hw_counters（通过 sysfs，延迟 < 1ms）。"""
        base = f"/sys/class/infiniband/{self.link.split('/')[0]}/ports/{self.link.split('/')[1]}/hw_counters"
        result = {}
        try:
            for fname in os.listdir(base):
                try:
                    val = int(open(f"{base}/{fname}").read().strip())
                    result[fname] = val
                except (ValueError, OSError): pass
        except OSError: pass
        return result

    def sample(self):
        """
        采样一次，返回:
          qp_deltas:   dict[cntn_id → {'lqpns':[...], field:delta,...}]
          port_deltas: dict[field → delta]  (仅非零)
        """
        cur_qp   = self.read_qp_stats()
        cur_port = self.read_port_stats()

        # QP delta
        qp_deltas = {}
        for cntn, stats in cur_qp.items():
            prev = self._prev_qp.get(cntn, {})
            delta = {k: stats[k] - prev.get(k, 0)
                     for k in stats if k != "lqpns" and isinstance(stats[k], (int,float))}
            if any(v != 0 for v in delta.values()):
                qp_deltas[cntn] = {"lqpns": stats["lqpns"], **delta}
        self._prev_qp = cur_qp

        # port delta
        port_deltas = {k: cur_port[k] - self._prev_port.get(k, 0)
                       for k in cur_port}
        port_deltas = {k: v for k, v in port_deltas.items() if v != 0}
        self._prev_port = cur_port

        return qp_deltas, port_deltas


# ──────────────────────────── 守护进程主类 ────────────────────────────

class CounterDaemon:
    def __init__(self, counter_interval_ms=DEFAULT_COUNTER_MS,
                 report_interval=DEFAULT_REPORT_INTERVAL_S,
                 device=DEFAULT_RDMA_DEVICE, port=DEFAULT_RDMA_PORT,
                 quiet=False):
        self.counter_interval = counter_interval_ms / 1000.0
        self.report_interval  = report_interval
        self.quiet            = quiet
        self.active_qps       = OrderedDict()
        self.running          = True
        self.event_count      = 0
        self._last_cnt_t      = time.monotonic()
        self._last_report_t   = time.monotonic()
        self.counter_mgr      = CounterManager(device=device, port=port)

    # ── 事件处理 ──
    def _handle_event(self, cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(QPEvent)).contents
        self.event_count += 1
        if   ev.event_type == EVENT_QP_MODIFY:  self._on_modify(ev)
        elif ev.event_type == EVENT_QP_DESTROY: self._on_destroy(ev)

    def _on_modify(self, ev):
        rec = self.active_qps.get(ev.qp_num)
        is_new = rec is None
        if is_new:
            rec = QPRecord(ev.qp_num, ev.pid, ev.timestamp_ns)
            self.active_qps[ev.qp_num] = rec
            self.counter_mgr.bind_qp(ev.qp_num)
        rec.last_modified_ns = ev.timestamp_ns
        if ev.qp_state != NO_STATE_CHANGE:
            rec.state = QP_STATE_NAMES.get(ev.qp_state, f"?({ev.qp_state})")
        if ev.dest_qp_num: rec.dest_qp_num = ev.dest_qp_num
        if ev.dest_ip:     rec.dest_ip     = ev.dest_ip
        if not self.quiet:
            tag  = "NEW+MOD" if is_new else "MODIFY"
            dest = (f"  dest_ip={_ip_str(ev.dest_ip)}  dest_qpn={ev.dest_qp_num}"
                    if ev.dest_ip else "")
            st   = rec.state if ev.qp_state != NO_STATE_CHANGE else "(no change)"
            print(f"  [{tag:7s}] QP {ev.qp_num:<8} → {st}{dest}  pid={ev.pid}")

    def _on_destroy(self, ev):
        rec = self.active_qps.pop(ev.qp_num, None)
        self.counter_mgr.unbind_qp(ev.qp_num)
        if not self.quiet:
            print(f"  [DESTROY] QP {ev.qp_num:<8}  pid={ev.pid}  "
                  f"({'tracked' if rec else 'untracked'})")

    def _reap(self):
        dead = [qn for qn,r in self.active_qps.items() if not _pid_alive(r.pid)]
        for qn in dead:
            rec = self.active_qps.pop(qn)
            self.counter_mgr.unbind_qp(qn)
            if not self.quiet:
                print(f"  [REAPED]  QP {qn:<8}  pid={rec.pid} (process exited)")

    # ── Counter 采样与打印 ──
    def _print_sample(self):
        qp_d, port_d = self.counter_mgr.sample()
        if not qp_d and not port_d: return

        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}]  Δ interval={self.counter_interval*1000:.0f}ms")

        for cntn, stats in qp_d.items():
            qpns = stats.get("lqpns", [])
            qpns_str = "+".join(str(q) for q in qpns)
            print(f"  counter {cntn}  lqpns=[{qpns_str}]")
            for k, v in sorted(stats.items()):
                if k == "lqpns" or v == 0: continue
                mark = "  ★" if k in HIGHLIGHT_FIELDS else ""
                print(f"    {k:<40} +{v}{mark}")

        if port_d:
            print(f"  [port {self.counter_mgr.link}]")
            for k, v in sorted(port_d.items()):
                if v == 0: continue
                mark = "  ★" if k in HIGHLIGHT_FIELDS else ""
                print(f"    {k:<40} +{v}{mark}")
        print()

    # ── 汇总 ──
    def _summary(self):
        self._reap()
        print(f"\n{'='*72}")
        print(f"  Active QPs: {len(self.active_qps)}   events={self.event_count}")
        print(f"{'='*72}")
        if not self.active_qps: print("  (none)")
        else:
            for _, r in self.active_qps.items(): print(f"    {r}")
        print(f"{'='*72}\n")

    # ── 主循环 ──
    def run(self):
        print("[counter] Loading eBPF program ...")
        b = BPF(text=BPF_PROGRAM)
        b.attach_uprobe(name=LIBIBVERBS_PATH, sym="ibv_modify_qp",  fn_name="trace_modify_qp")
        b.attach_uprobe(name=LIBIBVERBS_PATH, sym="ibv_destroy_qp", fn_name="trace_destroy_qp")
        b["events"].open_perf_buffer(self._handle_event, page_cnt=64)

        self.counter_mgr.enable_auto()
        # 建立基准（第一次采样的 delta 清零）
        self.counter_mgr.sample()

        print(f"[counter] RDMA link        : {self.counter_mgr.link}")
        print(f"[counter] Counter interval : {self.counter_interval*1000:.0f} ms")
        print(f"[counter] QP report interval:{self.report_interval} s")
        print("[counter] ★ = DCQCN / key fields")
        print("[counter] Note: counter object may cover multiple QPs of same type (RC/UD/UC)")
        print("[counter] Press Ctrl+C to stop\n")

        while self.running:
            try: b.perf_buffer_poll(timeout=PERF_POLL_MS)
            except KeyboardInterrupt: break
            now = time.monotonic()
            if now - self._last_cnt_t    >= self.counter_interval:
                self._print_sample(); self._last_cnt_t = now
            if now - self._last_report_t >= self.report_interval:
                self._summary();      self._last_report_t = now

        print("\n[counter] Shutting down ...")
        self._summary()


def main():
    p = argparse.ArgumentParser(
        description="qp_daemon_counter — QP 生命周期 + rdma statistic counter 轮询"
    )
    p.add_argument("-c","--counter-interval", type=float, default=DEFAULT_COUNTER_MS,
                   metavar="MS", help=f"counter 采样间隔 ms (默认 {DEFAULT_COUNTER_MS}，建议 ≥50)")
    p.add_argument("-i","--interval", type=float, default=DEFAULT_REPORT_INTERVAL_S,
                   help=f"活跃 QP 汇总间隔 s (默认 {DEFAULT_REPORT_INTERVAL_S})")
    p.add_argument("-d","--device",  default=DEFAULT_RDMA_DEVICE,
                   help=f"RDMA 设备名 (默认 {DEFAULT_RDMA_DEVICE})")
    p.add_argument("-p","--port",    type=int, default=DEFAULT_RDMA_PORT,
                   help=f"RDMA 端口号 (默认 {DEFAULT_RDMA_PORT})")
    p.add_argument("-q","--quiet", action="store_true",
                   help="不打印单条生命周期事件")
    args = p.parse_args()

    daemon = CounterDaemon(
        counter_interval_ms=args.counter_interval,
        report_interval=args.interval,
        device=args.device, port=args.port,
        quiet=args.quiet,
    )
    def _sig(s,f): daemon.running = False
    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)
    daemon.run()

if __name__ == "__main__":
    main()
