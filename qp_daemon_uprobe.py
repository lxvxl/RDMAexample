#!/usr/bin/env python3
"""
qp_daemon_uprobe.py  —— 技术路线 A：uprobe + BPF Map
====================================================

测量量: 每个 QP 每 5ms 发送的 **TX 字节数**（SGE 长度之和）

原理:
  在 Simulator 二进制中的 my_post_send() 入口挂 eBPF uprobe，
  在内核 BPF 程序中累加每次调用的 SGE 长度，写入 BPF_HASH(qp_tx_bytes)。
  Python 每 5ms 直接读取该 Map，计算 delta，延迟 < 1ms。

优点:
  • 延迟极低（无子进程，直接读 BPF map）
  • 字节粒度精确（逐 WR 统计）

局限:
  • 仅适用于 Sender 侧（需要挂载 my_post_send 符号）
  • 依赖 Simulator 二进制中存在 my_post_send 非内联符号

用法:
  sudo python3 qp_daemon_uprobe.py                   # 默认每 5ms 输出 TX 字节
  sudo python3 qp_daemon_uprobe.py -s ./Simulator    # 指定 Simulator 路径
  sudo python3 qp_daemon_uprobe.py -b 10             # 改为每 10ms 采样
  sudo python3 qp_daemon_uprobe.py -q                # 静默（不打印生命周期事件）
"""

import argparse
import ctypes
import datetime
import os
import signal
import time
from collections import OrderedDict
from bcc import BPF

# ──────────────────────────── 常量 ────────────────────────────

LIBIBVERBS_PATH       = "/lib/x86_64-linux-gnu/libibverbs.so"
DEFAULT_SIMULATOR_PATH = "/home/zhangj25/dcqcn-tuning/RDMAexample/Simulator"
DEFAULT_BYTE_INTERVAL_MS = 5    # BPF map 读取间隔 (ms)
DEFAULT_REPORT_INTERVAL_S = 5   # 活跃 QP 汇总打印间隔 (s)
PERF_POLL_MS = 5                # perf buffer 轮询超时 (ms)

EVENT_QP_MODIFY  = 2
EVENT_QP_DESTROY = 3
NO_STATE_CHANGE  = 0xFFFFFFFF

QP_STATE_NAMES = {0:"RESET", 1:"INIT", 2:"RTR", 3:"RTS", 4:"SQD", 5:"SQE", 6:"ERR"}

# ──────────────────────────── BPF 程序 ────────────────────────────

BPF_PROGRAM = r"""
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include <linux/ptrace.h>

#define IBV_QP_STATE    (1 <<  0)
#define IBV_QP_AV       (1 <<  7)
#define IBV_QP_DEST_QPN (1 << 20)

#define EVENT_QP_MODIFY   2
#define EVENT_QP_DESTROY  3
#define NO_STATE_CHANGE   0xFFFFFFFF

/* ---- libibverbs 结构镜像 ---- */
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
struct ibv_qp_cap { uint32_t max_send_wr, max_recv_wr, max_send_sge, max_recv_sge, max_inline_data; };
struct ibv_qp_attr_stub {
    int qp_state, cur_qp_state, path_mtu, path_mig_state;
    uint32_t qkey, rq_psn, sq_psn, dest_qp_num;
    unsigned int qp_access_flags;
    struct ibv_qp_cap cap;
    struct ibv_ah_attr ah_attr;
};

/* ---- 生命周期事件 ---- */
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
    ev.event_type  = EVENT_QP_DESTROY;
    ev.qp_num      = qp.qp_num;
    ev.qp_state    = NO_STATE_CHANGE;
    ev.pid         = bpf_get_current_pid_tgid() >> 32;
    ev.timestamp_ns= bpf_ktime_get_ns();
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

/* ============================================================
 * TX 字节统计：uprobe 挂载 my_post_send (Simulator 二进制)
 *
 * 无需 perf_submit，直接写 BPF Map，Python 侧定时 pull。
 * ibv_send_wr ABI：
 *   [0] wr_id(u64)  [8] *next  [16] *sg_list  [24] num_sge(int)
 * ibv_sge ABI (16B):
 *   [0] addr(u64)  [8] length(u32)  [12] lkey(u32)
 * ============================================================ */
struct ibv_send_wr_stub { uint64_t wr_id; void *next, *sg_list; int num_sge; };
struct ibv_sge_stub     { uint64_t addr; uint32_t length, lkey; };

BPF_HASH(qp_tx_bytes, u32, u64, 4096);  /* qp_num → cumulative TX bytes */

#define MY_MAX_SGE 8

int trace_post_send(struct pt_regs *ctx) {
    struct ibv_qp_stub      qp = {};
    struct ibv_send_wr_stub wr = {};
    bpf_probe_read_user(&qp, sizeof(qp), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read_user(&wr, sizeof(wr), (void *)PT_REGS_PARM2(ctx));

    u32 qp_num = qp.qp_num;
    u64 bytes  = 0;
    int nsge   = wr.num_sge;
    if (nsge > MY_MAX_SGE) nsge = MY_MAX_SGE;

    #pragma unroll
    for (int i = 0; i < MY_MAX_SGE; i++) {
        if (i >= nsge) break;
        struct ibv_sge_stub sge = {};
        bpf_probe_read_user(&sge, sizeof(sge),
                            (void *)((u64)wr.sg_list + (u64)i * 16ULL));
        bytes += sge.length;
    }

    u64 *total = qp_tx_bytes.lookup(&qp_num);
    if (total) { __sync_fetch_and_add(total, bytes); }
    else       { qp_tx_bytes.update(&qp_num, &bytes); }
    return 0;
}
"""

# ──────────────────────────── 用户态数据结构 ────────────────────────────

class QPEvent(ctypes.Structure):
    _fields_ = [
        ("event_type",   ctypes.c_uint32), ("qp_num",      ctypes.c_uint32),
        ("dest_qp_num",  ctypes.c_uint32), ("qp_state",    ctypes.c_uint32),
        ("dest_ip",      ctypes.c_uint32), ("pid",         ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
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

# ──────────────────────────── 守护进程 ────────────────────────────

class UprobeDaemon:
    def __init__(self, byte_interval_ms=DEFAULT_BYTE_INTERVAL_MS,
                 report_interval=DEFAULT_REPORT_INTERVAL_S,
                 simulator_path=DEFAULT_SIMULATOR_PATH, quiet=False):
        self.byte_interval    = byte_interval_ms / 1000.0
        self.report_interval  = report_interval
        self.simulator_path   = simulator_path
        self.quiet            = quiet
        self.active_qps       = OrderedDict()
        self.running          = True
        self.event_count      = 0
        self._tx_prev         = {}                  # qp_num → last sample bytes
        self._last_byte_t     = time.monotonic()
        self._last_report_t   = time.monotonic()

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
        self._tx_prev.pop(ev.qp_num, None)
        if not self.quiet:
            print(f"  [DESTROY] QP {ev.qp_num:<8}  pid={ev.pid}  "
                  f"({'tracked' if rec else 'untracked'})")

    def _reap(self):
        dead = [qn for qn,r in self.active_qps.items() if not _pid_alive(r.pid)]
        for qn in dead:
            rec = self.active_qps.pop(qn); self._tx_prev.pop(qn, None)
            if not self.quiet:
                print(f"  [REAPED]  QP {qn:<8}  pid={rec.pid} (process exited)")

    # ── TX 字节采样 ──
    def _sample_tx(self, bpf_obj):
        lines = []
        for k, v in bpf_obj["qp_tx_bytes"].items():
            qpn, cur = k.value, v.value
            prev = self._tx_prev.get(qpn)
            if prev is None:
                self._tx_prev[qpn] = cur; continue
            delta = cur - prev
            if delta > 0:
                self._tx_prev[qpn] = cur
                rate = delta * 8 / (self.byte_interval * 1e6)
                lines.append(f"  QP {qpn:<6}  +{delta:>10} B   {rate:>8.2f} Mb/s")
        if lines:
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{ts}]")
            for ln in lines: print(ln)

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
        print("[uprobe] Loading eBPF program ...")
        b = BPF(text=BPF_PROGRAM)
        b.attach_uprobe(name=LIBIBVERBS_PATH, sym="ibv_modify_qp",  fn_name="trace_modify_qp")
        b.attach_uprobe(name=LIBIBVERBS_PATH, sym="ibv_destroy_qp", fn_name="trace_destroy_qp")

        if self.simulator_path and os.path.isfile(self.simulator_path):
            b.attach_uprobe(name=self.simulator_path, sym="my_post_send",
                            fn_name="trace_post_send")
            print(f"  • my_post_send    (uprobe → {self.simulator_path})")
        else:
            print("  ! TX byte counting DISABLED — my_post_send symbol not found")
            print(f"    (given path: {self.simulator_path})")

        b["events"].open_perf_buffer(self._handle_event, page_cnt=64)
        print(f"[uprobe] TX byte interval : {self.byte_interval*1000:.0f} ms")
        print(f"[uprobe] QP report interval: {self.report_interval} s")
        print("[uprobe] Press Ctrl+C to stop\n")

        while self.running:
            try: b.perf_buffer_poll(timeout=PERF_POLL_MS)
            except KeyboardInterrupt: break
            now = time.monotonic()
            if now - self._last_byte_t   >= self.byte_interval:
                self._sample_tx(b);  self._last_byte_t = now
            if now - self._last_report_t >= self.report_interval:
                self._summary();     self._last_report_t = now

        print("\n[uprobe] Shutting down ...")
        self._summary()


def main():
    p = argparse.ArgumentParser(
        description="qp_daemon_uprobe — TX byte counting via my_post_send uprobe + BPF map"
    )
    p.add_argument("-s","--simulator", default=DEFAULT_SIMULATOR_PATH,
                   help="Simulator 二进制路径 (含 my_post_send 符号)")
    p.add_argument("-b","--byte-interval", type=float, default=DEFAULT_BYTE_INTERVAL_MS,
                   metavar="MS", help=f"TX 字节采样间隔 ms (默认 {DEFAULT_BYTE_INTERVAL_MS})")
    p.add_argument("-i","--interval", type=float, default=DEFAULT_REPORT_INTERVAL_S,
                   help=f"活跃 QP 汇总间隔 s (默认 {DEFAULT_REPORT_INTERVAL_S})")
    p.add_argument("-q","--quiet", action="store_true",
                   help="不打印单条生命周期事件")
    args = p.parse_args()

    daemon = UprobeDaemon(
        byte_interval_ms=args.byte_interval,
        report_interval=args.interval,
        simulator_path=args.simulator,
        quiet=args.quiet,
    )
    def _sig(s,f): daemon.running = False
    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)
    daemon.run()

if __name__ == "__main__":
    main()
