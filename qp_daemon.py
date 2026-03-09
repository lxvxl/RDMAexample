#!/usr/bin/env python3
"""
QP Lifecycle Daemon
===================
使用 eBPF uprobes 追踪 RDMA QP 的创建、状态转移和销毁，
在用户态维护一张实时的活跃 QP 表。

追踪目标（libibverbs 用户态函数）：
  - ibv_modify_qp   : uprobe  —— 状态转移 (RESET→INIT→RTR→RTS…)
                      首次 MODIFY→INIT 被视为 QP 「创建」事件
  - ibv_destroy_qp   : uprobe  —— 显式销毁

注：ibv_create_qp@@IBVERBS_1.1 是一个尾调用(jmp)包装器，
    无法通过 uretprobe 获取返回值，因此不再挂载。
    QP 创建通过首次 modify_qp(→INIT) 隐式检测。

用法：
  sudo python3 qp_daemon.py              # 默认每 5s 打印活跃 QP 汇总
  sudo python3 qp_daemon.py -i 2         # 改为每 2s 打印
  sudo python3 qp_daemon.py -q           # 静默模式，仅打印汇总
"""

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from collections import OrderedDict
from bcc import BPF

# ──────────────────────────── 常量 ────────────────────────────

LIBIBVERBS_PATH = "/lib/x86_64-linux-gnu/libibverbs.so"
POLL_INTERVAL_MS = 100        # perf buffer 轮询间隔 (ms)
DEFAULT_REPORT_INTERVAL_S = 5 # 活跃 QP 汇总报告间隔 (s)
DEFAULT_COUNTER_INTERVAL_S = 2 # counter 采样间隔 (s)
DEFAULT_RDMA_DEVICE = "mlx5_0"
DEFAULT_RDMA_PORT = 1

# 事件类型
EVENT_QP_MODIFY  = 2
EVENT_QP_DESTROY = 3

EVENT_TYPE_NAMES = {
    EVENT_QP_MODIFY:  "MODIFY",
    EVENT_QP_DESTROY: "DESTROY",
}

# QP 初始状态值 (ibv_qp_state.IBV_QPS_INIT = 1)
IBV_QPS_INIT = 1

# QP 状态名 (libibverbs enum ibv_qp_state)
QP_STATE_NAMES = {
    0: "RESET",
    1: "INIT",
    2: "RTR",
    3: "RTS",
    4: "SQD",
    5: "SQE",
    6: "ERR",
}

# 用于标识 "该事件不包含状态变更" 的哨兵值
NO_STATE_CHANGE = 0xFFFFFFFF

# ──────────────────────────── BPF 程序 ────────────────────────────

BPF_PROGRAM = r"""
#pragma clang diagnostic ignored "-Wmacro-redefined"
#include <linux/ptrace.h>

/* ---- ibv_modify_qp attr_mask 位 ---- */
#define IBV_QP_STATE     (1 <<  0)
#define IBV_QP_AV        (1 <<  7)
#define IBV_QP_DEST_QPN  (1 << 20)

/* ---- 事件类型 ---- */
#define EVENT_QP_MODIFY   2
#define EVENT_QP_DESTROY  3

/* ---- 哨兵值: 无状态变更 ---- */
#define NO_STATE_CHANGE   0xFFFFFFFF

/* ============================================================
 * libibverbs 结构体精简镜像 (仅保留我们需要读取的字段)
 * 字段顺序和大小必须与 ABI 完全一致，后续字段可省略。
 * ============================================================ */

struct ibv_qp_stub {
    void     *context;
    void     *qp_context;
    void     *pd;
    void     *send_cq;
    void     *recv_cq;
    void     *srq;
    uint32_t  handle;
    uint32_t  qp_num;       /* <-- 我们要读的字段 */
};

union ibv_gid {
    uint8_t raw[16];
    struct {
        __be64 subnet_prefix;
        __be64 interface_id;
    } global;
};

struct ibv_global_route {
    union ibv_gid dgid;
    uint32_t flow_label;
    uint8_t  sgid_index;
    uint8_t  hop_limit;
    uint8_t  traffic_class;
};

struct ibv_ah_attr {
    struct ibv_global_route grh;     /* offset 0 */
    uint16_t dlid;
    uint8_t  sl;
    uint8_t  src_path_bits;
    uint8_t  static_rate;
    uint8_t  is_global;
    uint8_t  port_num;
};

struct ibv_qp_cap {
    uint32_t max_send_wr;
    uint32_t max_recv_wr;
    uint32_t max_send_sge;
    uint32_t max_recv_sge;
    uint32_t max_inline_data;
};

struct ibv_qp_attr_stub {
    int      qp_state;             /* offset  0 */
    int      cur_qp_state;         /* offset  4 */
    int      path_mtu;             /* offset  8 */
    int      path_mig_state;       /* offset 12 */
    uint32_t qkey;                 /* offset 16 */
    uint32_t rq_psn;               /* offset 20 */
    uint32_t sq_psn;               /* offset 24 */
    uint32_t dest_qp_num;          /* offset 28 */
    unsigned int qp_access_flags;  /* offset 32 */
    struct ibv_qp_cap  cap;        /* offset 36, 20 bytes */
    struct ibv_ah_attr ah_attr;    /* offset 56 */
    /* 后续字段省略 —— 我们不读取 */
};

/* ==========================
 * 用户空间事件结构
 * ========================== */
struct qp_event {
    uint32_t event_type;       /* EVENT_QP_MODIFY / DESTROY */
    uint32_t qp_num;           /* 本地 QP number */
    uint32_t dest_qp_num;      /* 对端 QP number (仅 modify 时可能有值) */
    uint32_t qp_state;         /* 目标 QP 状态; NO_STATE_CHANGE = 不适用 */
    uint32_t dest_ip;          /* 对端 IPv4 (从 GID 提取; 仅 modify+AV) */
    uint32_t pid;              /* 触发进程 PID */
    uint64_t timestamp_ns;     /* bpf_ktime_get_ns() */
};

BPF_PERF_OUTPUT(events);

/* ========================
 * ibv_modify_qp
 * int ibv_modify_qp(struct ibv_qp *qp,
 *                   struct ibv_qp_attr *attr,
 *                   int attr_mask);
 * ======================== */
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

    /* 仅在 mask 包含对应位时才采集 */
    if (attr_mask & IBV_QP_STATE) {
        ev.qp_state = attr.qp_state;
    }
    if (attr_mask & IBV_QP_DEST_QPN) {
        ev.dest_qp_num = attr.dest_qp_num;
    }
    if (attr_mask & IBV_QP_AV) {
        /* RoCEv2: IPv4 嵌入在 GID interface_id 的高 32 位 */
        uint32_t dIP = (uint32_t)(attr.ah_attr.grh.dgid.global.interface_id >> 32);
        ev.dest_ip = bpf_ntohl(dIP);
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

/* ========================
 * ibv_destroy_qp
 * int ibv_destroy_qp(struct ibv_qp *qp);
 * ======================== */
int trace_destroy_qp(struct pt_regs *ctx) {
    struct ibv_qp_stub qp = {};
    bpf_probe_read_user(&qp, sizeof(qp), (void *)PT_REGS_PARM1(ctx));

    struct qp_event ev  = {};
    ev.event_type       = EVENT_QP_DESTROY;
    ev.qp_num           = qp.qp_num;
    ev.qp_state         = NO_STATE_CHANGE;
    ev.pid              = bpf_get_current_pid_tgid() >> 32;
    ev.timestamp_ns     = bpf_ktime_get_ns();

    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

# ──────────────────────────── 用户态数据结构 ────────────────────────────

class QPEvent(ctypes.Structure):
    """必须与 BPF struct qp_event 字段顺序/大小完全一致"""
    _fields_ = [
        ("event_type",   ctypes.c_uint32),
        ("qp_num",       ctypes.c_uint32),
        ("dest_qp_num",  ctypes.c_uint32),
        ("qp_state",     ctypes.c_uint32),
        ("dest_ip",      ctypes.c_uint32),
        ("pid",          ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
    ]


class QPRecord:
    """用户态维护的单条活跃 QP 记录"""
    __slots__ = (
        "qp_num", "pid", "state", "dest_qp_num",
        "dest_ip", "created_ns", "last_modified_ns",
    )

    def __init__(self, qp_num, pid, created_ns):
        self.qp_num          = qp_num
        self.pid             = pid
        self.state           = "RESET"
        self.dest_qp_num     = 0
        self.dest_ip         = 0
        self.created_ns      = created_ns
        self.last_modified_ns = created_ns

    def __repr__(self):
        ip_str = ip_to_str(self.dest_ip) if self.dest_ip else "N/A"
        return (
            f"QP(num={self.qp_num}, pid={self.pid}, state={self.state}, "
            f"dest_qpn={self.dest_qp_num}, dest_ip={ip_str})"
        )


# ──────────────────────────── 工具函数 ────────────────────────────

def ip_to_str(ip_int):
    """将 uint32 IP 地址转为点分十进制字符串"""
    return (
        f"{(ip_int >> 24) & 0xFF}."
        f"{(ip_int >> 16) & 0xFF}."
        f"{(ip_int >>  8) & 0xFF}."
        f"{ip_int & 0xFF}"
    )


def _pid_alive(pid):
    """检查给定 PID 的进程是否仍然存活"""
    try:
        os.kill(pid, 0)   # signal 0: 不发送信号，仅检查权限 / 进程存在
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True       # 进程存在但我们没有权限, 算作存活


# ──────────────────────────── Counter 管理器 ────────────────────────────

class CounterManager:
    """通过 iproute2 `rdma` CLI 管理 per-QP 计数器的绑定、解绑和读取。

    方案:
      1. 启动时开启 auto mode (`rdma statistic qp set ... auto type on`) —
         后续新建的 QP 自动按类型分组获得计数器。
      2. 对守护进程监测到的活跃 QP，尝试手动 bind —
         确保即使 auto mode 未及时绑定也能采集。
      3. 定期通过 `rdma -j statistic qp show` 读取 per-QP 计数器。
      4. QP 销毁时执行 unbind 清理。
    """

    def __init__(self, device=DEFAULT_RDMA_DEVICE, port=DEFAULT_RDMA_PORT):
        self.device = device
        self.port = port
        self.link = f"{device}/{port}"
        # qp_num → counter_id (from bind responses)
        self.bound_counters = {}   # qp_num → cntn_id | None
        # 上一次采样快照: qp_num → {counter_name: value}
        self.prev_qp_stats = {}
        # 上一次端口级快照
        self.prev_port_stats = {}

    # ── 初始化: 开启 auto mode ──

    def enable_auto_mode(self):
        """开启 auto type mode，使新建 QP 自动获得 counter。"""
        cmd = ["rdma", "statistic", "qp", "set", "link", self.link,
               "auto", "type", "on"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e:
            print(f"[Counter] WARNING: failed to enable auto mode: {e}")

    def disable_auto_mode(self):
        """关闭 auto type mode（清理用）。"""
        cmd = ["rdma", "statistic", "qp", "set", "link", self.link,
               "auto", "off"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

    # ── 绑定 / 解绑 ──

    def bind_qp(self, qp_num):
        """为指定 QP 手动绑定一个计数器。"""
        if qp_num in self.bound_counters:
            return  # 已绑定
        cmd = ["rdma", "statistic", "qp", "bind", "link", self.link,
               "lqpn", str(qp_num)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.bound_counters[qp_num] = None  # counter_id 未知，稍后从 show 中获取
            # 如果失败（例如 auto mode 已经绑定了），静默忽略
        except Exception:
            pass

    def unbind_qp(self, qp_num):
        """解绑指定 QP 的计数器。"""
        cntn_id = self.bound_counters.pop(qp_num, None)
        self.prev_qp_stats.pop(qp_num, None)
        # 注: QP 销毁后，内核会自动清理绑定，unbind 可能已经隐式完成
        # 但手动 unbind 也是安全的
        if cntn_id is not None:
            cmd = ["rdma", "statistic", "qp", "unbind", "link", self.link,
                   "cntn", str(cntn_id), "lqpn", str(qp_num)]
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass

    # ── 读取计数器 ──

    def read_qp_stats(self):
        """读取 per-QP 计数器 (JSON)。
        返回: dict[qp_num → dict[counter_name → value]]
        """
        cmd = ["rdma", "-j", "-p", "statistic", "qp", "show", "link", self.link]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0 or not result.stdout.strip():
                return {}
            data = json.loads(result.stdout)
        except Exception:
            return {}

        # data 格式示例:
        # [{"ifname": "mlx5_0", "port": 1, "cntn": 0,
        #   "lqpn": [178, 200],
        #   "rx_write_requests": 1234, ...}]
        qp_stats = {}
        for entry in data:
            counters = {k: v for k, v in entry.items()
                        if k not in ("ifname", "port", "cntn", "lqpn")}
            cntn_id = entry.get("cntn")
            lqpns = entry.get("lqpn", [])
            if isinstance(lqpns, int):
                lqpns = [lqpns]
            for qpn in lqpns:
                qp_stats[qpn] = counters
                # 记录 counter_id 映射
                if cntn_id is not None:
                    self.bound_counters[qpn] = cntn_id
        return qp_stats

    def read_port_stats(self):
        """读取端口级计数器 (JSON)。返回 dict[counter_name → value]。"""
        cmd = ["rdma", "-j", "-p", "statistic", "show", "link", self.link]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0 or not result.stdout.strip():
                return {}
            data = json.loads(result.stdout)
        except Exception:
            return {}

        if data and isinstance(data, list):
            entry = data[0]
            return {k: v for k, v in entry.items()
                    if k not in ("ifname", "port")}
        return {}

    def compute_deltas(self, current, previous):
        """计算两次采样之间的差值 (delta)。"""
        deltas = {}
        for key, val in current.items():
            if isinstance(val, (int, float)):
                prev_val = previous.get(key, 0)
                deltas[key] = val - prev_val
        return deltas

    def sample_and_diff(self):
        """执行一次完整采样，返回 per-QP deltas 和 port deltas。

        Returns:
            qp_deltas:   dict[qp_num → dict[counter_name → delta_value]]
            port_deltas: dict[counter_name → delta_value]
        """
        # Per-QP
        cur_qp = self.read_qp_stats()
        qp_deltas = {}
        for qpn, stats in cur_qp.items():
            prev = self.prev_qp_stats.get(qpn, {})
            delta = self.compute_deltas(stats, prev)
            if any(v != 0 for v in delta.values()):
                qp_deltas[qpn] = delta
        self.prev_qp_stats = cur_qp

        # Port-level
        cur_port = self.read_port_stats()
        port_deltas = self.compute_deltas(cur_port, self.prev_port_stats)
        self.prev_port_stats = cur_port

        return qp_deltas, port_deltas


# ──────────────────────────── 守护进程主类 ────────────────────────────

class QPDaemon:
    def __init__(self, report_interval=DEFAULT_REPORT_INTERVAL_S,
                 counter_interval=DEFAULT_COUNTER_INTERVAL_S,
                 device=DEFAULT_RDMA_DEVICE, port=DEFAULT_RDMA_PORT,
                 quiet=False):
        self.active_qps       = OrderedDict()  # qp_num → QPRecord
        self.running          = True
        self.last_report_time  = time.monotonic()
        self.last_counter_time = time.monotonic()
        self.report_interval  = report_interval
        self.counter_interval = counter_interval
        self.quiet            = quiet
        self.event_count      = 0
        self.counter_mgr      = CounterManager(device=device, port=port)

    # ── 事件分发 ──

    def handle_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(QPEvent)).contents
        self.event_count += 1

        if event.event_type == EVENT_QP_MODIFY:
            self._on_modify(event)
        elif event.event_type == EVENT_QP_DESTROY:
            self._on_destroy(event)

    # ── MODIFY (首次 MODIFY→INIT 被视为隐式 CREATE) ──

    def _on_modify(self, ev):
        rec = self.active_qps.get(ev.qp_num)
        is_new = rec is None

        if is_new:
            rec = QPRecord(ev.qp_num, ev.pid, ev.timestamp_ns)
            self.active_qps[ev.qp_num] = rec
            # 新 QP 出现, 尝试绑定 counter
            self.counter_mgr.bind_qp(ev.qp_num)

        rec.last_modified_ns = ev.timestamp_ns

        # 更新状态
        if ev.qp_state != NO_STATE_CHANGE:
            state_name = QP_STATE_NAMES.get(ev.qp_state, f"?({ev.qp_state})")
            rec.state = state_name

        # 更新对端信息
        if ev.dest_qp_num:
            rec.dest_qp_num = ev.dest_qp_num
        if ev.dest_ip:
            rec.dest_ip = ev.dest_ip

        if not self.quiet:
            # 首次 MODIFY→INIT 额外标注为隐式创建
            tag = "NEW+MOD" if is_new else "MODIFY"
            dest_info = ""
            if ev.dest_ip:
                dest_info = (
                    f"  dest_ip={ip_to_str(ev.dest_ip)}"
                    f"  dest_qpn={ev.dest_qp_num}"
                )
            state_str = rec.state if ev.qp_state != NO_STATE_CHANGE else "(no change)"
            print(
                f"  [{tag:7s}] QP {ev.qp_num:<8} → {state_str}"
                f"{dest_info}  pid={ev.pid}"
            )

    # ── DESTROY ──

    def _on_destroy(self, ev):
        rec = self.active_qps.pop(ev.qp_num, None)
        # 清理 counter 绑定
        self.counter_mgr.unbind_qp(ev.qp_num)
        if not self.quiet:
            tracked = "tracked" if rec else "untracked"
            print(f"  [DESTROY] QP {ev.qp_num:<8}  pid={ev.pid}  ({tracked})")

    # ── 进程退出检测：清理孤儿 QP ──

    def _reap_dead_pids(self):
        """检查活跃 QP 对应的 PID 是否仍然存活；
        若进程已退出（内核自动回收 QP），则从表中移除。
        """
        dead_qps = []
        for qp_num, rec in self.active_qps.items():
            if not _pid_alive(rec.pid):
                dead_qps.append(qp_num)
        for qp_num in dead_qps:
            rec = self.active_qps.pop(qp_num)
            self.counter_mgr.unbind_qp(qp_num)
            if not self.quiet:
                print(f"  [REAPED]  QP {qp_num:<8}  pid={rec.pid} (process exited)")

    # ── 定期汇总 ──

    def print_active_qps(self):
        # 先清理已退出进程的 QP
        self._reap_dead_pids()

        print(f"\n{'='*72}")
        print(f"  Active QPs: {len(self.active_qps)}    "
              f"(total events processed: {self.event_count})")
        print(f"{'='*72}")
        if not self.active_qps:
            print("  (none)")
        else:
            for _, rec in self.active_qps.items():
                print(f"    {rec}")
        print(f"{'='*72}\n")

    # ── Counter 采样与打印 ──

    def _sample_counters(self):
        """采样 per-QP 与端口级 counter，打印非零 delta。"""
        qp_deltas, port_deltas = self.counter_mgr.sample_and_diff()

        # 过滤只显示非零 delta 的字段
        non_zero_port = {k: v for k, v in port_deltas.items() if v != 0}

        if not qp_deltas and not non_zero_port:
            return  # 没有变化, 不打印

        print(f"  --- Counter deltas (interval={self.counter_interval}s) ---")

        if non_zero_port:
            print(f"  [PORT {self.counter_mgr.link}]")
            for k, v in non_zero_port.items():
                print(f"    {k}: +{v}")

        for qpn, deltas in qp_deltas.items():
            non_zero = {k: v for k, v in deltas.items() if v != 0}
            if non_zero:
                print(f"  [QP {qpn}]")
                for k, v in non_zero.items():
                    print(f"    {k}: +{v}")

        print()

    # ── 主循环 ──

    def run(self):
        print("[QPDaemon] Loading eBPF program ...")
        b = BPF(text=BPF_PROGRAM)

        # ---- 挂载 uprobes ----
        b.attach_uprobe(
            name=LIBIBVERBS_PATH,
            sym="ibv_modify_qp",
            fn_name="trace_modify_qp",
        )
        b.attach_uprobe(
            name=LIBIBVERBS_PATH,
            sym="ibv_destroy_qp",
            fn_name="trace_destroy_qp",
        )

        b["events"].open_perf_buffer(self.handle_event, page_cnt=64)

        # ---- 初始化 Counter 管理 ----
        self.counter_mgr.enable_auto_mode()
        # 做一次初始采样，建立 baseline（后续计算 delta）
        self.counter_mgr.sample_and_diff()

        print("[QPDaemon] Tracing libibverbs functions:")
        print("  • ibv_modify_qp   (uprobe) — first INIT = implicit creation")
        print("  • ibv_destroy_qp  (uprobe)")
        print(f"[QPDaemon] RDMA device: {self.counter_mgr.link}")
        print(f"[QPDaemon] Counter auto mode: enabled")
        print(f"[QPDaemon] Report interval: {self.report_interval}s")
        print(f"[QPDaemon] Counter sample interval: {self.counter_interval}s")
        print(f"[QPDaemon] Stale QP reaping: enabled (PID liveness check)")
        print("[QPDaemon] Press Ctrl+C to exit\n")

        while self.running:
            try:
                b.perf_buffer_poll(timeout=POLL_INTERVAL_MS)
            except KeyboardInterrupt:
                break

            now = time.monotonic()

            # 定期采样 counter
            if now - self.last_counter_time >= self.counter_interval:
                self._sample_counters()
                self.last_counter_time = now

            # 定期打印活跃 QP 汇总
            if now - self.last_report_time >= self.report_interval:
                self.print_active_qps()
                self.last_report_time = now

        # 退出前打印最终状态
        print("\n[QPDaemon] Shutting down ...")
        self.print_active_qps()


# ──────────────────────────── CLI 入口 ────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="QP Lifecycle Daemon")
    parser.add_argument(
        "-i", "--interval", type=float, default=DEFAULT_REPORT_INTERVAL_S,
        help=f"活跃 QP 汇总报告间隔 (秒), 默认 {DEFAULT_REPORT_INTERVAL_S}",
    )
    parser.add_argument(
        "-c", "--counter-interval", type=float, default=DEFAULT_COUNTER_INTERVAL_S,
        help=f"counter 采样间隔 (秒), 默认 {DEFAULT_COUNTER_INTERVAL_S}",
    )
    parser.add_argument(
        "-d", "--device", type=str, default=DEFAULT_RDMA_DEVICE,
        help=f"RDMA 设备名, 默认 {DEFAULT_RDMA_DEVICE}",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=DEFAULT_RDMA_PORT,
        help=f"RDMA 端口号, 默认 {DEFAULT_RDMA_PORT}",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="静默模式: 不打印单条事件, 仅打印周期汇总",
    )
    args = parser.parse_args()

    daemon = QPDaemon(
        report_interval=args.interval,
        counter_interval=args.counter_interval,
        device=args.device,
        port=args.port,
        quiet=args.quiet,
    )

    # 信号处理: 优雅退出
    def sig_handler(signum, frame):
        daemon.running = False

    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    daemon.run()


if __name__ == "__main__":
    main()
