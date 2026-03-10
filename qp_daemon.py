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
import datetime
import os
import signal
import sys
import time
from collections import OrderedDict
from bcc import BPF

# ──────────────────────────── 常量 ────────────────────────────

LIBIBVERBS_PATH = "/lib/x86_64-linux-gnu/libibverbs.so"
POLL_INTERVAL_MS = 5          # perf buffer 轮询间隔 (ms) — 紧跟 5ms 字节采样节奏
DEFAULT_REPORT_INTERVAL_S = 5 # 活跃 QP 汇总报告间隔 (s)
DEFAULT_SIMULATOR_PATH = "/home/zhangj25/dcqcn-tuning/RDMAexample/Simulator"

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

/* ============================================================
 * my_post_send uprobe — TX 字节统计
 * ============================================================
 * 函数签名 (post_send_hook.cc):
 *   int my_post_send(struct ibv_qp *qp,
 *                    struct ibv_send_wr *wr,
 *                    struct ibv_send_wr **bad_wr)
 *
 * ibv_send_wr 字段布局 (根据 <infiniband/verbs.h> ABI):
 *   offset  0: uint64_t wr_id
 *   offset  8: void    *next      (链表下一个 WR)
 *   offset 16: void    *sg_list   (scatter/gather 列表指针)
 *   offset 24: int      num_sge   (SGE 数量)
 *
 * ibv_sge 字段布局 (16B 对齐):
 *   offset  0: uint64_t addr
 *   offset  8: uint32_t length
 *   offset 12: uint32_t lkey
 * ============================================================ */

struct ibv_send_wr_stub {
    uint64_t wr_id;    /* offset  0 */
    void    *next;     /* offset  8 */
    void    *sg_list;  /* offset 16 */
    int      num_sge;  /* offset 24 */
};

struct ibv_sge_stub {
    uint64_t addr;     /* offset  0 */
    uint32_t length;   /* offset  8 */
    uint32_t lkey;     /* offset 12 */
};

/* 累计 TX 字节数: qp_num → bytes */
BPF_HASH(qp_tx_bytes, u32, u64, 4096);

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
        /* 每个 ibv_sge 固定 16 字节 */
        bpf_probe_read_user(&sge, sizeof(sge),
                            (void *)((u64)wr.sg_list + (u64)i * 16ULL));
        bytes += sge.length;
    }

    u64 *total = qp_tx_bytes.lookup(&qp_num);
    if (total) {
        __sync_fetch_and_add(total, bytes);
    } else {
        qp_tx_bytes.update(&qp_num, &bytes);
    }
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



# ──────────────────────────── 守护进程主类 ────────────────────────────

class QPDaemon:
    BYTE_INTERVAL = 0.005   # 5ms — TX 字节采样间隔

    def __init__(self, report_interval=DEFAULT_REPORT_INTERVAL_S,
                 simulator_path=None, quiet=False):
        self.active_qps       = OrderedDict()   # qp_num → QPRecord
        self.running          = True
        self.last_report_time = time.monotonic()
        self.last_byte_time   = time.monotonic()
        self.report_interval  = report_interval
        self.simulator_path   = simulator_path
        self.quiet            = quiet
        self.event_count      = 0
        self._tx_bytes_prev   = {}              # qp_num → 上次采样的累计字节数

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

        rec.last_modified_ns = ev.timestamp_ns

        if ev.qp_state != NO_STATE_CHANGE:
            rec.state = QP_STATE_NAMES.get(ev.qp_state, f"?({ev.qp_state})")
        if ev.dest_qp_num:
            rec.dest_qp_num = ev.dest_qp_num
        if ev.dest_ip:
            rec.dest_ip = ev.dest_ip

        if not self.quiet:
            tag = "NEW+MOD" if is_new else "MODIFY"
            dest_info = ""
            if ev.dest_ip:
                dest_info = (
                    f"  dest_ip={ip_to_str(ev.dest_ip)}"
                    f"  dest_qpn={ev.dest_qp_num}"
                )
            state_str = rec.state if ev.qp_state != NO_STATE_CHANGE else "(no change)"
            print(f"  [{tag:7s}] QP {ev.qp_num:<8} → {state_str}{dest_info}  pid={ev.pid}")

    # ── DESTROY ──

    def _on_destroy(self, ev):
        rec = self.active_qps.pop(ev.qp_num, None)
        self._tx_bytes_prev.pop(ev.qp_num, None)
        if not self.quiet:
            tracked = "tracked" if rec else "untracked"
            print(f"  [DESTROY] QP {ev.qp_num:<8}  pid={ev.pid}  ({tracked})")

    # ── 进程退出检测：清理孤儿 QP ──

    def _reap_dead_pids(self):
        dead = [qn for qn, r in self.active_qps.items() if not _pid_alive(r.pid)]
        for qn in dead:
            rec = self.active_qps.pop(qn)
            self._tx_bytes_prev.pop(qn, None)
            if not self.quiet:
                print(f"  [REAPED]  QP {qn:<8}  pid={rec.pid} (process exited)")

    # ── 每 5ms 采样 TX 字节数（直接读 BPF map，无子进程，延迟 <1ms） ──

    def _sample_tx_bytes(self, bpf_obj):
        """读取 qp_tx_bytes BPF map，输出字节增量非零的 QP。"""
        lines = []
        for k, v in bpf_obj["qp_tx_bytes"].items():
            qpn = k.value
            cur = v.value
            prev = self._tx_bytes_prev.get(qpn)
            if prev is None:
                # 首次见到该 QP：建立基准，本轮不输出
                self._tx_bytes_prev[qpn] = cur
                continue
            delta = cur - prev
            if delta > 0:
                self._tx_bytes_prev[qpn] = cur
                rate_mbps = (delta * 8) / (self.BYTE_INTERVAL * 1e6)
                lines.append(f"  QP {qpn:<6}  +{delta:>10} B   {rate_mbps:>8.2f} Mb/s")

        if lines:
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{ts}]")
            for line in lines:
                print(line)

    # ── 定期汇总 ──

    def print_active_qps(self):
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

        if self.simulator_path and os.path.isfile(self.simulator_path):
            b.attach_uprobe(
                name=self.simulator_path,
                sym="my_post_send",
                fn_name="trace_post_send",
            )
            print(f"  • my_post_send    (uprobe → {self.simulator_path})")
        else:
            print("  ! TX byte counting disabled "
                  "(use -s <path> to specify Simulator binary)")

        b["events"].open_perf_buffer(self.handle_event, page_cnt=64)

        print("[QPDaemon] Tracing:")
        print("  • ibv_modify_qp   (uprobe) — first INIT = implicit creation")
        print("  • ibv_destroy_qp  (uprobe)")
        print(f"[QPDaemon] TX byte sample interval : {self.BYTE_INTERVAL*1000:.0f} ms")
        print(f"[QPDaemon] Active QP report interval: {self.report_interval} s")
        print("[QPDaemon] Press Ctrl+C to exit\n")

        while self.running:
            try:
                b.perf_buffer_poll(timeout=POLL_INTERVAL_MS)
            except KeyboardInterrupt:
                break

            now = time.monotonic()

            # 每 5ms 采样 TX 字节数（直接读 BPF map，无子进程）
            if now - self.last_byte_time >= self.BYTE_INTERVAL:
                self._sample_tx_bytes(b)
                self.last_byte_time = now

            # 定期打印活跃 QP 汇总
            if now - self.last_report_time >= self.report_interval:
                self.print_active_qps()
                self.last_report_time = now

        print("\n[QPDaemon] Shutting down ...")
        self.print_active_qps()


# ──────────────────────────── CLI 入口 ────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="QP Lifecycle Daemon — eBPF 监测 RDMA QP 生命周期与 TX 字节数"
    )
    parser.add_argument(
        "-i", "--interval", type=float, default=DEFAULT_REPORT_INTERVAL_S,
        help=f"活跃 QP 汇总报告间隔 (秒), 默认 {DEFAULT_REPORT_INTERVAL_S}",
    )
    parser.add_argument(
        "-s", "--simulator", type=str, default=DEFAULT_SIMULATOR_PATH,
        help="Simulator 二进制绝对路径，用于 my_post_send uprobe，默认 %(default)s",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="静默模式: 不打印单条生命周期事件，仅打印周期 TX 字节与汇总",
    )
    args = parser.parse_args()

    daemon = QPDaemon(
        report_interval=args.interval,
        simulator_path=args.simulator,
        quiet=args.quiet,
    )

    def sig_handler(signum, frame):
        daemon.running = False

    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    daemon.run()


if __name__ == "__main__":
    main()
