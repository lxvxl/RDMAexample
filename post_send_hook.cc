/**
 * post_send_hook.cc
 * -----------------
 * 提供一个 **非内联** 的 ibv_post_send 包装函数 my_post_send，
 * 使 qp_daemon.py 可以通过 eBPF uprobe 挂载到该函数，
 * 从而统计每个 QP 发送的字节数。
 *
 * 背景：ibv_post_send 在 <infiniband/verbs.h> 中以 inline 形式定义，
 * 直接展开为 QP context ops 函数指针调用，不会在可执行文件里留下独立符号，
 * 因此无法被 uprobe 直接挂载。本文件将其包装为一个普通函数，
 * 保留独立的符号并禁止编译器内联，以供 uprobe 使用。
 */

#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * my_post_send - ibv_post_send 的非内联包装
 *
 * qp_daemon.py 通过 BPF uprobe 挂载到此函数入口，读取参数：
 *   - qp->qp_num        : 本地 QP 编号
 *   - wr->sg_list[]     : scatter/gather 列表，各项携带 length 字段
 *   - wr->num_sge       : SGE 数量
 * 从而累计每次 post_send 实际发送的字节数。
 */
__attribute__((noinline, used))
int my_post_send(struct ibv_qp       *qp,
                 struct ibv_send_wr  *wr,
                 struct ibv_send_wr **bad_wr)
{
    return ibv_post_send(qp, wr, bad_wr);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
