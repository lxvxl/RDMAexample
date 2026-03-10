#include "host.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] [server_ip]\n"
        "\n"
        "  server_ip        远端服务器 IP\n"
        "                   不指定 → 本机监听，作为 RDMA Sender\n"
        "                   指定   → 本机连接，作为 RDMA Receiver\n"
        "\n"
        "Options:\n"
        "  -n NUM_HOSTS     模拟的 Host 数量，即 QP 数量（默认 1）\n"
        "  -f FLOWS         每个 QP 发送的 WR(流) 数量（默认 1）\n"
        "  -w DWELL_MS      所有 WR 发完后 QP 保持存活的时长 ms（默认 2000）\n"
        "  -b BASE_PORT     起始 TCP 同步端口（默认 19875）\n"
        "  -g GID_IDX       GID 索引（默认 3）\n"
        "  -D DEV           RDMA 设备名（默认 mlx5_0）\n"
        "  -h               打印此帮助\n"
        "\n"
        "示例:\n"
        "  Sender   (无 server_ip): ./Simulator -n 2 -f 3 -w 5000\n"
        "  Receiver (有 server_ip): ./Simulator -n 2 -f 3 -w 5000 192.168.5.123\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *servername = NULL;
    int num_hosts  = 1;
    int num_flows  = 1;   /* WR 数量，不是 QP 数量 */
    int dwell_ms   = 2000;
    int base_port  = 19875;
    int gid_idx    = 3;
    const char *dev = "mlx5_0";

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            num_hosts = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            num_flows = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            dwell_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            base_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            gid_idx = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            dev = argv[++i];
        } else if (argv[i][0] != '-') {
            servername = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        i++;
    }

    if (num_hosts <= 0 || num_flows <= 0 || dwell_ms < 0) {
        fprintf(stderr, "Error: -n, -f must be positive; -w must be >= 0.\n");
        return 1;
    }

    // 不提供 server_ip → 本机监听 → isSender=true (RDMA 写入方)
    // 提供   server_ip → 本机连接 → isSender=false (RDMA 接收方)
    bool isSender = (servername == NULL);

    fprintf(stdout, "[main] Mode       : %s\n", isSender ? "Sender" : "Receiver");
    fprintf(stdout, "[main] Num hosts  : %d (= num QPs)\n", num_hosts);
    fprintf(stdout, "[main] WRs/QP     : %d\n", num_flows);
    fprintf(stdout, "[main] Dwell time : %d ms\n", dwell_ms);
    fprintf(stdout, "[main] Port range : %d – %d\n",
            base_port, base_port + num_hosts - 1);
    if (!isSender)
        fprintf(stdout, "[main] Server IP  : %s\n", servername);
    fflush(stdout);

    // ---- 创建 Host 对象（每个 Host 对应一个 QP / TCP 端口）----
    std::vector<Host*> hosts;
    hosts.reserve(num_hosts);
    for (int hi = 0; hi < num_hosts; hi++) {
        int port = base_port + hi;
        Host *h = new Host(gid_idx, port, servername, dev,
                           isSender, num_flows, dwell_ms);
        hosts.push_back(h);
    }

    // ---- 并发运行 ----
    if (num_hosts == 1) {
        hosts[0]->run();
    } else {
        for (auto h : hosts) h->run_in_thread();
        for (auto h : hosts) h->join();
    }

    // ---- 释放资源（触发 ibv_destroy_qp）----
    for (auto h : hosts) delete h;

    fprintf(stdout, "[main] All hosts finished.\n");
    return 0;
}