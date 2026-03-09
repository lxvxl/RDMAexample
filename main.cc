#include "host.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] [server_ip]\n"
        "\n"
        "  server_ip          远端服务器 IP（指定则本机为 Sender，否则为 Receiver）\n"
        "\n"
        "Options:\n"
        "  -n NUM_HOSTS       模拟的 Host 数量（默认 1）\n"
        "  -f FLOWS_PER_HOST  每个 Host 发送的流数量（默认 1）\n"
        "  -b BASE_PORT       起始 TCP 同步端口（默认 19875）\n"
        "  -g GID_IDX         GID 索引（默认 3）\n"
        "  -D DEV             RDMA 设备名（默认 mlx5_0）\n"
        "  -h                 打印此帮助\n"
        "\n"
        "端口分配: host_i 的 flow_j 使用端口 BASE_PORT + i * FLOWS_PER_HOST + j\n"
        "\n"
        "示例:\n"
        "  Receiver: ./Simulator -n 2 -f 3\n"
        "  Sender:   ./Simulator -n 2 -f 3 192.168.5.123\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *servername = NULL;
    int num_hosts      = 1;
    int flows_per_host = 1;
    int base_port      = 19875;
    int gid_idx        = 3;
    const char *dev    = "mlx5_0";

    // ---- 简单参数解析（getopt 风格） ----
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            num_hosts = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            flows_per_host = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            base_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            gid_idx = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            dev = argv[++i];
        } else if (argv[i][0] != '-') {
            // 非选项参数：server IP
            servername = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        i++;
    }

    if (num_hosts <= 0 || flows_per_host <= 0) {
        fprintf(stderr, "Error: -n and -f must be positive integers.\n");
        return 1;
    }

    bool isSender = (servername != NULL);
    int  total    = num_hosts * flows_per_host;

    fprintf(stdout, "[main] Mode        : %s\n", isSender ? "Sender" : "Receiver");
    fprintf(stdout, "[main] Num hosts   : %d\n", num_hosts);
    fprintf(stdout, "[main] Flows/host  : %d\n", flows_per_host);
    fprintf(stdout, "[main] Total QPs   : %d\n", total);
    fprintf(stdout, "[main] Port range  : %d – %d\n",
            base_port, base_port + total - 1);
    if (isSender)
        fprintf(stdout, "[main] Server IP   : %s\n", servername);
    fflush(stdout);

    // ---- 创建所有 Host 对象 ----
    // 端口分配: host_idx i, flow_idx j → port = base_port + i * flows_per_host + j
    std::vector<Host*> hosts;
    hosts.reserve(total);
    for (int hi = 0; hi < num_hosts; hi++) {
        for (int fi = 0; fi < flows_per_host; fi++) {
            int port = base_port + hi * flows_per_host + fi;
            Host *h = new Host(gid_idx, port, servername, dev, isSender);
            hosts.push_back(h);
        }
    }

    // ---- 并发运行：每个 Host 一个线程 ----
    if (total == 1) {
        // 单 Host 直接在主线程运行，方便调试
        hosts[0]->run();
    } else {
        for (auto h : hosts) {
            h->run_in_thread();
        }
        for (auto h : hosts) {
            h->join();
        }
    }

    // ---- 释放资源（~Host 调用 ibv_destroy_qp） ----
    for (auto h : hosts) {
        delete h;
    }

    fprintf(stdout, "[main] All hosts finished.\n");
    return 0;
}