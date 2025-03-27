#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <thread>
class Host {
   public:
    Host(int gid_idx, int tcp_port, const char *servername, const char *dev_name, bool isSender);
    ~Host();
    int init();
    void run();
    void run_in_thread();

   private:
    struct cm_con_data_t {
        uint64_t addr;        /* Buffer address */
        uint32_t rkey;        /* Remote key */
        uint32_t qp_num;      /* QP number */
        uint16_t lid;         /* LID of the IB port */
        uint8_t gid[16];      /* gid */
    } __attribute__((packed));

    struct resource_t {
        struct ibv_device_attr device_attr; /* Device attributes */
        struct ibv_port_attr port_attr;     /* IB port attributes */
        struct cm_con_data_t remote_props;  /* values to connect to remote side */
        struct ibv_context *ib_ctx;         /* device handle */
        struct ibv_pd *pd;                  /* PD handle */
        struct ibv_cq *cq;                  /* CQ handle */
        struct ibv_qp *qp;                  /* QP handle */
        struct ibv_mr *mr;                  /* MR handle for buf */
        char *buf;                          /* memory buffer pointer, used for RDMA and send ops */
        int sock;                           /* TCP socket file descriptor */
    };

    struct config_t {
        const char *dev_name; /* IB device name */
        const char *server_name;    /* server host name */
        uint32_t tcp_port;    /* server TCP port */
        int ib_port;          /* local IB port to work with */
        int gid_idx;          /* gid index to use */
        int udp_sport;        /* udp src port */
        void inline print() {
            fprintf(stdout, " ------------------------------------------------\n");
            fprintf(stdout, " Device name : \"%s\"\n", dev_name);
            fprintf(stdout, " IB port : %u\n", ib_port);
            if(server_name)
            {
                fprintf(stdout, " IP : %s\n", server_name);
            }
            fprintf(stdout, " TCP port : %u\n", tcp_port);
            if(gid_idx >= 0)
            {
                fprintf(stdout, " GID index : %u\n", gid_idx);
            }
            if (udp_sport == 0 || (udp_sport >= 49152 && udp_sport <= 65535))
            {
                fprintf(stdout, " UDP source port : %u\n", udp_sport);
            }
            fprintf(stdout, " ------------------------------------------------\n\n");
        }
    };

    struct resource_t res;
    struct config_t config;
    bool isSender;

    //return sock
    int sock_connect();
    int sock_sync_data(int xfer_size, char *local_data, char *remote_data);
    int poll_completion();
    int post_send(int opcode);
    int post_receive();
    int resources_create();
    int modify_qp_to_init();
    int modify_qp_to_rtr(uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid);
    int modify_qp_to_rts();
    int connect_qp();
    int resources_destroy();
    std::thread thread_obj;
};