#include "host.h"

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
#include <random>


#define MAX_POLL_CQ_TIMEOUT 2000
#define MSG_SIZE 3000

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) {
    return bswap_64(x);
}
static inline uint64_t ntohll(uint64_t x) {
    return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
    return x;
}
static inline uint64_t ntohll(uint64_t x)
{
    return x;
}
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

#define GOTO_ERR_IF_NONZERO(expr, label) do { \
    int rc = (expr);                    \
    if (rc) {                \
        fprintf(stderr, "[%d]Error: %s failed at %s:%d with code %d in <%s>\n", \
                config.tcp_port, #expr, __FILE__, __LINE__, rc, __PRETTY_FUNCTION__); \
        goto label;                     \
    }                                   \
} while (0)

#define GOTO_ERR_IF_NEG(expr, label) do { \
    int rc = (expr);                    \
    if (rc < 0) {                \
        fprintf(stderr, "[%d]Error: %s failed at %s:%d with code %d in <%s>\n", \
                config.tcp_port, #expr, __FILE__, __LINE__, rc, __PRETTY_FUNCTION__); \
        goto label;                     \
    }                                   \
} while (0)

#define EXIT_IF_NONZERO(expr) do { \
    int rc = (expr);                    \
    if (rc) {                \
        fprintf(stderr, "[%d]Error: %s failed at %s:%d with code %d in <%s>\n", \
                config.tcp_port, #expr, __FILE__, __LINE__, rc, __PRETTY_FUNCTION__); \
        return rc;                     \
    }                                   \
} while (0)

char sync_str[] = "S";

Host::Host(int gid_idx, int tcp_port, const char *servername, const char *dev_name, bool isSender) {
    config.gid_idx = gid_idx;
    config.tcp_port = tcp_port;
    config.server_name = servername;
    config.dev_name = dev_name;
    config.ib_port = 1;
    config.udp_sport = 0;
    this->isSender = isSender;
    config.print();
}


int Host::sock_connect() {
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;

    struct addrinfo hints = {
        .ai_flags    = AI_PASSIVE,
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    if(sprintf(service, "%d", config.tcp_port) < 0) {
        goto sock_connect_exit;
    }

    /* Resolve DNS address, use sockfd as temp storage */
    GOTO_ERR_IF_NONZERO(getaddrinfo(config.server_name, service, &hints, &resolved_addr), sock_connect_exit);

    /* Search through results and find the one we want */
    for(iterator = resolved_addr; iterator ; iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        if(sockfd >= 0) {
            if(config.server_name) {
                /* Client mode. Initiate connection to remote */
                if((tmp=connect(sockfd, iterator->ai_addr, iterator->ai_addrlen))) {
                    fprintf(stdout, "failed connect \n");
                    close(sockfd);
                    sockfd = -1;
                }
            }
            else {
                /* Server mode. Set up listening socket an accept a connection */
                listenfd = sockfd;
                sockfd = -1;
                if(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen)) {
                    goto sock_connect_exit;
                }
                listen(listenfd, 1);
                sockfd = accept(listenfd, NULL, 0);
            }
        }
    }

sock_connect_exit:
    if(listenfd) {
        close(listenfd);
    }

    if(resolved_addr) {
        freeaddrinfo(resolved_addr);
    }

    if(sockfd < 0) {
        if(config.server_name) {
            fprintf(stderr, "Couldn't connect to %s:%d\n", config.server_name, config.tcp_port);
        }
        else {
            perror("server accept");
            fprintf(stderr, "accept() failed\n");
        }
    }

    return sockfd;
}

int Host::sock_sync_data(int xfer_size, char *local_data, char *remote_data) {
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write(res.sock, local_data, xfer_size);
    if(rc < xfer_size) {
        fprintf(stderr, "Failed writing data during sock_sync_data\n");
    } else {
        rc = 0;
    }

    while(!rc && total_read_bytes < xfer_size) {
        read_bytes = read(res.sock, remote_data + total_read_bytes, xfer_size - total_read_bytes);
        if(read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }
    return rc;
}

int Host::poll_completion() {
    struct ibv_wc wc;
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    int poll_result;
    int rc = 0;
    /* poll the completion for a while before giving up of doing it .. */
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do {
        poll_result = ibv_poll_cq(res.cq, 1, &wc);
        gettimeofday(&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    } while((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));

    if(poll_result < 0) {
        /* poll CQ failed */
        fprintf(stderr, "poll CQ failed\n");
        rc = 1;
    } else if(poll_result == 0) {
        /* the CQ is empty */
        //fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
        rc = 2;
    } else {
        /* CQE found */
        //fprintf(stdout, "completion was found in CQ with status 0x%x\n", wc.status);
        /* check the completion status (here we don't care about the completion opcode */
        if(wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "got bad completion with status: 0x%x, vendor syndrome: 0x%x\n", 
                    wc.status, wc.vendor_err);
            rc = 3;
        }
    }
    return rc;
}

int Host::post_send(int opcode) {
    struct ibv_send_wr sr;                  // Send Work Request
    struct ibv_sge sge;                     //Scatter/Gather Entry
    struct ibv_send_wr *bad_wr = NULL;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res.buf;
    sge.length = MSG_SIZE;
    sge.lkey = res.mr->lkey;

    /* prepare the send work request */
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.wr_id = 0;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = (enum ibv_wr_opcode)opcode;
    sr.send_flags = IBV_SEND_SIGNALED;
    if(opcode != IBV_WR_SEND) {
        sr.wr.rdma.remote_addr = res.remote_props.addr;
        sr.wr.rdma.rkey = res.remote_props.rkey;
    }

    /* there is a Receive Request in the responder side, so we won't get any into RNR flow */
    EXIT_IF_NONZERO(ibv_post_send(res.qp, &sr, &bad_wr));
    //switch(opcode) {
    //case IBV_WR_SEND:
    //    fprintf(stdout, "Send Request was posted\n");
    //    break;
    //case IBV_WR_RDMA_READ:
    //    fprintf(stdout, "RDMA Read Request was posted\n");
    //    break;
    //case IBV_WR_RDMA_WRITE:
    //    fprintf(stdout, "RDMA Write Request was posted\n");
    //    break;
    //default:
    //    fprintf(stdout, "Unknown Request was posted\n");
    //    break;
    //}
    return 0;
}


int Host::post_receive() {
    struct ibv_recv_wr rr;
    struct ibv_sge sge;
    struct ibv_recv_wr *bad_wr;

    /* prepare the scatter/gather entry */
    memset(&sge, 0, sizeof(sge));
    sge.addr = (uintptr_t)res.buf;
    sge.length = MSG_SIZE;
    sge.lkey = res.mr->lkey;

    /* prepare the receive work request */
    memset(&rr, 0, sizeof(rr));
    rr.next = NULL;
    rr.wr_id = 0;
    rr.sg_list = &sge;
    rr.num_sge = 1;
    /* post the Receive Request to the RQ */
    EXIT_IF_NONZERO(ibv_post_recv(res.qp, &rr, &bad_wr));
    return 0;
}

int Host::resources_create() {
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;
    size_t size;
    int i;
    int mr_flags = 0;
    int cq_size = 0;
    int num_devices;

    /*===================Create Sock=======================*/
    GOTO_ERR_IF_NEG((res.sock = sock_connect()), resources_create_error);
    //fprintf(stdout, "TCP connection was established, fockfd = %d\n", res.sock);
    //fprintf(stdout, "searching for IB devices in host\n");

    /*===================Get Device Handle=================*/
    /* get device names in the system */
    GOTO_ERR_IF_NONZERO(!(dev_list = ibv_get_device_list(&num_devices)), resources_create_error);

    /* if there isn't any IB device in host */
    GOTO_ERR_IF_NONZERO(!num_devices, resources_create_error);
    //fprintf(stdout, "found %d device(s)\n", num_devices);
    /* search for the specific device we want to work with */
    for(i = 0; i < num_devices; i ++) {
        if(!config.dev_name) {
            config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
            fprintf(stdout, "device not specified, using first one found: %s\n", config.dev_name);
        }
        /* find the specific device */
        if(!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name)) {
            ib_dev = dev_list[i];
            break;
        }
    }
    /* if the device wasn't found in host */
    GOTO_ERR_IF_NONZERO(!ib_dev, resources_create_error);
    /* get device handle */
    GOTO_ERR_IF_NONZERO(!(res.ib_ctx = ibv_open_device(ib_dev)), resources_create_error);
    /* We are now done with device list, free it */
    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;


    /*===================Get Device And Port Arrtibutions=================*/
    /* query device attributions */
    GOTO_ERR_IF_NONZERO(ibv_query_device(res.ib_ctx, &res.device_attr), resources_create_error);
    //fprintf(stdout, "dev.max_qp = %d\n", res.device_attr.max_qp);
    /* query port properties */
    GOTO_ERR_IF_NONZERO(ibv_query_port(res.ib_ctx, config.ib_port, &res.port_attr), resources_create_error);

    /*===================Alloc Protect Domain=================*/
    GOTO_ERR_IF_NONZERO(!(res.pd = ibv_alloc_pd(res.ib_ctx)), resources_create_error);

    /*===================Create Completion Queue==============*/
    cq_size = 10;
    GOTO_ERR_IF_NONZERO(!(res.cq = ibv_create_cq(res.ib_ctx, cq_size, NULL, NULL, 0)), resources_create_error);

    /*===================Register Memory Buffer================*/
    size = MSG_SIZE;
    GOTO_ERR_IF_NONZERO(!(res.buf = (char *) malloc(size)), resources_create_error);
    memset(res.buf, 0, size);
    /* register the memory buffer */
    mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE ;
    GOTO_ERR_IF_NONZERO(!(res.mr = ibv_reg_mr(res.pd, res.buf, size, mr_flags)), resources_create_error);
    //fprintf(stdout, "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n",
    //        res.buf, res.mr->lkey, res.mr->rkey, mr_flags);

    /*===================Create Queue Pair================*/
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.sq_sig_all = 1;
    qp_init_attr.send_cq = res.cq;
    qp_init_attr.recv_cq = res.cq;
    qp_init_attr.cap.max_send_wr = 5;
    qp_init_attr.cap.max_recv_wr = 5;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    GOTO_ERR_IF_NONZERO(!(res.qp = ibv_create_qp(res.pd, &qp_init_attr)), resources_create_error);
    //fprintf(stdout, "QP was created, QP number=0x%x\n", res.qp->qp_num);

    return 0;
resources_create_error:
        /* Error encountered, cleanup */
    if(res.qp)
    {
        ibv_destroy_qp(res.qp);
        res.qp = NULL;
    }
    if(res.mr) {
        ibv_dereg_mr(res.mr);
        res.mr = NULL;
    }
    if(res.buf) {
        free(res.buf);
        res.buf = NULL;
    }
    if(res.cq) {
        ibv_destroy_cq(res.cq);
        res.cq = NULL;
    }
    if(res.pd) {
        ibv_dealloc_pd(res.pd);
        res.pd = NULL;
    }
    if(res.ib_ctx) {
        ibv_close_device(res.ib_ctx);
        res.ib_ctx = NULL;
    }
    if(dev_list) {
        ibv_free_device_list(dev_list);
        dev_list = NULL;
    }
    if(res.sock >= 0) {
        if(close(res.sock)) {
            fprintf(stderr, "failed to close socket\n");
        }
        res.sock = -1;
    }
    return 1;
}

int Host::modify_qp_to_init() {
    struct ibv_qp_attr attr;
    int flags;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = config.ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    EXIT_IF_NONZERO(ibv_modify_qp(res.qp, &attr, flags));
    return 0;
}

int Host::modify_qp_to_rtr(uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid) {
    struct ibv_qp_attr attr;
    int flags;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256; /* this field specifies the MTU from source code*/
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = config.ib_port;
    if(config.gid_idx >= 0) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        /* this field specify the UDP source port. if the target UDP source port is expected to be X, the value of flow_label = X ^ 0xC000 */
        if (config.udp_sport == 0){
            attr.ah_attr.grh.flow_label = 0;
        }
        else{
            attr.ah_attr.grh.flow_label = config.udp_sport ^ 0xC000;
        }
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = config.gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
            IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    EXIT_IF_NONZERO(ibv_modify_qp(res.qp, &attr, flags));
    return 0;
}


int Host::modify_qp_to_rts() {
    struct ibv_qp_attr attr;
    int flags;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    EXIT_IF_NONZERO(ibv_modify_qp(res.qp, &attr, flags));
    return 0;
}

int Host::connect_qp() {
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    char temp_char;
    union ibv_gid my_gid;
    if(config.gid_idx >= 0) {
        GOTO_ERR_IF_NONZERO(ibv_query_gid(res.ib_ctx, config.ib_port, config.gid_idx, &my_gid), connect_qp_exit);
    } else {
        memset(&my_gid, 0, sizeof(my_gid));
    }

    /* exchange using TCP sockets info required to connect QPs */
    local_con_data.addr = htonll((uintptr_t)res.buf);
    local_con_data.rkey = htonl(res.mr->rkey);
    local_con_data.qp_num = htonl(res.qp->qp_num);
    local_con_data.lid = htons(res.port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);
    //fprintf(stdout, "\nLocal LID = 0x%x\n", res.port_attr.lid);
    GOTO_ERR_IF_NONZERO(sock_sync_data(sizeof(struct cm_con_data_t), (char *) &local_con_data, (char *) &tmp_con_data), connect_qp_exit);

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    /* save the remote side attributes, we will need it for the post SR */
    res.remote_props = remote_con_data;
    //fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data.addr);
    //fprintf(stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
    //fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    //fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    //if(config.gid_idx >= 0) {
    //    uint8_t *p = remote_con_data.gid;
    //    fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
    //            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    //}

    GOTO_ERR_IF_NONZERO(modify_qp_to_init(), connect_qp_exit);
    GOTO_ERR_IF_NONZERO(modify_qp_to_rtr(remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid), connect_qp_exit);
    GOTO_ERR_IF_NONZERO(modify_qp_to_rts(), connect_qp_exit);
    GOTO_ERR_IF_NONZERO(sock_sync_data(1, sync_str, &temp_char), connect_qp_exit);

    return 0;

connect_qp_exit:
    return 1;
}

int Host::resources_destroy() {
    int rc = 0;
    if(res.qp) {
        if(ibv_destroy_qp(res.qp))
        {
            fprintf(stderr, "failed to destroy QP\n");
            rc = 1;
        }
    }
    if(res.mr) {
        if(ibv_dereg_mr(res.mr))
        {
            fprintf(stderr, "failed to deregister MR\n");
            rc = 1;
        }
    }
    if(res.buf) {
        free(res.buf);
    }
    if(res.cq) {
        if(ibv_destroy_cq(res.cq)) {
            fprintf(stderr, "failed to destroy CQ\n");
            rc = 1;
        }
    }
    if(res.pd) {
        if(ibv_dealloc_pd(res.pd)) {
            fprintf(stderr, "failed to deallocate PD\n");
            rc = 1;
        }
    }
    if(res.ib_ctx) {
        if(ibv_close_device(res.ib_ctx)) {
            fprintf(stderr, "failed to close device context\n");
            rc = 1;
        }
    }
    if(res.sock >= 0) {
        if(close(res.sock)) {
            fprintf(stderr, "failed to close socket\n");
            rc = 1;
        }
    }
    return rc;
}

int Host::init() {
    memset(&res, 0, sizeof(res));
    res.sock = -1;
    GOTO_ERR_IF_NONZERO(resources_create(), init_error);
    GOTO_ERR_IF_NONZERO(connect_qp(), init_error);
    return 0;
init_error:
    resources_destroy();
    return -1;
}

void Host::run() {
    char temp_buf[10];
    GOTO_ERR_IF_NONZERO(init(), host_run_exit);
    printf("[%d]Successfully established RDMA connection! This is %s\n", config.tcp_port, isSender ? "Sender" : "Receiver");
    while (true) {
        if (isSender) {
            GOTO_ERR_IF_NONZERO(post_send(IBV_WR_RDMA_WRITE), host_run_exit);
            GOTO_ERR_IF_NONZERO(poll_completion(), host_run_exit);
            GOTO_ERR_IF_NONZERO(sock_sync_data(1, sync_str, temp_buf), host_run_exit);
            printf("[%d] successfully send data\n", config.tcp_port);
            std::this_thread::sleep_for(std::chrono::milliseconds(std::rand() % 97));
        } else {
            //GOTO_ERR_IF_NONZERO(post_receive(), host_run_exit);
            GOTO_ERR_IF_NONZERO(sock_sync_data(1, sync_str, temp_buf), host_run_exit);
            //GOTO_ERR_IF_NONZERO(poll_completion(), host_run_exit);
            printf("[%d] successfully receive data\n", config.tcp_port);
        }
        break; //暂时只发送一次
    }
    printf("[%d] successfully finish the task\n", config.tcp_port);
    return;
host_run_exit:
    printf("[%d] has error when running, destroying resources...\n", config.tcp_port);
}

void Host::run_in_thread() {
    thread_obj = std::thread(&Host::run, this);
    thread_obj.detach();
}

Host::~Host() {
    resources_destroy();
}
