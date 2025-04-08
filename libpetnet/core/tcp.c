/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>
#include <petlib/pet_ringbuffer.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"

#define TCP_SYN (1 << 0)
#define TCP_ACK (1 << 1)
#define TCP_PSH (1 << 2)
#define TCP_RST (1 << 3)
#define TCP_URG (1 << 4)
#define TCP_FIN (1 << 5)

#define USE_DEFAULT_SEQ ((uint32_t)(-1))
#define USE_DEFAULT_ACK ((uint32_t)(-1))


/// @dark_magic
struct pet_ringbuf;


struct socket {
    int fd;

    pet_sock_type_t   type;
    pet_sock_family_t family;

    struct {

        uint64_t connecting    : 1;
        uint64_t listening     : 1;


        uint64_t connected     : 1;
        uint64_t closed        : 1;

        uint64_t error         : 1;

    } __attribute__((packed));

    int sock_errno;

    struct pet_ringbuf * recv_buf;
    struct pet_ringbuf * send_buf;

    uint16_t local_port;
    uint16_t remote_port;

    union {
        struct ipv4_addr * local_addr_v4;
    };

    union {
        struct ipv4_addr * remote_addr_v4;
    };

    int              backlog;
    int              num_pending;
    struct list_head pending_list;


    pthread_mutex_t lock;
    pthread_cond_t  cond_var;

    int ref_cnt;
    struct list_head list_node;

};

// struct pet_ringbuf {
//     uint8_t * buf;
//     uint8_t * head;
//     uint8_t * tail;
//     size_t    size;
// };

// static struct pet_ringbuf *
// pet_create_ringbuf(uint32_t size)
// {
//     struct pet_ringbuf * rb = pet_malloc(sizeof(struct pet_ringbuf));
//     if (!rb) return NULL;

//     rb->data = pet_malloc(size);
//     if (!rb->data) {
//         pet_free(rb);
//         return NULL;
//     }

//     rb->size  = size;
//     rb->start = 0;
//     rb->end   = 0;

//     return rb;
// }

/// dark_magic



extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};


static int __send_syn_ack(struct tcp_connection * con, struct packet * recv_pkt);
static int send_ack(struct tcp_connection * con, uint32_t recv_seq, uint32_t payload_len);
static int send_fin(struct tcp_connection * con, uint32_t recv_seq);
static int __send_pkt(struct tcp_connection * con, uint8_t flags, uint32_t seq_num, uint32_t ack_num);
static struct tcp_connection * get_listen_connection(struct tcp_con_map * map,
                                                      struct ipv4_addr   * local_ip,
                                                      uint16_t             local_port,
                                                      struct ipv4_addr   * remote_ip,
                                                      uint16_t             remote_port);


static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "PSH flag",    hdr->flags.PSH);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}





int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{

    log_debug("tcp_listen: sock = %p", sock);

    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    if (!tcp_state || !tcp_state->con_map) {
        log_error("tcp_listen: tcp_state or connection map is NULL\n");
        return -1;
    }

    // Use 0.0.0.0 instead of NULL for remote_addr
    uint8_t zero[4] = {0, 0, 0, 0};
    struct ipv4_addr * dummy_remote = ipv4_addr_from_octets(zero);

    struct tcp_connection * con = create_ipv4_tcp_con(
        tcp_state->con_map,
        local_addr,
        dummy_remote,
        local_port,
        0
    );

    free_ipv4_addr(dummy_remote);

    if (!con) {
        log_error("Could not create TCP connection\n");
        return -1;
    }

    con->con_state = LISTEN;

//dark
    // if (sock->recv_buf == NULL) {
    //     sock->recv_buf = pet_create_ringbuf(4096);
    // }

    // if (sock && sock->state && sock->state->recv_buf == NULL) {
    //     sock->state->recv_buf = pet_ringbuf_create(4096);
    // }

    if (!sock) {
        log_error("Socket is NULL\n");
        put_and_unlock_tcp_con(con);
        return -1;
    }


    if (add_sock_to_tcp_con(tcp_state->con_map, con, sock) == -1) {
        log_error("Could not add socket to TCP connection\n");
        put_and_unlock_tcp_con(con);
        return -1;
    }

    put_and_unlock_tcp_con(con);
    log_debug("tcp_listen: Listening on %s:%d\n", ipv4_addr_to_str(local_addr), local_port);
    return 0;
}

int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;

    (void)tcp_state; // delete me

    return -1;
}


int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;

    (void)tcp_state; // delete me

    return -1;
}



/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
  
    (void)tcp_state; // delete me

    return 0;
}



int pet_socket_data_received(struct socket * sock, uint8_t * data, size_t len) {
    // 尝试将数据写入 recv_buf 环形缓冲区
    int bytes_written = pet_ringbuf_write(sock->recv_buf, data, len);
    if (bytes_written < 0 || (size_t)bytes_written != len) {
        log_error("recv_buf ring overflow or write error: written=%d, expected=%zu", bytes_written, len);
        return -1;
    }
    
    // 写入成功后，通知等待数据到来的线程
    pthread_mutex_lock(&sock->lock);
    pthread_cond_signal(&sock->cond_var);
    pthread_mutex_unlock(&sock->lock);
    
    return bytes_written;
}


/**
 * This function is called when a TCP packet is received
 * It will check the TCP header and handle the packet
 * 
 * The main task of this function is
 * 1. Check the TCP header
 *   a. Get TCP ip and port
 *   b. Get TCP seq_num, ack_num, header_len
 *   c. Get TCP flags: SYN, ACK, PSH, FIN
 * 2. Handle the TCP packet depending on the flags
 *   a. If SYN and not ACK, send SYN-ACK
 *   b. If ACK, check if the connection is established
 *   c. If PSH, send data to the socket
 *   d. If FIN, send FIN
 * @param pkt The packet received
 * @return 0 on success, -1 on error
 */
int 
tcp_pkt_rx(struct packet * pkt)
{        
    if (pkt->layer_3_type != IPV4_PKT) {
        return -1;
    }
    struct ipv4_raw_hdr * ipv4_hdr = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
    struct tcp_raw_hdr  * tcp_hdr  = __get_tcp_hdr(pkt);

    struct ipv4_addr    * src_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
    struct ipv4_addr    * dst_ip   = ipv4_addr_from_octets(ipv4_hdr->dst_ip);

    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dst_port = ntohs(tcp_hdr->dst_port);

    struct tcp_state    * tcp_state = petnet_state->tcp_state;
    struct tcp_con_map  * con_map   = tcp_state->con_map;

    print_tcp_header(tcp_hdr);

    // Handle IPV4 Packet
    if (tcp_hdr->flags.SYN && !tcp_hdr->flags.ACK) {
        log_debug("Received SYN from %s:%d to %s:%d\n",
                    ipv4_addr_to_str(src_ip), src_port,
                    ipv4_addr_to_str(dst_ip), dst_port);

        // Check if we have a listening connection
        // 🔥 检测是否已有连接（防止重复创建）
        struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
            con_map,
            dst_ip,    // local_ip
            src_ip,    // remote_ip
            dst_port,  // local_port
            src_port   // remote_port
        );

        if (con) {
            if (con->con_state == SYN_RCVD) {
                log_debug("Duplicate SYN received, resend SYN-ACK\n");
                __send_syn_ack(con, pkt);
                put_and_unlock_tcp_con(con);  // 不要忘记解锁！
                goto cleanup;  // 不再创建新连接
            } else {
                // 状态不是 SYN_RCVD，可以选择忽略或报错
                put_and_unlock_tcp_con(con);
            }
        }
        // Use tcpdump to check the packet
        // and find out I send two SYN packets
        // If I don't put this, the server will send two SYN-ACK packets
        // and I will receive two SYN-ACK packets
        // It is sooo hard to find out the bug 🥹🥹🥹 

        struct tcp_connection * new_con = get_listen_connection(
            con_map,
            dst_ip,    // local_ip
            dst_port,  // local_port
            src_ip,    // remote_ip
            src_port   // remote_port
        );

        /////////// thanks
        // log_debug("[test1] con = %p, con->sock = %p", new_con, new_con->sock);
        
        if (!new_con) {
            goto cleanup;
        }

        // Send SYN-ACK
        new_con->rcv_nxt = ntohl(tcp_hdr->seq_num) + 1;
        // here is new_con but I use con and try to debug many times and fail
        // crycry
        if (__send_syn_ack(new_con, pkt) == -1) {
            log_error("Failed to send SYN-ACK packet\n");
            goto cleanup;
        }
        log_debug("Sent SYN-ACK to %s:%d\n",
                    ipv4_addr_to_str(src_ip), src_port);

        put_and_unlock_tcp_con(new_con);

    } else if(tcp_hdr->flags.ACK) {

        // Fin
        if (tcp_hdr->flags.FIN) {
            log_debug("Received FIN from %s:%d to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port,
                        ipv4_addr_to_str(dst_ip), dst_port);
            struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
                con_map,
                dst_ip,    // local_ip
                src_ip,    // remote_ip
                dst_port,  // local_port
                src_port   // remote_port
            );
            if (!con) {
                log_error("Could not find TCP connection for %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);
                goto cleanup;
            }

            ////////////////////////////////////////////////////////////////////
            // Here we dont need to send FIN-ACK,because we are receiving a FIN
            // from the client, we just need to send an ACK
            // if (__send_fin_ack(con, ntohl(tcp_hdr->seq_num)) == -1) {
            //     log_error("Failed to send FIN-ACK packet\n");
            //     put_and_unlock_tcp_con(con);
            //     goto cleanup;
            // }
            // log_debug("Sent FIN-ACK to %s:%d\n",
            //             ipv4_addr_to_str(src_ip), src_port);
            ///////////////////////////////////////////////////////////////////
            // Send ACK
            if (send_ack(con, ntohl(tcp_hdr->seq_num), 1) == -1) {
                log_error("Failed to send ACK packet in received FIN part\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            }
            con->con_state = CLOSE_WAIT;
            log_debug("Sent ACK in receiving FIN to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);
            
            // Send FIN
            if (send_fin(con, ntohl(tcp_hdr->seq_num)) == -1) {
                log_error("Failed to send FIN packet\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            }
            con->con_state = LAST_ACK;
            log_debug("Sent FIN to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);
                
            put_and_unlock_tcp_con(con);
        }

        if (pkt->payload_len == 0 && !tcp_hdr->flags.PSH) {
            
            /////////// Pure ACK
            log_debug("Received ACK from %s:%d to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port,
                        ipv4_addr_to_str(dst_ip), dst_port);
            struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
                con_map,
                dst_ip,    // local_ip
                src_ip,    // remote_ip
                dst_port,  // local_port
                src_port   // remote_port
            );
            if (!con) {
                log_error("Could not find TCP connection for %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);
                goto cleanup;
            }
            ////////// Establish connection will error
            // if (con->con_state != SYN_RCVD) {
            //     log_error("Connection is not in SYN_RCVD state\n");
            //     put_and_unlock_tcp_con(con);
            //     goto cleanup;
            // }
            if (con->con_state == SYN_RCVD) {
                uint32_t client_ack = ntohl(tcp_hdr->ack_num);
                if (client_ack == con->server_seq + 1) {
                    log_debug("Received valid ACK from %s:%d to %s:%d\n",
                                ipv4_addr_to_str(src_ip), src_port,
                                ipv4_addr_to_str(dst_ip), dst_port);
                    con->con_state = ESTABLISHED;
                    put_and_unlock_tcp_con(con);
                } else {
                    log_error("Invalid ACK number from %s:%d to %s:%d\n",
                            ipv4_addr_to_str(src_ip), src_port,
                            ipv4_addr_to_str(dst_ip), dst_port);
                    put_and_unlock_tcp_con(con);
                    goto cleanup;
                }
            } else if (con->con_state == ESTABLISHED) {
                log_debug("Received duplicate ACK (connection already ESTABLISHED)\n");
                put_and_unlock_tcp_con(con);
            } else if (con->con_state == CLOSE_WAIT) {
                log_debug("Received ACK in CLOSE_WAIT state\n");
                put_and_unlock_tcp_con(con);
            } else if (con->con_state == LAST_ACK) {
                log_debug("Received ACK in LAST_ACK state\n");
                con->con_state = CLOSED;
                remove_tcp_con(con_map, con);
                put_and_unlock_tcp_con(con);
            } else {
                log_error("Connection is not in SYN_RCVD or ESTABLISHED state\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            }
        } else {
            ///////////// Data packet
            log_debug("Received data packet from %s:%d to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port,
                        ipv4_addr_to_str(dst_ip), dst_port);
            struct tcp_connection * con = get_and_lock_tcp_con_from_ipv4(
                con_map,
                dst_ip,    // local_ip
                src_ip,    // remote_ip
                dst_port,  // local_port
                src_port   // remote_port
            );

            ///////////// thanks
            // log_debug("[test2] con = %p, con->sock = %p", con, con->sock);

            if (!con) {
                log_error("Could not find TCP connection for %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);
                goto cleanup;
            }
            if (con->con_state != ESTABLISHED) {
                log_error("Connection is not in ESTABLISHED state\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            }

            // get payload
            void * payload = __get_payload(pkt);
            uint32_t len = pkt->payload_len;

            ////////////// Good note It helps a lot in debugging Data package!
            // log_debug("Payload pointer: %p, length: %d", payload, len);
            // log_debug("First few bytes: %02x %02x %02x %02x", 
            //         len > 0 ? ((uint8_t*)payload)[0] : 0,
            //         len > 1 ? ((uint8_t*)payload)[1] : 0,
            //         len > 2 ? ((uint8_t*)payload)[2] : 0,
            //         len > 3 ? ((uint8_t*)payload)[3] : 0);
            /////////////////////////////////////////////////

            //// this cannot be used
            // log_debug("recv_buf = %p", con->sock->recv_buf);

            // 🚨 添加这段 before 正式写入
            // if (con->sock) {
            //     pet_socket_received_data(con->sock, NULL, 0);  // trigger recv_buf allocation
            // }
        
            // if (con->sock && con->sock->recv_buf == NULL) {
            //     con->sock->recv_buf = pet_create_ringbuf(4096); // or some reasonable default size
            //     if (!con->sock->recv_buf) {
            //         log_error("Failed to allocate recv_buf");
            //         put_and_unlock_tcp_con(con);
            //         goto cleanup;
            //     }
            // }

            int ret = pet_socket_data_received(con->sock, payload, len);
            
            ///////////// thanks
            // log_debug("Result of pet_socket_received_data ret: %d", ret);
            if (ret == -1) {
                log_error("Failed to receive data from socket\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            } else {
                log_debug("Received %d bytes from socket\n", ret);
                log_debug("The data is: %s\n", (char *)payload);
            }

            // Send ACK
            if (send_ack(con, ntohl(tcp_hdr->seq_num), len) == -1) {
                log_error("Failed to send ACK packet\n");
                put_and_unlock_tcp_con(con);
                goto cleanup;
            }
            log_debug("Sent Data Received ACK to %s:%d\n",
                        ipv4_addr_to_str(src_ip), src_port);

            put_and_unlock_tcp_con(con);

        }
        
    }

    return 0;

cleanup:
    if (src_ip) free_ipv4_addr(src_ip);
    if (dst_ip) free_ipv4_addr(dst_ip);
    return 0;
}

static uint16_t
__calculate_tcp_checksum(struct ipv4_addr * src_ip,
                         struct ipv4_addr * dst_ip,
                         struct packet    * pkt)
{
    struct ipv4_pseudo_hdr hdr;
    uint16_t checksum = 0;

    memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

    ipv4_addr_to_octets(src_ip, hdr.src_ip);
    ipv4_addr_to_octets(dst_ip, hdr.dst_ip);

    hdr.proto = IPV4_PROTO_TCP;
    hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);
    checksum = calculate_checksum_continue(checksum, pkt->payload,     pkt->payload_len     / 2);

    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);
        checksum = calculate_checksum_finalize(checksum, &tmp, 1);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }
    return checksum;
}

static int __send_pkt(struct tcp_connection * con, uint8_t flags, uint32_t seq_num, uint32_t ack_num) {
    // Create a empty packet
    struct packet * pkt = create_empty_packet();
    if (!pkt) {
        log_error("Could not create packet\n");
        return -1;
    }

    pkt->layer_3_type = IPV4_PKT;

    // Create TCP header
    struct tcp_raw_hdr * tcp_hdr = __make_tcp_hdr(pkt, 0);
    if (!tcp_hdr) {
        log_error("Could not create TCP header for sending ACK\n");
        free_packet(pkt);
        return -1;
    }

    // src_port = my_port
    tcp_hdr->src_port = htons(con->ipv4_tuple.local_port);
    // dst_port = their_port
    tcp_hdr->dst_port = htons(con->ipv4_tuple.remote_port);
    // seq_num = current_seq
    uint32_t seq_to_use = (seq_num == USE_DEFAULT_SEQ) ? con->snd_nxt : seq_num;
    tcp_hdr->seq_num = htonl(seq_to_use);
    // ack_num = their_seq + len
    uint32_t ack_to_use = (ack_num == USE_DEFAULT_ACK) ? con->rcv_nxt : ack_num;
    tcp_hdr->ack_num = htonl(ack_to_use);

    // header_len = tcp_raw_hdr_len / 4
    tcp_hdr->header_len = (sizeof(struct tcp_raw_hdr) / 4);

    // flags
    tcp_hdr->flags.SYN = (flags & TCP_SYN) ? 1 : 0;
    tcp_hdr->flags.ACK = (flags & TCP_ACK) ? 1 : 0;
    tcp_hdr->flags.PSH = (flags & TCP_PSH) ? 1 : 0;
    tcp_hdr->flags.RST = (flags & TCP_RST) ? 1 : 0;
    tcp_hdr->flags.URG = (flags & TCP_URG) ? 1 : 0;
    tcp_hdr->flags.FIN = (flags & TCP_FIN) ? 1 : 0;

    // recv_win
    tcp_hdr->recv_win = htons(64240); // 0xF8B0 64240 bytes left

    // checksum
    tcp_hdr->checksum = __calculate_tcp_checksum(
        con->ipv4_tuple.local_ip,
        con->ipv4_tuple.remote_ip,
        pkt
    );

    int ret = ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);
    if (ret == -1) {
        log_error("Failed to send packet\n");
        free_packet(pkt);
        return -1;
    }
    log_debug("Sent packet to %s:%d\n",
                ipv4_addr_to_str(con->ipv4_tuple.remote_ip), con->ipv4_tuple.remote_port);

    return ret;
}

static int send_fin(struct tcp_connection  * con, uint32_t recv_seq) {
    // Send FIN
    uint8_t flags = TCP_FIN;
    uint32_t seq_num = con->snd_nxt;
    uint32_t ack_num = 0;
    int ret = __send_pkt(con, flags, seq_num, ack_num);
    if (ret == -1) {
        log_error("Failed to send FIN packet\n");
        return -1;
    }
    con->snd_nxt++;
    return ret;
}

static int send_ack(struct tcp_connection * con, uint32_t recv_seq, uint32_t payload_len) {
    // This is a pure ACK packet, no payload
    // We need to send an ACK packet back to the sender
    // To acknowledge the data received
    
    uint8_t flags = TCP_ACK;
    uint32_t seq_num = con->snd_nxt;
    uint32_t ack_num = con->rcv_nxt + payload_len;
    int ret = __send_pkt(con, flags, seq_num, ack_num);
    if (ret == -1) {
        log_error("Failed to send ACK packet\n");
        return -1;
    }
    // seq_num = current_seq
    // con->snd_nxt no need to be updated here
    // because we are not sending any data
    // It is a pure ACK packet
    
    return ret;
}                         

static int __send_syn_ack(struct tcp_connection * con, struct packet * recv_pkt) {
    // Create a empty packet
    struct packet * pkt = create_empty_packet();
    if (!pkt) {
        log_error("Could not create packet\n");
        return -1;
    }

    // Create TCP header
    // layer 2 and layer 3 will be autoset in the func ipv4_pkt_tx
    pkt->layer_3_type = IPV4_PKT;

    // Header of layer 4
    struct tcp_raw_hdr * tcp_hdr = __make_tcp_hdr(pkt, 0);
    if (!tcp_hdr) {
        log_error("Could not create TCP header\n");
        free_packet(pkt);
        return -1;
    }

    // src_port = my_port
    tcp_hdr->src_port = htons(con->ipv4_tuple.local_port);
    // dst_port = their_port
    // tcp_hdr->dst_port = ((struct tcp_raw_hdr *)recv_pkt->layer_4_hdr)->src_port;
    // in the get_listen_connection, we have already set the local port
    // so we can use the local port here
    // there is no need to set the dst_port again 🥹
    tcp_hdr->dst_port = htons(con->ipv4_tuple.remote_port);
    // seq_num = my_first_seq
    uint32_t server_seq = 1000; // Better to use a random number later
    tcp_hdr->seq_num = htonl(server_seq);
    con->server_seq = server_seq;
    con->snd_nxt = server_seq + 1;
    // ack_num = their_seq + 1
    tcp_hdr->ack_num = htonl(con->rcv_nxt);

    // header_len = 20
    tcp_hdr->header_len = 5; // 5 * 4 = 20 bytes

    // flags
    tcp_hdr->flags.SYN = 1;
    tcp_hdr->flags.ACK = 1;
    tcp_hdr->flags.PSH = 0;
    tcp_hdr->flags.RST = 0;
    tcp_hdr->flags.URG = 0;
    tcp_hdr->flags.FIN = 0;

    // recv_win
    tcp_hdr->recv_win = htons(64240); // 0xF8B0 64240 bytes left

    // checksum
    // tcp_hdr->checksum = 0; // TODO: calculate checksum
    pkt->payload_len = 0; // No payload
    pkt->payload     = NULL;
    tcp_hdr->checksum = __calculate_tcp_checksum(
        con->ipv4_tuple.local_ip,
        con->ipv4_tuple.remote_ip,
        pkt
    );

    int ret = ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);
    if (ret == -1) {
        log_error("Failed to send SYN-ACK packet\n");
        free_packet(pkt);
        return -1;
    }

    // make an error
    // free_packet(pkt);
    // ipv4_pkt_tx will free the packet

    return ret;
}

struct tcp_connection *
get_listen_connection(struct tcp_con_map * map,
                            struct ipv4_addr   * local_ip, 
                            uint16_t             local_port,
                            struct ipv4_addr   * remote_ip,
                            uint16_t             remote_port)
{
    struct ipv4_addr * dummy_remote = ipv4_addr_from_octets((uint8_t[4]){0, 0, 0, 0});
    if (!dummy_remote) {
        log_error("Could not create dummy remote address\n");
        return NULL;
    }

    struct tcp_connection * listen_con = get_and_lock_tcp_con_from_ipv4(
        map,
        local_ip,
        dummy_remote,
        local_port,
        0
    );
    free_ipv4_addr(dummy_remote);

    if (!listen_con) {
        log_error("Could not find listening connection for %s:%d\n",
                  ipv4_addr_to_str(local_ip), local_port);
        return NULL;
    }

    log_debug("[get_listen_connection] listen_con = %p, listen_con->sock = %p", listen_con, listen_con ? listen_con->sock : NULL);

    if (listen_con->con_state != LISTEN) {
        log_error("Connection is not in LISTEN state\n");
        put_and_unlock_tcp_con(listen_con);
        return NULL;
    }

    struct tcp_connection * new_con = create_ipv4_tcp_con(
        map,
        local_ip,
        remote_ip,
        local_port,
        remote_port
    );

    if (!new_con) {
        log_error("Could not create new TCP connection\n");
        put_and_unlock_tcp_con(listen_con);
        return NULL;
    }

    new_con->con_state = SYN_RCVD;

    // add socket to new connection, if not, socket will be NULL
    if (add_sock_to_tcp_con(map, new_con, listen_con->sock) == -1) {
        log_error("Could not add socket to new TCP connection\n");
        put_and_unlock_tcp_con(new_con);
        put_and_unlock_tcp_con(listen_con);
        return NULL;
    }
    
    put_and_unlock_tcp_con(listen_con);

    return new_con;
}

int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}
