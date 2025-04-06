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

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"


extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};



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






int 
tcp_pkt_rx(struct packet * pkt)
{        
    if (pkt->layer_3_type == IPV4_PKT) {
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
            struct tcp_connection * new_con = get_listen_conncection(
                con_map,
                dst_ip,    // local_ip
                dst_port,  // local_port
                src_ip,    // remote_ip
                src_port   // remote_port
            );
            
            if (!new_con) {
                goto cleanup;
            }

            // Send SYN-ACK
            if (__send_syn_ack(new_con, pkt) == -1) {
                log_error("Failed to send SYN-ACK packet\n");
                goto cleanup;
            }
            log_debug("Sent SYN-ACK to %s:%d\n",
                      ipv4_addr_to_str(src_ip), src_port);

            put_and_unlock_tcp_con(new_con);
        }

    }

    return -1;

cleanup:
    if (src_ip) free_ipv4_addr(src_ip);
    if (dst_ip) free_ipv4_addr(dst_ip);
    if (pkt) free_packet(pkt);
    return 0;
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
    tcp_hdr->dst_port = ((struct tcp_raw_hdr *)recv_pkt->layer_4_hdr)->src_port;
    // seq_num = my_first_seq
    uint32_t server_seq = 1000; // Better to use a random number later
    tcp_hdr->seq_num = htonl(server_seq);
    // ack_num = their_seq + 1
    uint32_t client_seq = ntohl(((struct tcp_raw_hdr *)recv_pkt->layer_4_hdr)->seq_num);
    tcp_hdr->ack_num = htonl(client_seq + 1);

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
    tcp_hdr->checksum = 0; // TODO: calculate checksum

    int ret = ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);
    if (ret == -1) {
        log_error("Failed to send SYN-ACK packet\n");
        free_packet(pkt);
        return -1;
    }

    return ret;
}

struct tcp_connection *
get_listen_conncection(struct tcp_con_map * map,
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
