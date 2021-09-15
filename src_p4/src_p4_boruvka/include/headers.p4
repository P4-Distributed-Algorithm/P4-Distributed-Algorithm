/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_EXP = 0x88b5;


const bit<8> SYNC_BROADCAST = 0;
const bit<8> SYNC_REPLY = 1;
const bit<8> FIN_REPLY = 2;
const bit<8> NORMAL_PKT = 3;
const bit<8> START_BROADCAST = 4;
const bit<8> ACK_MSG = 5;


typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ethertype;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4_addr_t src;
    ipv4_addr_t dst;
}

header CPU_t{
    bit<8> message_type;
    bit<32> stage;
    bit<32> idx;
    bit<32> min_val;
    bit<8> flag;
    bit<8> req_type;
    bit<8> channel_id;
    bit<8> message_id;
    bit<32> dbg_info;
    bit<8> is_cpu;
}


header sync_hdr_t{
    bit<8> message_type;
    bit<32> stage;
    bit<8> channel_id;
    bit<8> message_id;
}


/*
 * self defined payload
 */

header payload_t{
    bit<8> req_type;
    bit<32> idx;
    bit<8> flag;
    bit<32> min_val;
}

header data_pkt_payload_t{
    bit<32> idx;
}

struct metadata {
    //tmp use
    bit<32> self_stage;
    bit<6> sons_cnt;
    bit<6> neighbor_cnt;
    bit<8> message_type;
    bit<6> from_index;
    bit<6> reply_cnt;
    bit<48> father;
    bit<9> egress_port;
    bit<6> fin_reply_idx;
    bit<2> is_cpu;
    bit<8> resend_channel_id;
    bit<8> channel_id;

    bit<32> terminate_stage;
    bit<8> clone_message_type;

    bit<8> old_message_type;
    bit<32> old_self_stage;
    bit<32> old_idx;
    bit<32> old_min_val;
    bit<8> old_req_type;
    bit<8> old_flag;
    bit<8> old_channel_id;
    bit<8> old_message_id;

    bit<32> dbg_tmp;

    bit<32> self_host_id;
    bit<32> edge_weight;
    bit<32> gen_tree_father;
    bit<1> alg_ret;
    bit<1> alg_term;

    bit<8> egress_flag;
    bit<8> egress_req_type;
    bit<32> egress_min_val;
    bit<32> egress_idx;

    bit<8> except_port;
    bit<8> except_egress_flag;
    bit<8> except_egress_req_type;
    bit<32> except_egress_min_val;
    bit<32> except_egress_idx;

    bit<8> delete_son_port;
    bit<8> delete_neighbor_port;
    bit<8> add_son_port;
    bit<8> no_send_port; // 255: no requirement. 
    bit<2> send_port_option;  // 0: send to all sons; 1: send to all neighbors; 2: specified by mcast_grp
    bit<1> egress_initialize_option;

    bit<1> egress_is_drop;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    CPU_t        CPU;
	sync_hdr_t   sync_header;
    payload_t    msg;
    data_pkt_payload_t data_payload;
}
