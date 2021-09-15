/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6


const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_EXP = 0x88b5;


const bit<8> SYNC_BROADCAST = 0;
const bit<8> SYNC_REPLY = 1;
const bit<8> FIN_REPLY = 2;
const bit<8> NORMAL_PKT = 3;
const bit<8> START_BROADCAST = 4;
const bit<8> ACK_MSG_NORMAL = 5;
const bit<8> ACK_MSG_SYNC = 6;


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
    bit<32> value;
    bit<8> message_id;
    bit<32> dbg_info;
    bit<8> is_cpu;
}


header sync_hdr_t{
    bit<8> message_type;
    bit<32> stage;
    bit<8> message_id;
}


/*
 * self defined payload
 */

header payload_t{
    bit<32> value;
    bit<8> rand_value;
    bit<1> node_type;
    bit<1> edge_type;
    bit<2> inner_stage;
    bit<4> padding;
}

header data_pkt_payload_t{
    bit<32> idx;
}

struct metadata {
    // Set during ingress stage
    bit<32> self_stage;
    bit<48> father;
    bit<9> father_port;
    bit<6> sons_cnt;
    bit<6> neighbor_cnt;
    bit<32> terminate_stage;

    // set during Alg_Start
    bit<1> alg_ret;

    bit<1> d_n_b;


    bit<8> message_type;
    bit<6> from_index;
    bit<1> reply_stat;


    // tmp variables 
    bit<6> reply_cnt;
    bit<32> value;
    bit<6> fin_reply_idx;
    bit<2> is_cpu;

    bit<8> clone_message_type;
    /* debug_only metadata*/
    bit<8> old_message_type;
    bit<32> old_self_stage;
    bit<32> old_value;
    bit<8> old_message_id;

    bit<32> dbg_tmp;


    // Added for Luby algorithm
    // 1 -> the packet need to be dropped at the out of egress
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

// // 4 * 32bits
// struct stored_hdr{
//     bit<8> message_type;
//     bit<32> stage;
//     bit<8> message_id;
//     bit<32> value;
//     bit<48> last_timestamp;
//     bit<1> existence;
// }