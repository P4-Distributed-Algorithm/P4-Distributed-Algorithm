
/* -*- P4_16 v1 model -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"

#define DROP_PORT 511

// case 1: receive a message. This packet is "cloned" to the corresponding egress port to send an 
// ACK_MSG
// Meanwhile, store the packet in register and forward. Old stuff can be covered in case ACK arrives
// later than a normal reply message.
// case 2: receive an ACK message. "Unicast Forward" it to the corresponding egress port = ingress port. Update the
// corresponding register and drop.
// case 3: receive a dataplane packet as a "probe". In ingress pipeline, store a global timestamp. If
// the current global timestamp >= last global timestamp + TIMEOUT, "clone" the packet to all the 
// egress ports. For each egress port, we store two packets for 
// retransmission: one is for synchronizer messages, and the other is for the distributed algorithm 
// itself. We retransmit the packet with the earliest timestamp.
// Note: Always use multicast group for packets that are not related to retransmission.

#define INF 1000000000
#define MAX_PORT_CNT 64
#define CHANNEL_CNT 3
#define INF_TIMESTAMP (bit<48>)1000000000

#define SINGLE_HOP_DELAY 1100000					  // e.g. 1000ms + 100ms
#define EG_TIMEOUT_MCSEC (2 * SINGLE_HOP_DELAY)   // 2 * delay.

#define SYMBOL_OF_TERMINATE 987654321

register<bit<32> >(1) cur_stage;
register<bit<6> >(1) sync_reply_cnt;
register<bit<6> >(1) fin_reply_cnt;
register<bit<8> >(1) resend_channel_id;
register<bit<8> >(1) resend_port_id;

register<bit<8> >(MAX_PORT_CNT * 3) stored_egress_message_id;                 // for handling packet loss
register<bit<8> >(MAX_PORT_CNT * 3) stored_ingress_message_id;
register<bit<48> >(MAX_PORT_CNT * 3) stored_last_timestamp;
register<bit<8> >(MAX_PORT_CNT * 3) stored_message_type;

register<bit<8> >(MAX_PORT_CNT * 3) stored_alg_req_type;
register<bit<32> >(MAX_PORT_CNT * 3) stored_alg_idx;
register<bit<8> >(MAX_PORT_CNT * 3) stored_alg_flag;
register<bit<32> >(MAX_PORT_CNT * 3) stored_alg_min_val;

register<bit<32> >(MAX_PORT_CNT * 3) stored_stage;
register<bit<1> >(MAX_PORT_CNT * 3) stored_existence;


// mcast_grp: lower 8 bits + upper 8 bits
// lower 8 bits: for synchronizer
// mcast_grp = 1: only sons
// mcast_grp = 2: all sons + father
// mcast_grp = 3: all neighbors 
// mcast_grp = 4: father
// mcast_grp = 5: only sons (for START_BROADCAST)
// upper 8 bits: for the algorithm
// mcast_grp = 3: all neighbors
// clone session_id: 0: clone to mcast_grp = 2; 1-64: clone to port k - 1

// To distinguish the old/out-of-date retransmission packet from a new message, we store message id for every <src_mac, dst_mac> pair on each switch. 
// We maintain an ingress message_id and an egress message_id (one id for each direction). We could simply check if the pkt's message_id match with ingress message_id to determine if it is an old packet or a new packet.

// algorithm specific defines
#define MIN_BROADCAST 0
#define MIN_REPLY 1
#define FIN_BROADCAST 2
#define PULL_REQ 3
#define PULL_REPLY 4
#define PUSH_REQ 5
#define ADDEDGE_REQ 6
#define ADDEDGE_REPLY 7
#define TERMINATE 8

#define SUBSTAGE_CAST_BELONGS 1
#define SUBSTAGE_REMOVE_EDGES 2
#define SUBSTAGE_CAST_MINIMUM 3
#define SUBSTAGE_CONNECT 0

register<bit<8> >(1)gen_tree_father;
register<bit<32> >(1)belong_id;
register<bit<32> >(1)request_id;
register<bit<8> >(1)min_port;
register<bit<32> >(1)min_val;
register<bit<8> >(1)query_remain;
register<bit<8> >(1)rem_cnt;
register<bit<8> >(1)tot_neighbor;
register<bit<8> >(1)tot_sons;

register<bit<1> >(MAX_PORT_CNT)is_son;
register<bit<1> >(MAX_PORT_CNT)is_neighbor;
register<bit<1> >(MAX_PORT_CNT)new_is_son;
register<bit<1> >(MAX_PORT_CNT)new_is_neighbor;
register<bit<8> >(1)gen_tree_new_father;

// egress counters
register<bit<32> >(1) egress_counter;


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta){
	apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control Alg_Initialization(inout headers hdr,
						   inout metadata meta,
						   inout standard_metadata_t standard_metadata){
	apply{
		bit<32> sub_stage;
		bit<8> tmp_father;
		bit<8> tmp_tot_neighbor;
		bit<8> tmp_tot_sons;
		sub_stage = meta.self_stage & 3;
		if (sub_stage == SUBSTAGE_CAST_MINIMUM){
			meta.egress_initialize_option = 1;
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
		}
		else if (sub_stage == SUBSTAGE_CAST_BELONGS){
			min_val.write(0, INF);
			min_port.write(0, 255);

			gen_tree_new_father.read(tmp_father, 0);
			if (tmp_father != 255){
				gen_tree_father.write(0, tmp_father);
			}
			gen_tree_new_father.write(0, 255);
			gen_tree_father.read(tmp_father, 0);

			request_id.write(0, 0xffffffff);
			tot_neighbor.read(tmp_tot_neighbor, 0);
			query_remain.write(0, tmp_tot_neighbor);

			meta.egress_initialize_option = 1;
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
		}
	}
}

control Judge_And_Restruct(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	apply{
		bit<32> tmp_request_id;
		bit<8> tmp_min_port;
		bit<1> tmp_is_son;
		bit<8> tmp_tot_sons;
		request_id.read(tmp_request_id, 0);
		meta.egress_req_type = FIN_BROADCAST;
		if ((tmp_request_id == 0xffffffff) || (tmp_request_id < meta.self_host_id)){
			min_port.read(tmp_min_port, 0);
			is_son.read(tmp_is_son, (bit<32>)tmp_min_port);
			gen_tree_new_father.write(0, tmp_min_port);

			meta.except_port = tmp_min_port;
			meta.except_egress_flag = 1;
			meta.except_egress_idx = meta.self_host_id;
			if (tmp_is_son == 0){
				meta.except_egress_req_type = ADDEDGE_REQ;
			}
			else{
				meta.delete_son_port = tmp_min_port;
				tot_sons.read(tmp_tot_sons, 0);
				tot_sons.write(0, tmp_tot_sons - 1);
				meta.except_egress_req_type = PUSH_REQ;
				meta.alg_ret = 1;
			}
		}
		else{
			meta.alg_ret = 1;
		}
		standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
	}
}

control Alg_Start(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	Judge_And_Restruct() judge_and_restruct;
	apply{
		bit<32> sub_stage;
		bit<8> tmp_father;
		bit<8> tmp_tot_neighbor;
		bit<8> tmp_tot_sons;
		bit<32> tmp_belong_id;
		bit<8> tmp_min_port;
		bit<1> tmp_is_son;

		meta.add_son_port = 255;
		meta.delete_son_port = 255;
		meta.delete_neighbor_port = 255;
		meta.no_send_port = 255;
		meta.except_port = 255;
		meta.alg_ret = 0;

		sub_stage = meta.self_stage & 3;
		gen_tree_father.read(tmp_father, 0);

		if (sub_stage == SUBSTAGE_CAST_BELONGS){
			if (tmp_father == 255){
				belong_id.write(0, meta.self_host_id);
				meta.alg_ret = 1;
				meta.egress_req_type = FIN_BROADCAST;
				meta.egress_flag = 1;
				meta.egress_idx = meta.self_host_id;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
			}
		}
		else if (sub_stage == SUBSTAGE_REMOVE_EDGES){
			query_remain.read(tmp_tot_neighbor, 0); // only use query_remain because tot_neighbor may change after it receives an ADDEDGE_REQ message.
			if (tmp_tot_neighbor == 0){
				meta.alg_ret = 1;
			}
			else{
				belong_id.read(tmp_belong_id, 0);
				meta.egress_req_type = ADDEDGE_REQ;
				meta.egress_flag = 2;
				meta.egress_idx = tmp_belong_id;
				meta.send_port_option = 3;
				//meta.no_send_port = tmp_father;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
			}
		}
		else if (sub_stage == SUBSTAGE_CAST_MINIMUM){
			if (tmp_father == 255){
				tot_sons.read(tmp_tot_sons, 0);
				rem_cnt.write(0, tmp_tot_sons);
				meta.egress_req_type = MIN_BROADCAST;
				if (tmp_tot_sons == 0){
					min_port.read(tmp_min_port, 0);
					meta.except_port = tmp_min_port;
					meta.except_egress_req_type = ADDEDGE_REQ;
					meta.except_egress_flag = 0;
					meta.except_egress_idx = meta.self_host_id;
				}
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
			}
		}
		else{
			if (tmp_father == 255){
				min_port.read(tmp_min_port, 0);
				is_son.read(tmp_is_son, (bit<32>)tmp_min_port);
				if (tmp_is_son == 0){
					judge_and_restruct.apply(hdr, meta, standard_metadata);
				}
				else{
					meta.egress_req_type = PULL_REQ;
					meta.send_port_option = 2;
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)(tmp_min_port + 4)) << 8);
				}
			}
		}
	}
}

control Fin_Reply(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	Alg_Initialization() alg_initialization;
	Alg_Start() alg_start;
	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
	}
	
	action send_to_cpu(){
		meta.is_cpu = 1;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp & 0xff00;
		if (standard_metadata.mcast_grp == 0){
			standard_metadata.egress_spec = DROP_PORT;
		}
	}
	
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		standard_metadata.egress_spec = DROP_PORT;
	}

	// action initial_broadcast(){
	// 	cur_stage.write((bit<32>)0, meta.self_stage + 1);
	// 	standard_metadata.mcast_grp = standard_metadata.mcast_grp | 1;
	// 	alg_initialization.apply(hdr, meta, standard_metadata);
	// 	meta.message_type = SYNC_BROADCAST;
	// }
	
	apply{
		fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);

		if (meta.alg_term == 1){
			meta.egress_min_val = SYMBOL_OF_TERMINATE; // symbol of termination
			send_to_cpu();
			//drop();
		}
		else if (meta.reply_cnt >= meta.sons_cnt){
			fin_reply_cnt.write((bit<32>)0, 0);
			if (meta.father != (bit<48>)0xffffffffffff){
				meta.message_type = FIN_REPLY;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | 4;
				// standard_metadata.egress_spec = meta.egress_port;
			}
			else{
				// initial_Broadcast
				meta.self_stage = meta.self_stage + 1;
				cur_stage.write((bit<32>)0, meta.self_stage);
				if (((meta.self_stage & 3) == 1) || ((meta.self_stage & 3) == 3)){
					
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | 1;
					alg_initialization.apply(hdr, meta, standard_metadata);
					meta.message_type = SYNC_BROADCAST;
				}
				else{
					alg_start.apply(hdr, meta, standard_metadata);        // it should be guaranteed that there is no conflict between the alg_start and the last NORMAL_PKT on the root
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | 5;
					if (meta.alg_ret == 1){ 
						fin_reply_cnt.write((bit<32>)0, 1);
					}
				}
			}
		}
		else{
			send_to_cpu();
			//drop();
		}
	}
}



control Max_Value_Broadcast(inout headers hdr,
				            inout metadata meta,
				            inout standard_metadata_t standard_metadata){
	Alg_Start() alg_start;
	apply{
		alg_start.apply(hdr, meta, standard_metadata);

		standard_metadata.mcast_grp = standard_metadata.mcast_grp | 5;
		if (meta.alg_ret == 1){ 
			fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
			fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);

			// This node cannot be the root. It must guarantee that some other nodes do not finish at this stage.
			if (meta.reply_cnt >= meta.sons_cnt){
				fin_reply_cnt.write((bit<32>)0, 0);
				meta.message_type = FIN_REPLY;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp ^ 5 ^ 2;
			}
		}
	}
}


control Sync_Reply(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	Max_Value_Broadcast() max_value_broadcast; 

	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
	}
	action send_to_cpu(){
		meta.is_cpu = 1;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp & 0xff00;
		if (standard_metadata.mcast_grp == 0){
			standard_metadata.egress_spec = DROP_PORT;
		}
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		standard_metadata.egress_spec = DROP_PORT;
	}

	apply{
		sync_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		sync_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);
		if (meta.reply_cnt + 1 >= meta.sons_cnt){
			sync_reply_cnt.write((bit<32>)0, 0);

			if (meta.father != (bit<48>)0xffffffffffff){
				meta.message_type = SYNC_REPLY;
				//standard_metadata.egress_spec = meta.egress_port;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | 4;
			}
			else{
				max_value_broadcast.apply(hdr, meta, standard_metadata);
			}
		}
		else{
			send_to_cpu();
			//drop();
		}
	}
}

control Sync_Broadcast(inout headers hdr,
					   inout metadata meta,
					   inout standard_metadata_t standard_metadata){
	Alg_Initialization() alg_initialization;
	Sync_Reply() sync_reply;
	apply{
		// initialization
		alg_initialization.apply(hdr, meta, standard_metadata);

		if (meta.sons_cnt == 0){
			sync_reply.apply(hdr, meta, standard_metadata);
		}
		else{
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | 1;
			meta.message_type = SYNC_BROADCAST;
		}
	}
}



control Nml_Pkt_Cb(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	Judge_And_Restruct() judge_and_restruct;

	action send_to_cpu(){
		meta.is_cpu = 1;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp & 0xff00;
		if (standard_metadata.mcast_grp == 0){
			standard_metadata.egress_spec = DROP_PORT;
		}
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		standard_metadata.egress_spec = DROP_PORT;
	}
	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
	}

	

	action mark_as_terminate(){
		meta.alg_ret = 1;
		meta.alg_term = 1;
		meta.egress_req_type = TERMINATE;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
	}

	

	
	Fin_Reply() fin_reply;
	apply{
		bit<8> tmp_min_port;
		bit<32> tmp_belong_id;
		bit<8> tmp_query_remain;
		bit<8> tmp_tot_sons;
		bit<8> tmp_tot_neighbor;
		bit<8> tmp_father;
		bit<8> tmp_rem_cnt;
		bit<1> tmp_is_son;
		bit<32> tmp_request_id;
		bit<32> tmp_min_val;
		
		

		meta.add_son_port = 255;
		meta.delete_son_port = 255;
		meta.delete_neighbor_port = 255;
		meta.no_send_port = 255;
		meta.except_port = 255;
		meta.alg_ret = 0;
		
		if (hdr.msg.req_type == ADDEDGE_REQ){
			meta.egress_req_type = ADDEDGE_REPLY;
			meta.except_port = 255;
			if (hdr.msg.flag == 0){
				meta.egress_flag = 0;
				min_port.read(tmp_min_port, 0);
				if (tmp_min_port == (bit<8>)standard_metadata.ingress_port){
					request_id.write(0, hdr.msg.idx);
				}
			}
			else if (hdr.msg.flag == 1){
				meta.egress_flag = 0;
				meta.add_son_port = (bit<8>)standard_metadata.ingress_port;
				tot_sons.read(tmp_tot_sons, 0);
				tot_sons.write(0, tmp_tot_sons + 1);
			}
			else{
				belong_id.read(tmp_belong_id, 0);
				meta.egress_flag = 1;
				if (tmp_belong_id == hdr.msg.idx){
					meta.egress_flag = 2;
					meta.delete_neighbor_port = (bit<8>)standard_metadata.ingress_port;
					tot_neighbor.read(tmp_tot_neighbor, 0);
					tot_neighbor.write(0, tmp_tot_neighbor - 1);
				}
			}
			meta.send_port_option = 2;
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | ((bit<16>)(standard_metadata.ingress_port + 4) << 8);
			meta.channel_id = 1; // !!!
		}
		else if (hdr.msg.req_type == ADDEDGE_REPLY){
			if (hdr.msg.flag >= 1){
				query_remain.read(tmp_query_remain, 0);
				query_remain.write(0, tmp_query_remain - 1);
				if (tmp_query_remain - 1 == 0){
					meta.alg_ret = 1;
				}
				if (hdr.msg.flag == 2){
					// do nothing
				}
				else if (hdr.msg.flag == 1){
					min_val.read(tmp_min_val, 0);
					if (meta.edge_weight < tmp_min_val){
						min_val.write(0, meta.edge_weight);
						min_port.write(0, (bit<8>)standard_metadata.ingress_port);
					}
				}
			}
			else{
				meta.alg_ret = 1;
			}
		}
		else if (hdr.msg.req_type == TERMINATE){
			mark_as_terminate();
			
		}
		else if (hdr.msg.req_type == FIN_BROADCAST){
			meta.alg_ret = 1;
			if (hdr.msg.flag == 1){
				belong_id.write(0, hdr.msg.idx);
			}
			meta.egress_req_type = FIN_BROADCAST;
			meta.egress_idx = hdr.msg.idx;
			meta.egress_flag = hdr.msg.flag;
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
		}
		else if (hdr.msg.req_type == MIN_BROADCAST){
			tot_sons.read(tmp_tot_sons, 0);
			rem_cnt.write(0, tmp_tot_sons);
			meta.egress_req_type = MIN_BROADCAST;
			if (tmp_tot_sons == 0){
				min_val.read(tmp_min_val, 0);
				gen_tree_father.read(tmp_father, 0);
				meta.except_port = tmp_father;
				meta.except_egress_req_type = MIN_REPLY;
				meta.except_egress_min_val = tmp_min_val;
			}
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
		}
		else if (hdr.msg.req_type == MIN_REPLY){
			rem_cnt.read(tmp_rem_cnt, 0);
			rem_cnt.write(0, tmp_rem_cnt - 1);
			min_val.read(tmp_min_val, 0);
			if (tmp_min_val > hdr.msg.min_val){
				tmp_min_val = hdr.msg.min_val;
				min_val.write(0, hdr.msg.min_val);
				min_port.write(0, (bit<8>)standard_metadata.ingress_port);
			}
			if (tmp_rem_cnt - 1 == 0){
				gen_tree_father.read(tmp_father, 0);
				if (tmp_father != 255){
					meta.egress_req_type = MIN_REPLY;
					meta.egress_min_val = tmp_min_val;
					meta.send_port_option = 2;
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)(tmp_father + 4)) << 8);
				}
				else if (tmp_min_val == INF){
					mark_as_terminate();
				}
				else{
					min_port.read(tmp_min_port, 0);
					meta.egress_req_type = FIN_BROADCAST;
					meta.except_port = tmp_min_port;
					meta.except_egress_idx = meta.self_host_id;
					meta.except_egress_flag = 0;
					is_son.read(tmp_is_son, (bit<32>)tmp_min_port);
					if (tmp_is_son == 0){
						meta.except_egress_req_type = ADDEDGE_REQ;
					}
					else{
						meta.except_egress_req_type = PUSH_REQ;
						meta.alg_ret = 1;
					}
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
				}
			}
		}
		else if (hdr.msg.req_type == PULL_REQ){
			min_port.read(tmp_min_port, 0);
			is_son.read(tmp_is_son, (bit<32>)tmp_min_port);
			request_id.read(tmp_request_id, 0);
			gen_tree_father.read(tmp_father, 0);
			meta.egress_idx = tmp_request_id;
			if (tmp_is_son == 0){
				meta.egress_req_type = PULL_REPLY;
				meta.send_port_option = 2;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)(tmp_father + 4)) << 8);
			}
			else{
				meta.egress_req_type = PULL_REQ;
				meta.send_port_option = 2;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)(tmp_min_port + 4)) << 8);
			}
		}
		else if (hdr.msg.req_type == PULL_REPLY){
			request_id.write(0, hdr.msg.idx);
			gen_tree_father.read(tmp_father, 0);
			if (tmp_father != 255){
				meta.egress_req_type = PULL_REPLY;
				meta.egress_idx = hdr.msg.idx;
				meta.send_port_option = 2;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)(tmp_father + 4)) << 8);
			}
			else{
				judge_and_restruct.apply(hdr, meta, standard_metadata);
			}
		}
		else{
			min_port.read(tmp_min_port, 0);
			gen_tree_father.read(tmp_father, 0);
			is_son.read(tmp_is_son, (bit<32>)tmp_min_port);
			if (hdr.msg.flag == 1){
				gen_tree_father.read(tmp_father, 0);
				if (tmp_is_son == 1){
					meta.delete_son_port = tmp_min_port;
					tot_sons.read(tmp_tot_sons, 0);
					tot_sons.write(0, tmp_tot_sons - 1);
				}
				gen_tree_new_father.write(0, tmp_min_port);
				meta.add_son_port = tmp_father;
				tot_sons.read(tmp_tot_sons, 0);
				tot_sons.write(0, tmp_tot_sons + 1);
				
			}
			meta.egress_req_type = FIN_BROADCAST;
			meta.except_port = tmp_min_port;
			meta.except_egress_flag = hdr.msg.flag;
			meta.except_egress_idx = hdr.msg.idx;
			if (tmp_is_son == 0){
				meta.except_egress_req_type = ADDEDGE_REQ;
			}
			else{
				meta.except_egress_req_type = PUSH_REQ;
				meta.alg_ret = 1;
			}
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
		}

		if (meta.alg_ret == 1){
			meta.fin_reply_idx = 0; // The node itself has finished.
			fin_reply.apply(hdr, meta, standard_metadata);
		}
	}
}


control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	Fin_Reply() fin_reply;
	Sync_Reply() sync_reply;
	Sync_Broadcast() sync_broadcast;
	Nml_Pkt_Cb() nml_pkt_cb;
	Max_Value_Broadcast() max_value_broadcast;
	
	/******************* inherited code starts here       ************************/
	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
	}

	action send_to_cpu(){
		meta.is_cpu = 1;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp & 0xff00;
		if (standard_metadata.mcast_grp == 0){
			standard_metadata.egress_spec = DROP_PORT;
		}
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		standard_metadata.egress_spec = DROP_PORT;
	}

	action send_to_cpu_copy(){
		meta.is_cpu = 1;
		clone3(CloneType.I2E, 100, meta);
	}


	action modify_general_info(bit<48> father, bit<9> egress_port, bit<32> terminate_stage, bit<6> sons_cnt, bit<6>neighbor_cnt){
		meta.father = father;
		meta.egress_port = egress_port;
		meta.terminate_stage = terminate_stage;
		meta.sons_cnt = sons_cnt;
		meta.neighbor_cnt = neighbor_cnt;
	}

	table get_general_info{
		key = {
			hdr.ethernet.src_addr: exact;
		}
		actions = {
			modify_general_info;
		}
		size = 64;
		default_action = modify_general_info((bit<48>)0xffffffffffff, (bit<9>)0, (bit<32>)0, (bit<6>)0, (bit<6>)0);
	}

	action modify_target_algo_info(bit<32> host_id, bit<32> edge_weight){
		meta.self_host_id = host_id;
		meta.edge_weight = edge_weight;
	}

	table get_target_algo_info{
		key = {
			hdr.ethernet.src_addr: exact;
		}
		actions = {
			modify_target_algo_info;	
		}
		default_action = modify_target_algo_info(0, INF);
	}

	table debug_log{
		key = {
			standard_metadata.mcast_grp: exact;
			standard_metadata.egress_spec: exact;
		}
		actions = { NoAction; }
        const default_action = NoAction();
	}


	apply{
		bit<8> cur_message_id;
		bit<32> write_index;
		bit<8> tmp_resend_channel_id;
		bit<8> tmp_resend_port_id;

		meta.is_cpu = 0;
		standard_metadata.mcast_grp = 0;
		get_general_info.apply();
		cur_stage.read(meta.self_stage, (bit<32>)0);

		if (hdr.ipv4.isValid()){ // normal data plane packet
			// simple round robin algorithm
			resend_channel_id.read(tmp_resend_channel_id, 0);
			resend_port_id.read(tmp_resend_port_id, 0);
			tmp_resend_channel_id = tmp_resend_channel_id + 1;
			if (tmp_resend_channel_id == CHANNEL_CNT){
				tmp_resend_channel_id = 0;
				tmp_resend_port_id = tmp_resend_port_id + 1;
				if (tmp_resend_port_id == (bit<8>)(meta.neighbor_cnt)){
					tmp_resend_port_id = 0;
				}
			}
			resend_channel_id.write(0, tmp_resend_channel_id);
			resend_port_id.write(0, tmp_resend_port_id);
			meta.resend_channel_id = tmp_resend_channel_id;
			clone3(CloneType.I2E, (bit<32>)((tmp_resend_port_id + 1) + 1), meta);
			
			drop();
		}


		else if ((hdr.ethernet.isValid()) && (hdr.sync_header.isValid()) && (hdr.sync_header.message_type == ACK_MSG)) {
			standard_metadata.egress_spec = standard_metadata.ingress_port;
		}

		else if  ((hdr.ethernet.isValid()) && (hdr.sync_header.isValid())){
			if (hdr.sync_header.stage > meta.self_stage){
				meta.self_stage = hdr.sync_header.stage;
				cur_stage.write(0, meta.self_stage);
			}
			write_index = (bit<32>)(standard_metadata.ingress_port);
			if (hdr.sync_header.channel_id >= 1){
				write_index = write_index + MAX_PORT_CNT;
			}
			if (hdr.sync_header.channel_id >= 2){
				write_index = write_index + MAX_PORT_CNT;
			}
			stored_ingress_message_id.read(cur_message_id, write_index);
			if ((hdr.sync_header.message_id - cur_message_id) != 1){
				send_to_cpu_error();
			}
			else{
				stored_ingress_message_id.write(write_index, (cur_message_id + 1));
				
				get_target_algo_info.apply();

				if (hdr.sync_header.message_type == SYNC_BROADCAST){
					sync_broadcast.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == SYNC_REPLY){
					sync_reply.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == FIN_REPLY){
					fin_reply.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == NORMAL_PKT){
					nml_pkt_cb.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == START_BROADCAST){
					max_value_broadcast.apply(hdr,meta, standard_metadata);
				}
				else{
					send_to_cpu_error();
				}

				if (standard_metadata.mcast_grp == 0){
					drop();
				}
			}
			clone3(CloneType.I2E, (bit<32>)(standard_metadata.ingress_port + 1), meta);  // send an ACK anyway
		}
		else{
			drop();
		}
		debug_log.apply();
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control Egress_Distributed_Alg(inout headers hdr,
							   inout metadata meta,
							   inout standard_metadata_t standard_metadata){
	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
		meta.egress_is_drop = 1;
	}
	apply{
		bit<1> tmp_is_son;
		bit<1> tmp_is_neighbor;
		if (meta.delete_neighbor_port == (bit<8>)standard_metadata.egress_port){
			new_is_neighbor.write((bit<32>)meta.delete_neighbor_port, 0);
		}
		if (meta.delete_son_port == (bit<8>)standard_metadata.egress_port){
			new_is_son.write((bit<32>)meta.delete_son_port, 0);
		}
		if (meta.add_son_port == (bit<8>)standard_metadata.egress_port){
			new_is_son.write((bit<32>)meta.add_son_port, 1);
		}
		if (meta.egress_initialize_option == 1){     // update registers and drop the packet
			new_is_son.read(tmp_is_son, (bit<32>)standard_metadata.egress_port);
			is_son.write((bit<32>)standard_metadata.egress_port, tmp_is_son);
			new_is_neighbor.read(tmp_is_neighbor, (bit<32>)standard_metadata.egress_port);
			is_neighbor.write((bit<32>)standard_metadata.egress_port, tmp_is_neighbor);
			drop();
		}
		if (meta.no_send_port == (bit<8>)standard_metadata.egress_port){
			drop();
		}
		else if (meta.except_port == (bit<8>)standard_metadata.egress_port){
			if (!hdr.msg.isValid()){
				hdr.msg.setValid();
			}
			hdr.msg.req_type = meta.except_egress_req_type;
			hdr.msg.idx = meta.except_egress_idx;
			hdr.msg.flag = meta.except_egress_flag;
			hdr.msg.min_val = meta.except_egress_min_val;
		}
		else{
			is_son.read(tmp_is_son, (bit<32>)standard_metadata.egress_port);
			is_neighbor.read(tmp_is_neighbor, (bit<32>)standard_metadata.egress_port);
			if (((bit<2>)tmp_is_son != meta.send_port_option) && (meta.send_port_option != 3 || tmp_is_neighbor == 1)){
				if (!hdr.msg.isValid()){
					hdr.msg.setValid();
				}
				hdr.msg.req_type = meta.egress_req_type;
				hdr.msg.idx = meta.egress_idx;
				hdr.msg.flag = meta.egress_flag;
				hdr.msg.min_val = meta.egress_min_val;
			}
			else{
				drop();
			}
		}
	}
}

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata){
	Egress_Distributed_Alg() egress_distributed_alg;

	action send_to_control_plane(){
		clone3(CloneType.E2E, 100, meta);
	}

	action drop(){
		standard_metadata.mcast_grp = 0;
		standard_metadata.egress_spec = DROP_PORT;
	}

	action set_nhop(mac_addr_t src_addr, mac_addr_t dst_addr){
		hdr.ethernet.src_addr = src_addr;
		hdr.ethernet.dst_addr = dst_addr;
	}

	table lookup_nhop{
		key = {
			standard_metadata.egress_port: exact;
		}
		actions = {
			set_nhop;
		}
		size = 64;
	}

	table debug_log{
		key = {
			standard_metadata.instance_type: exact;
			meta.message_type: exact;
			hdr.sync_header.message_type: exact;
			standard_metadata.egress_rid: exact;

			meta.egress_req_type: exact;
			meta.egress_flag: exact;
			meta.egress_idx: exact;
			meta.egress_min_val: exact;
			meta.add_son_port: exact;
			meta.delete_son_port: exact;
			meta.delete_neighbor_port: exact;
			meta.except_port: exact;
			meta.except_egress_req_type: exact;
			meta.except_egress_flag: exact;
			meta.except_egress_idx: exact;
			meta.except_egress_min_val: exact;
			meta.send_port_option: exact;
			meta.no_send_port: exact;
			meta.egress_initialize_option: exact;
		}
		actions = { NoAction; }
        const default_action = NoAction();
	}


	apply{
		bit<8> cur_message_id;
		bit<48> sync_last_timestamp;
		bit<48> normal_last_timestamp;
		bit<1> cur_existence;
		bit<48> cur_global_ts;
		bit<8> cur_message_type;
		bit<32> current_stage;
		bit<32> write_index;
		bit<32> tmp_min_val;
		bit<32> tmp_idx;
		bit<8> tmp_req_type;
		bit<8> tmp_flag;
		bit<1> do_not_send = 0;
		bit<32> tmp_counter;

		

		if ((standard_metadata.instance_type == 1) && (meta.is_cpu >= 1)) {    // I2E
			send_to_control_plane();   // clone a copy to the control plane
		}
		if (standard_metadata.instance_type == 2){
			hdr.CPU.setValid();
			hdr.CPU.is_cpu = (bit<8>)meta.is_cpu;
			hdr.CPU.message_type = meta.old_message_type;
			hdr.CPU.channel_id = meta.old_channel_id;
			hdr.CPU.message_id = meta.old_message_id;
			hdr.CPU.stage = meta.old_self_stage;
			hdr.CPU.dbg_info = meta.dbg_tmp;
			if (meta.old_message_type == NORMAL_PKT){
				hdr.CPU.idx = meta.old_idx;
				hdr.CPU.min_val = meta.old_min_val;
				hdr.CPU.flag = meta.old_flag;
				hdr.CPU.req_type = meta.old_req_type;
			}
			else{
				hdr.CPU.min_val = 233;
			}
			if (!hdr.msg.isValid()){
				hdr.msg.setValid();
			}
			if (meta.egress_min_val == SYMBOL_OF_TERMINATE){
				hdr.msg.min_val = meta.egress_min_val;
			}

		}
		else{
			if (hdr.sync_header.isValid()){
				meta.old_message_type = hdr.sync_header.message_type;
				meta.old_self_stage = hdr.sync_header.stage;
				meta.old_message_id = hdr.sync_header.message_id;
				meta.old_channel_id = hdr.sync_header.channel_id;
			}
			if (hdr.msg.isValid()){
				meta.old_idx = hdr.msg.idx;
				meta.old_min_val = hdr.msg.min_val;
				meta.old_flag = hdr.msg.flag;
				meta.old_req_type = hdr.msg.req_type;
			}

			
			if (standard_metadata.instance_type == 1){    // cloned packet. Two cases: ACK_MSG or retransmission msg
				if (hdr.ipv4.isValid()){
					// check_and_retransmit
					hdr.sync_header.setValid();
					hdr.ipv4.setInvalid();
					hdr.ethernet.ethertype = TYPE_EXP;

					cur_global_ts = standard_metadata.egress_global_timestamp;
					
					write_index = (bit<32>)(standard_metadata.egress_port);
					if (meta.resend_channel_id >= 1){
						write_index = write_index + MAX_PORT_CNT;
					}
					if (meta.resend_channel_id >= 2){
						write_index = write_index + MAX_PORT_CNT;
					}
					stored_last_timestamp.read(sync_last_timestamp, write_index);
					stored_existence.read(cur_existence, write_index);
					if (cur_existence == 0){
						sync_last_timestamp = cur_global_ts;
					}
					if (cur_global_ts - sync_last_timestamp < EG_TIMEOUT_MCSEC){
						drop();
						do_not_send = 1;
					}
					else{	
						stored_egress_message_id.read(cur_message_id, write_index);
						stored_message_type.read(cur_message_type, write_index);
						stored_stage.read(current_stage, write_index);

						hdr.sync_header.message_type = cur_message_type;
						hdr.sync_header.message_id = cur_message_id;
						hdr.sync_header.stage = current_stage;
						hdr.sync_header.channel_id = meta.resend_channel_id;
						
						if (meta.resend_channel_id == 0){
							if (hdr.msg.isValid()){
								hdr.msg.setInvalid();
							}
						}
						else{
							stored_alg_req_type.read(tmp_req_type, write_index);
							stored_alg_flag.read(tmp_flag, write_index);
							stored_alg_min_val.read(tmp_min_val, write_index);
							stored_alg_idx.read(tmp_idx, write_index);
							if (!hdr.msg.isValid()){
								hdr.msg.setValid();
							}
							hdr.msg.idx = tmp_idx;
							hdr.msg.flag = tmp_flag;
							hdr.msg.req_type = tmp_req_type;
							hdr.msg.min_val = tmp_min_val;
						}

						stored_last_timestamp.write(write_index, standard_metadata.egress_global_timestamp);
					}
				}
				else{
					// no need to modify sync_header.message_id and channel_id
					hdr.sync_header.message_type = ACK_MSG;
					hdr.msg.setInvalid();
				}
			}
			else if (hdr.sync_header.message_type == ACK_MSG){
				write_index = (bit<32>)(standard_metadata.egress_port);
				if (hdr.sync_header.channel_id >= 1){
					write_index = write_index + MAX_PORT_CNT;
				}
				if (hdr.sync_header.channel_id >= 2){
					write_index = write_index + MAX_PORT_CNT;
				}
				stored_egress_message_id.read(cur_message_id, write_index);
				if (cur_message_id == hdr.sync_header.message_id){
					stored_existence.write(write_index, 0);
				}
				// for debugging purpose:
				hdr.sync_header.message_type = 255;
				drop();
			}
			else{
				hdr.sync_header.stage = meta.self_stage;
				if (standard_metadata.instance_type == 5){
					if (standard_metadata.egress_rid == 2){
						meta.message_type = START_BROADCAST;
					}
					else if (standard_metadata.egress_rid == 4){
						meta.message_type = NORMAL_PKT;
					}
				}
				hdr.sync_header.message_type = meta.message_type;
				if (meta.message_type == NORMAL_PKT){
					egress_distributed_alg.apply(hdr, meta, standard_metadata);
				}
				else{
					if (hdr.msg.isValid()){
						hdr.msg.setInvalid();
					}
				}

				// update stored-message
				if (meta.egress_is_drop == 0){
					if (meta.message_type == NORMAL_PKT){
						write_index = (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT);
						meta.channel_id = meta.channel_id + 1;
						if (meta.channel_id == 2){
							write_index = write_index + MAX_PORT_CNT;
						}
					}
					else{
						write_index = (bit<32>)standard_metadata.egress_port;
						meta.channel_id = 0;
					}
					
					stored_last_timestamp.write(write_index, standard_metadata.egress_global_timestamp);
					stored_message_type.write(write_index, meta.message_type);
					stored_stage.write(write_index, meta.self_stage);
					stored_existence.write(write_index, 1);
					stored_egress_message_id.read(cur_message_id, write_index);
					cur_message_id = cur_message_id + 1;
					
					stored_egress_message_id.write(write_index, cur_message_id);

					if (meta.message_type == NORMAL_PKT){
						stored_alg_flag.write(write_index, hdr.msg.flag);
						stored_alg_idx.write(write_index, hdr.msg.idx);
						stored_alg_req_type.write(write_index, hdr.msg.req_type);
						stored_alg_min_val.write(write_index, hdr.msg.min_val);
					}
					hdr.sync_header.message_id = cur_message_id;
					hdr.sync_header.channel_id = meta.channel_id;
				}
				else{
					hdr.sync_header.message_type = 254; // a dropped message
				}
			}

			lookup_nhop.apply();
			if (do_not_send == 0){
				send_to_control_plane();
				egress_counter.read(tmp_counter, 0);
				egress_counter.write(0, tmp_counter + 1);
			}
		}
		debug_log.apply();
	}
}



/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta){
	apply {}
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()) main;

