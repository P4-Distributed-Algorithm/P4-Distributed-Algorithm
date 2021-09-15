
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
#define INT_RANGE 2147483648
#define MAX_PORT_CNT 64
#define CHANNEL_CNT 3
#define INF_TIMESTAMP (bit<48>)1000000000

#define SINGLE_HOP_DELAY 1100000					  // e.g. 1000ms + 100ms
#define EG_TIMEOUT_MCSEC (2 * SINGLE_HOP_DELAY)   // 2 * delay.

#define SYMBOL_OF_TERMINATE 255

register<bit<32> >(1) cur_stage;
register<bit<6> >(1) sync_reply_cnt;
register<bit<6> >(1) term_cnt;
register<bit<6> >(1) fin_reply_cnt;
register<bit<8> >(1) resend_channel_id;
register<bit<8> >(1) resend_port_id;

register<bit<8> >(MAX_PORT_CNT * 3) stored_egress_message_id;                 // for handling packet loss
register<bit<8> >(MAX_PORT_CNT * 3) stored_ingress_message_id;
register<bit<48> >(MAX_PORT_CNT * 3) stored_last_timestamp;
register<bit<8> >(MAX_PORT_CNT * 3) stored_message_type;

register<bit<8> >(MAX_PORT_CNT * 3) stored_alg_req_type;
register<bit<8> >(MAX_PORT_CNT * 3) stored_alg_flag;

register<bit<32> >(MAX_PORT_CNT * 3) stored_stage;
register<bit<1> >(MAX_PORT_CNT * 3) stored_existence;

register<bit<32> >(1) is_terminate;

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
#define FLAG_STUCK 0
#define FLAG_RAISE 1
#define NOTIFY_COVER 0
#define NOTIFY_COVER_REPLY 1
#define RAISE_STUCK 2
#define MUL_FACTOR 256

register<bit<1> >(MAX_PORT_CNT) is_neighbor;
register<bit<1> >(MAX_PORT_CNT) is_deleted_neighbor;
register<bit<1> >(1) is_join;
register<bit<32> >(1) basis_delta_sum;
register<bit<32> >(1) sum_delta;
register<bit<32> >(1) sum_deal;
register<bit<32> >(MAX_PORT_CNT) deal;
register<bit<32> >(MAX_PORT_CNT) delta;
register<bit<6> >(1) reply_remain;
register<bit<6> >(1) remain_neighbor_cnt;
register<bit<6> >(1) newest_remain_neighbor_cnt;
register<bit<1> >(1) self_stuck_state;

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
	action set_shift(bit<32> shift_value){
		meta.tmp_arithmetic_out = shift_value;
	}
	
	table lpm_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_shift;
		}
		size = 32;
		default_action = set_shift(0);
	}

	action set_log(bit<32> log_value){
		meta.tmp_arithmetic_out = log_value;
	}

	table log_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_log;
		}
		size = 256;
		default_action = set_log(0);
	}

	action set_exp(bit<32> exp_value){
		meta.tmp_arithmetic_out = exp_value;
	}

	table exp_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_exp;
		}
		size = 256;
		default_action = set_exp(1);
	}

	apply{
		bit<6> tmp_remain_neighbor_cnt;
		bit<32> tmp_is_terminate;
		bit<32> tot_shift;

		is_terminate.read(tmp_is_terminate, 0);
		
		if ((tmp_is_terminate == 0) && ((meta.self_stage & 1) == 0)){
			newest_remain_neighbor_cnt.read(tmp_remain_neighbor_cnt, 0);
			remain_neighbor_cnt.write(0, tmp_remain_neighbor_cnt);
			reply_remain.write(0, tmp_remain_neighbor_cnt + 1);

			sum_deal.read(meta.tmp_arithmetic_in, 0);

			lpm_lookup.apply();
			tot_shift = meta.tmp_arithmetic_out + meta.alpha_shift;
			meta.tmp_arithmetic_in = meta.tmp_arithmetic_in << (31 - (bit<8>)meta.tmp_arithmetic_out);
			log_lookup.apply();
			meta.tmp_arithmetic_in = meta.tmp_arithmetic_out + meta.alpha_lookup;
			if ((meta.tmp_arithmetic_in & INT_RANGE) != 0){
				tot_shift = tot_shift + 1;
				meta.tmp_arithmetic_in = meta.tmp_arithmetic_in ^ INT_RANGE;
			}
			exp_lookup.apply();
			meta.tmp_arithmetic_out = meta.tmp_arithmetic_out >> (31 - (bit<8>)tot_shift);
			
			if (meta.tmp_arithmetic_out <= meta.beta_mul_self_weight){
				self_stuck_state.write(0, FLAG_RAISE);
			}
			else{
				self_stuck_state.write(0, FLAG_STUCK);
			}

			sum_deal.write(0, 0);
			sum_delta.write(0, 0);
		}
	}
}

control Alg_Start(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	apply{
		bit<32> tmp_sum_delta;
		bit<32> tmp_basis_delta_sum;
		bit<6> tmp_remain_neighbor_cnt;
		bit<6> tmp_reply_remain;
		bit<1> tmp_self_stuck_state;
		bit<32> tmp_is_terminate;
		is_terminate.read(tmp_is_terminate, 0);
		if ((tmp_is_terminate == 0) || (tmp_is_terminate == meta.self_stage)){
			meta.alg_ret = 0;
			meta.alg_term = 0;
			meta.delete_port = 255;
			meta.specified_port = 255;
			meta.egress_initialize_option = 0;

			if ((meta.self_stage & 1) == 1){
				sum_delta.read(tmp_sum_delta, 0);
				basis_delta_sum.read(tmp_basis_delta_sum, 0);
				if (tmp_sum_delta + tmp_basis_delta_sum >= (meta.self_weight << 8) - meta.beta_mul_self_weight){
					is_join.write(0, 1);
					remain_neighbor_cnt.read(tmp_remain_neighbor_cnt, 0);
					reply_remain.write(0, tmp_remain_neighbor_cnt);

					meta.egress_req_type = NOTIFY_COVER;
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
				}
				else{
					meta.alg_ret = 1;
				}
			}
			else{
				reply_remain.read(tmp_reply_remain, 0);
				reply_remain.write(0, tmp_reply_remain - 1);

				if (tmp_reply_remain == 1){
					meta.alg_ret = 1;
				}

				meta.egress_req_type = RAISE_STUCK;
				self_stuck_state.read(tmp_self_stuck_state, 0);
				meta.egress_flag = (bit<8>)tmp_self_stuck_state;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | (((bit<16>)3) << 8);
			}
		}
		else{
			meta.alg_ret = 1;
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
		bit<6> tmp_term_cnt;
		bit<32> tmp_stage;
		fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);

		if (hdr.sync_header.stage == 0){
			term_cnt.read(tmp_term_cnt, 0);
			term_cnt.write(0, tmp_term_cnt + 1);
		}
		
		if (meta.reply_cnt >= meta.sons_cnt){
			fin_reply_cnt.write((bit<32>)0, 0);
			term_cnt.read(tmp_term_cnt, 0);
			if (tmp_term_cnt <= meta.sons_cnt){
				meta.alg_term = 0;
			}
			else{
				meta.alg_term = 1;
				term_cnt.write(0, 0);
			}

			if ((meta.alg_term == 1) && (meta.father == (bit<48>)0xffffffffffff)){
				meta.egress_flag = 255;
				send_to_cpu();
			}
			else if (meta.father != (bit<48>)0xffffffffffff){
				meta.message_type = FIN_REPLY;
				standard_metadata.mcast_grp = standard_metadata.mcast_grp | 4;
				// standard_metadata.egress_spec = meta.egress_port;
			}
			else{
				// initial_Broadcast
				// meta.self_stage = meta.self_stage + 1;
				cur_stage.read(meta.self_stage, 0);
				meta.self_stage = meta.self_stage + 1;
				cur_stage.write((bit<32>)0, meta.self_stage);
				if ((meta.self_stage & 1) == 0){
					standard_metadata.mcast_grp = standard_metadata.mcast_grp | 1;
					alg_initialization.apply(hdr, meta, standard_metadata);
					meta.message_type = SYNC_BROADCAST;
				}
				else{
					alg_start.apply(hdr, meta, standard_metadata);
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

	action send_to_cpu(){
		meta.is_cpu = 1;
		standard_metadata.mcast_grp = standard_metadata.mcast_grp & 0xff00;
		if (standard_metadata.mcast_grp == 0){
			standard_metadata.egress_spec = DROP_PORT;
		}
	}

	apply{
		bit<6> tmp_term_cnt;

		alg_start.apply(hdr, meta, standard_metadata);

		standard_metadata.mcast_grp = standard_metadata.mcast_grp | 5;

		if (meta.alg_ret == 1){ 
			fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
			fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);

			// This node cannot be the root. It must guarantee that some other nodes do not finish at this stage.
			if (meta.reply_cnt >= meta.sons_cnt){
				term_cnt.read(tmp_term_cnt, 0);
				if (tmp_term_cnt <= meta.sons_cnt){
					meta.alg_term = 0;
				}
				else{
					meta.alg_term = 1;
					term_cnt.write(0, 0);
				}

				if ((meta.alg_term == 1) && (meta.father == (bit<48>)0xffffffffffff)){
					meta.egress_flag = 255;
					send_to_cpu();
				}
				else{
					fin_reply_cnt.write((bit<32>)0, 0);
					meta.message_type = FIN_REPLY;
					standard_metadata.mcast_grp = standard_metadata.mcast_grp ^ 5 ^ 2;
				}
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

	action set_shift(bit<32> shift_value){
		meta.tmp_arithmetic_out = shift_value;
	}
	
	table lpm_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_shift;
		}
		size = 32;
		default_action = set_shift(0);
	}

	action set_log(bit<32> log_value){
		meta.tmp_arithmetic_out = log_value;
	}

	table log_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_log;
		}
		size = 256;
		default_action = set_log(0);
	}

	action set_exp(bit<32> exp_value){
		meta.tmp_arithmetic_out = exp_value;
	}

	table exp_lookup{
		key = {
			meta.tmp_arithmetic_in: lpm;
		}
		actions = {
			set_exp;
		}
		size = 256;
		default_action = set_exp(1);
	}

	
	Fin_Reply() fin_reply;
	apply{
		meta.alg_term = 0;
		meta.delete_port = 255;
		meta.specified_port = 255;
		meta.egress_initialize_option = 0;

		bit<6> tmp_reply_remain;
		bit<32> tmp_sum_deal;
		bit<32> tmp_deal;
		bit<32> tmp_sum_delta;
		bit<32> tmp_delta;
		bit<1> tmp_join;
		bit<32> tmp_basis_delta_sum;
		bit<6> tmp_remain_neighbor_cnt;
		bit<1> tmp_self_stuck_state;
		bit<6> tmp_term_cnt;
		bit<32> tmp_is_terminate;
		bit<32> tot_shift;

		if (hdr.msg.req_type == NOTIFY_COVER){
			meta.delete_port = (bit<8>)standard_metadata.ingress_port;
			newest_remain_neighbor_cnt.read(tmp_remain_neighbor_cnt, 0);
			newest_remain_neighbor_cnt.write(0, tmp_remain_neighbor_cnt - 1);
			if (tmp_remain_neighbor_cnt == 1){
				meta.alg_term = 1;
			}

			sum_deal.read(tmp_sum_deal, 0);
			sum_delta.read(tmp_sum_delta, 0);
			deal.read(tmp_deal, (bit<32>)standard_metadata.ingress_port);
			delta.read(tmp_delta, (bit<32>)standard_metadata.ingress_port);
			basis_delta_sum.read(tmp_basis_delta_sum, 0);

			sum_deal.write(0, tmp_sum_deal - tmp_deal);
			sum_delta.write(0, tmp_sum_delta - tmp_delta);
			basis_delta_sum.write(0, tmp_basis_delta_sum + tmp_delta);

			meta.egress_req_type = NOTIFY_COVER_REPLY;
			standard_metadata.mcast_grp = standard_metadata.mcast_grp | ((bit<16>)(standard_metadata.ingress_port + 4) << 8);
			meta.channel_id = 1;
		}
		else if (hdr.msg.req_type == NOTIFY_COVER_REPLY){
			reply_remain.read(tmp_reply_remain, 0);
			reply_remain.write(0, tmp_reply_remain - 1);
			if (tmp_reply_remain == 1){
				meta.alg_ret = 1;
			}
			is_join.read(tmp_join, 0);
			if (tmp_join == 1){
				meta.alg_term = 1;
			}
		}
		else{
			reply_remain.read(tmp_reply_remain, 0);
			reply_remain.write(0, tmp_reply_remain - 1);
			if (tmp_reply_remain == 1){
				meta.alg_ret = 1;
			}
			self_stuck_state.read(tmp_self_stuck_state, 0);

			deal.read(tmp_deal, (bit<32>)standard_metadata.ingress_port);
			if ((hdr.msg.flag == FLAG_RAISE) && (tmp_self_stuck_state == FLAG_RAISE)){
				meta.tmp_arithmetic_in = tmp_deal;
				lpm_lookup.apply();
				tot_shift = meta.tmp_arithmetic_out + meta.alpha_shift;
				meta.tmp_arithmetic_in = meta.tmp_arithmetic_in << (31 - (bit<8>)meta.tmp_arithmetic_out);

				log_lookup.apply();
				meta.tmp_arithmetic_in = meta.tmp_arithmetic_out + meta.alpha_lookup;
				if ((meta.tmp_arithmetic_in & INT_RANGE) != 0){
					tot_shift = tot_shift + 1;
					meta.tmp_arithmetic_in = meta.tmp_arithmetic_in ^ INT_RANGE;
				}
				exp_lookup.apply();
				meta.tmp_arithmetic_out = meta.tmp_arithmetic_out >> (31 - (bit<8>)tot_shift);
				tmp_deal = meta.tmp_arithmetic_out;
			}

			deal.write((bit<32>)standard_metadata.ingress_port, tmp_deal);

			sum_deal.read(tmp_sum_deal, 0);
			sum_deal.write(0, tmp_sum_deal + tmp_deal);
			delta.read(tmp_delta, (bit<32>)standard_metadata.ingress_port);
			tmp_delta = tmp_delta + tmp_deal;
			delta.write((bit<32>)standard_metadata.ingress_port, tmp_delta);
			sum_delta.read(tmp_sum_delta, 0);
			sum_delta.write(0, tmp_sum_delta + tmp_delta);
		}

		/*
		 * for benchmarking
		 */
		if (meta.alg_term == 1){
			meta.alg_term_cpu = 1;
		}

		if (meta.alg_term == 1){
			is_terminate.read(tmp_is_terminate, 0);
			if (tmp_is_terminate == 0){
				is_terminate.write(0, meta.self_stage);
				term_cnt.read(tmp_term_cnt, 0);
				term_cnt.write(0, tmp_term_cnt + 1);
			}
		}

		if (meta.alg_ret == 1){
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

	action modify_target_algo_info(bit<32> alpha_lookup, bit<32> alpha_shift, bit<32> self_weight, bit<32> beta_mul_self_weight){
		meta.alpha_lookup = alpha_lookup;
		meta.alpha_shift = alpha_shift;
		meta.self_weight = self_weight;
		meta.beta_mul_self_weight = beta_mul_self_weight;
	}

	table get_target_algo_info{
		key = {
			hdr.ethernet.src_addr: exact;
		}
		actions = {
			modify_target_algo_info;	
		}
		default_action = modify_target_algo_info(0, 0, 0, 0);
	}

	table debug_log{
		key = {
			standard_metadata.mcast_grp: exact;
			standard_metadata.egress_spec: exact;
			meta.alpha_shift: exact;
			meta.alpha_lookup: exact;
			meta.self_weight: exact;
			meta.beta_mul_self_weight: exact;
			meta.tmp_arithmetic_out: exact;
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
		cur_stage.read(meta.self_stage, (bit<32>)0);
		get_general_info.apply();

		

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



		else if ((hdr.ethernet.isValid()) && (hdr.sync_header.isValid()) && (hdr.sync_header.message_type >= ACK_MSG)) {
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
		bit<1> tmp_is_neighbor;
		bit<1> tmp_is_deleted_neighbor;
		is_neighbor.read(tmp_is_neighbor, (bit<32>)standard_metadata.egress_port);
		if (tmp_is_neighbor == 0){
			drop();
		}
		else{
			if (meta.delete_port == (bit<8>)standard_metadata.egress_port){
				is_deleted_neighbor.write((bit<32>)standard_metadata.egress_port, 1);
			}
		    if (meta.egress_initialize_option == 1){     // update registers and drop the packet
				is_deleted_neighbor.read(tmp_is_deleted_neighbor, (bit<32>)standard_metadata.egress_port);
				if (tmp_is_deleted_neighbor == 1){
					is_neighbor.write((bit<32>)standard_metadata.egress_port, 0);
				}
				drop();
			}
		
			else if ((meta.specified_port == 255) || (meta.specified_port == (bit<8>)standard_metadata.egress_port)){
				if (!hdr.msg.isValid()){
					hdr.msg.setValid();
				}
				hdr.msg.req_type = meta.egress_req_type;
				hdr.msg.flag = meta.egress_flag;
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
			meta.specified_port: exact;
			meta.delete_port: exact;
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
				hdr.CPU.flag = meta.old_flag;
				hdr.CPU.req_type = meta.old_req_type;
			}
			else{
				hdr.CPU.flag = 233;
			}
			if (!hdr.msg.isValid()){
				hdr.msg.setValid();
			}
			
			/*
			 * benchmarking
			 */
			if (meta.alg_term_cpu == 1){
				hdr.msg.flag = SYMBOL_OF_TERMINATE;
			}
			// if (meta.egress_flag == SYMBOL_OF_TERMINATE){
			// 	hdr.msg.flag = SYMBOL_OF_TERMINATE;
			// }

		}
		else{
			if (hdr.sync_header.isValid()){
				meta.old_message_type = hdr.sync_header.message_type;
				meta.old_self_stage = hdr.sync_header.stage;
				meta.old_message_id = hdr.sync_header.message_id;
				meta.old_channel_id = hdr.sync_header.channel_id;
			}
			if (hdr.msg.isValid()){
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
							if (!hdr.msg.isValid()){
								hdr.msg.setValid();
							}
							hdr.msg.flag = tmp_flag;
							hdr.msg.req_type = tmp_req_type;
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
			else if (hdr.sync_header.message_type >= ACK_MSG){
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

				if ((meta.alg_term == 1) && (hdr.sync_header.message_type == FIN_REPLY)){
					hdr.sync_header.stage = 0;
				}

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
						stored_alg_req_type.write(write_index, hdr.msg.req_type);
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

