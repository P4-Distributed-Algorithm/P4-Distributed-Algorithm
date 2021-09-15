
/* -*- P4_16 v1 model -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"



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

#define MAX_PORT_CNT 64
#define CHANNEL_CNT 3
#define INF_TIMESTAMP (bit<48>)1000000000

#define SINGLE_HOP_DELAY 1100000					  // e.g. 1000ms + 100ms
#define EG_TIMEOUT_MCSEC (2 * SINGLE_HOP_DELAY)   // 2 * delay.

#define SYMBOL_OF_TERMINATE 987654321

register<bit<32> >(1) cur_stage;
register<bit<6> >(1) sync_reply_cnt;
register<bit<6> >(1) fin_reply_cnt;
register<bit<6> >(1) msg_rcv_cnt;
register<bit<32> >(1) max_value;

register<bit<8> >(1) resend_channel_id;
register<bit<8> >(1) resend_port_id;

register<bit<8> >(MAX_PORT_CNT * 3) stored_egress_message_id;                 // for handling packet loss
register<bit<8> >(MAX_PORT_CNT * 3) stored_ingress_message_id;
register<bit<48> >(MAX_PORT_CNT * 3) stored_last_timestamp;
register<bit<8> >(MAX_PORT_CNT * 3) stored_message_type;
register<bit<32> >(MAX_PORT_CNT * 3) stored_value;
register<bit<32> >(MAX_PORT_CNT * 3) stored_stage;
register<bit<1> >(MAX_PORT_CNT * 3) stored_existence;

// mcast_grp: lower 8 bits + upper 8 bits
// lower 8 bits: 
// mcast_grp = 1: only sons. SYNC_BROADCAST. rid = 1
// mcast_grp = 2: all neighbors max_value_broadcast (rid = 2) + all sons broadcast of starting message (rid = 3)
// mcast_grp = 3: all neighbors broadcast ()
// upper 8 bits:
// mcast_grp = 0: no extra single packet mcast
// mcast_grp = k > 0: extra single packet cast to port k - 1
// clone session_id: 0: clone to mcast_grp = 3; 1-64: clone to port k - 1

// To distinguish the old/out-of-date retransmission packet from a new message, we store message id for every <src_mac, dst_mac> pair on each switch. 
// We maintain an ingress message_id and an egress message_id (one id for each direction). We could simply check if the pkt's message_id match with ingress message_id to determine if it is an old packet or a new packet.

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

control Alg_Start(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	apply{
		msg_rcv_cnt.read(meta.reply_cnt, (bit<32>)0);
		msg_rcv_cnt.write((bit<32>)0, meta.reply_cnt + 1);

		standard_metadata.mcast_grp = 2;
		max_value.read(meta.value, 0);
	}
}

control Fin_Reply(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	Alg_Start() alg_start;
	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	
	action send_to_cpu(){
		meta.is_cpu = 1;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}

	// action initial_broadcast(){
	// 	cur_stage.write((bit<32>)0, meta.self_stage + 1);
	// 	standard_metadata.mcast_grp = 1;
	// 	meta.message_type = SYNC_BROADCAST;
	// }
	
	apply{
		fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);
		if (meta.reply_cnt >= meta.sons_cnt){
			fin_reply_cnt.write((bit<32>)0, 0);
			if (meta.father != (bit<48>)0xffffffffffff){
				meta.message_type = FIN_REPLY;
				standard_metadata.egress_spec = meta.egress_port;
			}
			else if (meta.self_stage < meta.terminate_stage) { // not general, but easy to implement for this example
				meta.self_stage = meta.self_stage + 1;
				cur_stage.write((bit<32>)0, meta.self_stage);
				alg_start.apply(hdr, meta, standard_metadata);
			}
			else{
				meta.value = SYMBOL_OF_TERMINATE; // symbol of termination
				send_to_cpu();
				//drop();
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
		if (meta.reply_cnt >= meta.neighbor_cnt){  
			msg_rcv_cnt.write((bit<32>)0, 0);
			
			fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
			fin_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);

			// This node cannot be the root. It must guarantee that some other nodes do not finish at this stage.
			if (meta.reply_cnt >= meta.sons_cnt){
				fin_reply_cnt.write((bit<32>)0, 0);
			 	// meta.message_type = FIN_REPLY;
			 	// clone3(CloneType.I2E, (bit<32>)meta.egress_port, meta);
				standard_metadata.mcast_grp = (((bit<16>)(meta.egress_port + 1)) << 8) + 2;
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
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu(){
		meta.is_cpu = 1;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}

	apply{
		sync_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		sync_reply_cnt.write((bit<32>)0, meta.reply_cnt + 1);
		if (meta.reply_cnt + 1 >= meta.sons_cnt){
			sync_reply_cnt.write((bit<32>)0, 0);

			if (meta.father != (bit<48>)0xffffffffffff){
				meta.message_type = SYNC_REPLY;
				standard_metadata.egress_spec = meta.egress_port;
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
	Sync_Reply() sync_reply;
	apply{
		if (meta.sons_cnt == 0){
			sync_reply.apply(hdr, meta, standard_metadata);
		}
		else{
			standard_metadata.mcast_grp = 1;
			meta.message_type = SYNC_BROADCAST;
		}
	}
}

control Nml_Pkt_Cb(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	action send_to_cpu(){
		meta.is_cpu = 1;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	
	Fin_Reply() fin_reply;
	apply{
		msg_rcv_cnt.read(meta.reply_cnt, (bit<32>)0);
		msg_rcv_cnt.write((bit<32>)0, meta.reply_cnt + 1);

		max_value.read(meta.value, (bit<32>)0);
		if (hdr.msg.value > meta.value){
			meta.value = hdr.msg.value;
		}
		max_value.write((bit<32>)0, meta.value);

		if (meta.reply_cnt >= meta.neighbor_cnt){
			msg_rcv_cnt.write((bit<32>)0, 0);
			//meta.fin_reply_idx = 0;
			fin_reply.apply(hdr, meta, standard_metadata);
		}
		else{
			send_to_cpu();
			//drop();
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
		mark_to_drop(standard_metadata);
	}

	action send_to_cpu(){
		meta.is_cpu = 1;
		// clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}

	action send_to_cpu_copy(){
		meta.is_cpu = 1;
		clone3(CloneType.I2E, 100, meta);
	}


	action modify_general_info(bit<48> father, bit<9> egress_port, bit<32> terminate_stage, bit<6> sons_cnt, bit<6> neighbor_cnt){
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

	table debug_log{
		key = {
			standard_metadata.mcast_grp: exact;
			meta.value: exact;
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
				

				//meta.dbg_tmp = (bit<32>)meta.from_index;
				if (hdr.sync_header.message_type == SYNC_BROADCAST){
					// IT SHOULD NEVER REACH HERE FOR THIS ALGORITHM
					sync_broadcast.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == SYNC_REPLY){
					// IT SHOULD NEVER REACH HERE FOR THIS ALGORITHM
					sync_reply.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == FIN_REPLY){
					//meta.fin_reply_idx = meta.from_index;
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

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata)
{
	
	action send_to_control_plane(){
		clone3(CloneType.E2E, 100, meta);
	}

	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
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
			meta.value: exact;
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
		bit<32> cur_value;
		bit<1> do_not_send = 0;
		bit<32> tmp_counter;

		debug_log.apply();

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
				hdr.CPU.value = meta.old_value;
			}
			else{
				hdr.CPU.value = 232;
			}
			if (!hdr.msg.isValid()){
				hdr.msg.setValid();
			}
			hdr.msg.value = meta.value;
		}
		else{
			if (hdr.sync_header.isValid()){
				meta.old_message_type = hdr.sync_header.message_type;
				meta.old_self_stage = hdr.sync_header.stage;
				meta.old_message_id = hdr.sync_header.message_id;
				meta.old_channel_id = hdr.sync_header.channel_id;
			}
			if (hdr.msg.isValid()){
				meta.old_value = hdr.msg.value;
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
							stored_value.read(cur_value, write_index);
							if (!hdr.msg.isValid()){
								hdr.msg.setValid();
							}
							hdr.msg.value = cur_value;
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
					if (standard_metadata.egress_rid == 3){
						meta.message_type = START_BROADCAST;
					}
					else if (standard_metadata.egress_rid == 2){
						meta.message_type = NORMAL_PKT;
					}
					else if (standard_metadata.egress_rid == 4){
						meta.message_type = FIN_REPLY;
					}
				}
				hdr.sync_header.message_type = meta.message_type;
				if (meta.message_type == NORMAL_PKT){
					if (!hdr.msg.isValid()){
						hdr.msg.setValid();
					}
					hdr.msg.value = meta.value;
				}
				else{
					if (hdr.msg.isValid()){
						hdr.msg.setInvalid();
					}
				}

				// update stored-message
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
					stored_value.write(write_index, meta.value);
				}
				hdr.sync_header.message_id = cur_message_id;
				hdr.sync_header.channel_id = meta.channel_id;
			}

			lookup_nhop.apply();
			if (do_not_send == 0){
				send_to_control_plane();
				egress_counter.read(tmp_counter, 0);
				egress_counter.write(0, tmp_counter + 1);
			}
		}
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
