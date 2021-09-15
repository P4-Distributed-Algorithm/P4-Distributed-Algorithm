
/* -*- P4_16 v1 model -*- */
#include <core.p4>
#include <v1model.p4>

#include "../include/headers.p4"
#include "../include/parsers.p4"
#include "luby_headers.p4"



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
#define INF_TIMESTAMP (bit<48>)1000000000
#define ROOT_FATHER (bit<48>)0xffffffffffff

#define ING_TIMEOUT_MCSEC 10000                     // approximately_max_delay / 2 (delay <= x with 99% probability) for a link
#define EG_TIMEOUT_MCSEC (4 * ING_TIMEOUT_MCSEC)   // 2 * delay. The actual timeout would then be 2 * delay <= timeout <= 3 * delay

#define SYMBOL_OF_TERMINATE 987654321


register<bit<32> >(1) cur_stage;
register<bit<6> >(1) sync_reply_cnt;
register<bit<6> >(1) fin_reply_cnt;



register<bit<8> >(MAX_PORT_CNT * 2) stored_egress_message_id;                 // for handling packet loss
register<bit<8> >(MAX_PORT_CNT * 2) stored_ingress_message_id;
register<bit<48> >(MAX_PORT_CNT * 2) stored_last_timestamp;
register<bit<8> >(MAX_PORT_CNT * 2) stored_message_type;
register<bit<32> >(MAX_PORT_CNT * 2) stored_value;
register<bit<32> >(MAX_PORT_CNT * 2) stored_stage;
register<bit<1> >(MAX_PORT_CNT * 2) stored_existence;
// register<bit<8> >(MAX_PORT_CNT * 2) targ_algo_message_id;
// register<stored_hdr>(MAX_PORT_CNT * 2) stored_sync_msg;
// register<stored_hdr>(MAX_PORT_CNT * 2) stored_targ_algo_msg;
register<bit<48> >(1) last_ingress_ts;

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




/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta){
	apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control Luby_Init(inout headers hdr,
						   inout metadata meta,
	                			   inout standard_metadata_t standard_metadata){
        apply {
			// First read global valid information
			bit<1> tmp_global_valid;
			global_valid.read(tmp_global_valid, 0);
			if (tmp_global_valid == INVALID) {
				return;
			}

            bit<32> stage;
            short_int tmp_deleted_cnt;
            short_int tmp_neighbor_cnt;

            // Start SEND_VALUE state
            cur_state.write(0, SEND_VALUE);

            // Calculate the number of message desired
            deleted_cnt.read(tmp_deleted_cnt, 0);
            neighbor_cnt.read(tmp_neighbor_cnt, 0);
            msg_desired.write(0, tmp_neighbor_cnt - tmp_deleted_cnt);

            // Read and step forward inner_stage
            bit<2> tmp_inner_stage;
            inner_stage.read(tmp_inner_stage, 0);
            // Step forward one stage
            tmp_inner_stage = tmp_inner_stage + 1;
            if (tmp_inner_stage == 3) {
                tmp_inner_stage = SYNC_RAND_VALUE;
            }
            inner_stage.write(0, tmp_inner_stage);

            // SYNC_RAND_VALUE stage
            if (tmp_inner_stage == SYNC_RAND_VALUE) {
                // Global states maintained from start
                bit<1> tmp_node_valid;
                node_valid.read(tmp_node_valid, 0);
                if (tmp_node_valid == INVALID) {
                    global_valid.write(0, INVALID);
                }

                bit<1> tmp_node_selected;
                node_selected.read(tmp_node_selected, 0);
                if (tmp_node_selected == 1) {
                    global_selected.write(0, 1);
                }

                // Local states to stages in Luby's algorithm
                node_selected.write(0, 1);
                node_valid.write(0, VALID);

                // Generate rand number in the range
                bit<8> tmp_rand_value;
                random(tmp_rand_value, 0, 255);
                rand_value.write(0, tmp_rand_value);

            }

        }
}
control Luby_Active(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	apply{
		// First read global valid information
		bit<1> tmp_global_valid;
		global_valid.read(tmp_global_valid, 0);
		if (tmp_global_valid != INVALID) {
	            // Check whether has finished
	            bool finish;
	            short_int tmp_msg_desired;
	            msg_desired.read(tmp_msg_desired, 0);
	            finish = (tmp_msg_desired == 0);

	            // Get inner stage
	            bit<2> tmp_inner_stage;
	            inner_stage.read(tmp_inner_stage, 0);

				// Write state
				cur_state.write(0, RECV_VALUE);
	            hdr.msg.setValid();
	            hdr.msg.inner_stage = tmp_inner_stage;
	            // Broadcast to all neighbors
	            standard_metadata.mcast_grp = 3;
	            // Start sending its random_value to its valid neighbors
	            if (tmp_inner_stage == SYNC_RAND_VALUE) {
	                // Read my tmp_rand_value
	                bit<8> tmp_rand_value;
	                rand_value.read(tmp_rand_value, 0);
	                // Copy rand value to the header
	                hdr.msg.rand_value = tmp_rand_value;
	            } else if (tmp_inner_stage == SYNC_NODE_INFO) {
	                // Send the node selected information
	                bit<1> tmp_node_selected;
	                node_selected.read(tmp_node_selected, 0);

	                if (tmp_node_selected == 1) {
	                    node_valid.write(0, INVALID);
	                    hdr.msg.node_type = NODE_SELECTED;
	                } else {
	                    hdr.msg.node_type = NODE_UNSELECTED;
	                }


	            } else if (tmp_inner_stage == SYNC_EDGE_INFO) {
	                // Send the edge deleted information
	                bit<1> tmp_node_valid;
	                node_valid.read(tmp_node_valid, 0);
	                if (tmp_node_valid == VALID) {
	                    hdr.msg.edge_type = EDGE_UNSELECTED;
	                } else {
	                    hdr.msg.edge_type = EDGE_SELECTED;
	                }
					// Use old d_n_b
					meta.d_n_b = 1;
	            }
				if (finish) {
					meta.alg_ret = NODE_FINISH;

				}

		} else {
			meta.alg_ret = NODE_FINISH;
		}
	}
}

// Called when START_BROADCAST
control Start_Broadcast(inout headers hdr,
				            inout metadata meta,
				            inout standard_metadata_t standard_metadata){
	Luby_Active() luby_active; 
	apply{
		// Invoke luby_active algoritm
		luby_active.apply(hdr, meta, standard_metadata);

		if (meta.alg_ret == NODE_FINISH) {  
			// This node has finished this round of luby algorithm
			// fin_reply_cnt += 1	
			fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
			meta.reply_cnt = meta.reply_cnt + 1;
			fin_reply_cnt.write((bit<32>)0, meta.reply_cnt);

			if (meta.reply_cnt >= meta.sons_cnt + 1){
				// Reset fin_reply_cnt
				fin_reply_cnt.write((bit<32>)0, 0);

				if (meta.father != ROOT_FATHER) {
					// (rid == 2, NORMAL_PACKET), (rid == 3, START_BROADCAST), (rid == 4, FIN_REPLY)
					standard_metadata.mcast_grp = (((bit<16>)(meta.father_port + 1)) << 8) + 2;
				} else {
					// TODO: should start sync_broadcast 
				}
			} else {
				// (rid == 2, NORMAL_PACKET), (rid == 3, START_BROADCAST)
				standard_metadata.mcast_grp = 2;
			}
		} else {
				// (rid == 2, NORMAL_PACKET), (rid == 3, START_BROADCAST)
				standard_metadata.mcast_grp = 2;
		}
	}
}

control Sync_Reply(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	Start_Broadcast() start_broadcast; 

	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu(){
		meta.is_cpu = 1;
		mark_to_drop(standard_metadata);
	}

	apply{
		// sync_reply_cnt += 1
		sync_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		meta.reply_cnt = meta.reply_cnt + 1;
		sync_reply_cnt.write((bit<32>)0, meta.reply_cnt);



		if (meta.reply_cnt >= meta.sons_cnt){
			// Clear the sync_reply_cnt
			sync_reply_cnt.write((bit<32>)0, 0);

			if (meta.father != ROOT_FATHER) {
				meta.message_type = SYNC_REPLY;
				standard_metadata.egress_spec = meta.father_port;
			}
			else{
				start_broadcast.apply(hdr, meta, standard_metadata);
			}
		}
		else{
			send_to_cpu();
		}
	}
}

control Sync_Broadcast(inout headers hdr,
					   inout metadata meta,
					   inout standard_metadata_t standard_metadata){
	
	Luby_Init() luby_init;
	Sync_Reply() sync_reply;
	apply{
		// Initialize this stage
		luby_init.apply(hdr, meta, standard_metadata);

		if (meta.sons_cnt == 0){
			sync_reply.apply(hdr, meta, standard_metadata);
		}
		else{
			// Broadcast to its sons 
			standard_metadata.mcast_grp = 1;
		}
	}
}

control Fin_Reply(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata){
	Sync_Broadcast() sync_broadcast;
	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	
	action send_to_cpu(){
		meta.is_cpu = 1;
		//clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}
	
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}
	
	apply{
		// fin_reply_cnt += 1
		fin_reply_cnt.read(meta.reply_cnt, (bit<32>)0);
		meta.reply_cnt = meta.reply_cnt + 1;
		fin_reply_cnt.write((bit<32>)0, meta.reply_cnt);

		if (meta.reply_cnt >= meta.sons_cnt + 1){
			// fin_reply_cnt = 0
			fin_reply_cnt.write((bit<32>)0, 0);
			if (meta.father != ROOT_FATHER){
				meta.message_type = FIN_REPLY;
				standard_metadata.egress_spec = meta.father_port;
			}
			else if (meta.self_stage < meta.terminate_stage) { 
				meta.self_stage = meta.self_stage + 1;
				cur_stage.write((bit<32>)0, meta.self_stage);
				// Start next round sync_broadcast 
				sync_broadcast.apply(hdr, meta, standard_metadata);
			}
			else{
				meta.value = SYMBOL_OF_TERMINATE; // symbol of termination
				send_to_cpu();
			}
		}
		else{
			send_to_cpu();
		}
	}
}


control Luby_Passive(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata){
	Fin_Reply() fin_reply;
	action send_to_cpu(){
		meta.is_cpu = 1;
		//clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}
	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}
	

	apply{

		// First read global valid information
		bit<1> tmp_global_valid;
		global_valid.read(tmp_global_valid, 0);
		if (tmp_global_valid != INVALID) {
	        // Decrease the desired number of messages
	        short_int tmp_msg_desired;
	        msg_desired.read(tmp_msg_desired, 0);
	        tmp_msg_desired = tmp_msg_desired - 1;
	        msg_desired.write(0, tmp_msg_desired);

	        bit<1> tmp_cur_state;
	        cur_state.read(tmp_cur_state, 0);

	        // Evaluate the finish state
	        bool finish;
	        finish = (tmp_msg_desired == 0) && (tmp_cur_state == RECV_VALUE);

	        if (hdr.msg.inner_stage == SYNC_RAND_VALUE) {
	            bit<8> tmp_rand_value;
	            rand_value.read(tmp_rand_value, 0);
	            // Update selected states based on imcoming rand_value
	            if (hdr.msg.rand_value <= tmp_rand_value) {
	                node_selected.write(0, 0);
	            }

	        } else if (hdr.msg.inner_stage == SYNC_NODE_INFO) {
	            // Mark this node as unselected
	            if (hdr.msg.node_type == NODE_SELECTED) {
	                node_valid.write(0, INVALID);
	            }

	        } else if (hdr.msg.inner_stage == SYNC_EDGE_INFO) {
                    // Delete this edge
                    if (hdr.msg.edge_type == EDGE_SELECTED) {
                        bit<1> if_deleted;
                        deleted_neighbors.read(if_deleted, (bit<32>)standard_metadata.ingress_port);
                        if (if_deleted == 0) {
                            short_int tmp_deleted_cnt;
                            deleted_cnt.read(tmp_deleted_cnt, 0);
                            tmp_deleted_cnt = tmp_deleted_cnt + 1;
                            deleted_cnt.write(0, tmp_deleted_cnt);
                        	deleted_neighbors.write((bit<32>)standard_metadata.ingress_port, 1);
                        }
                    }
	        }
			if (finish) {
				fin_reply.apply(hdr, meta, standard_metadata);
			} else {
				send_to_cpu();
			}
		} else {
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
	Luby_Passive() luby_passive;
	Start_Broadcast() start_broadcast;
	
	/******************* inherited code starts here       ************************/
	action drop(){
		standard_metadata.mcast_grp = 0;
		mark_to_drop(standard_metadata);
	}

	action send_to_cpu(){
		meta.is_cpu = 1;
		// clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}
	action send_to_cpu_error(){
		meta.is_cpu = 2;
		//clone3(CloneType.I2E, 100, meta);
		mark_to_drop(standard_metadata);
	}

	action send_to_cpu_copy(){
		meta.is_cpu = 1;
		// clone3(CloneType.I2E, 100, meta);
	}

	action modify_general_info(bit<48> father, bit<9> egress_port, bit<32> terminate_stage, bit<6> sons_cnt, bit<6>neighbor_cnt){
		meta.father = father;
		meta.father_port = egress_port;
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
		default_action = modify_general_info(ROOT_FATHER, (bit<9>)0, (bit<32>)0, (bit<6>)0, (bit<6>)0);
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
		meta.is_cpu = 0;

		// Read cur_stage information into meta.self_stage
		cur_stage.read(meta.self_stage, (bit<32>)0);

		// Set following fields
		// meta.father: the father in the spanning tree
		// meta.father_port: the egress port to the father
		// meta.terminate_stage: the termination stage
		// meta.sons_cnt: the number of sons
		// meta.neighbor_cnt: the number of neighbors 
		get_general_info.apply();
		
		// Normal IPV4 dagta packet: ignore 
		if (hdr.ipv4.isValid()){
			drop();
		}
		// Ack message .. 
		else if ((hdr.ethernet.isValid()) && (hdr.sync_header.isValid()) && (hdr.sync_header.message_type >= ACK_MSG_NORMAL)) {
			standard_metadata.egress_spec = standard_metadata.ingress_port;
		}
		// 
		else if  ((hdr.ethernet.isValid()) && (hdr.sync_header.isValid())){
			// Based on input stage
			if (hdr.sync_header.stage > meta.self_stage){
				meta.self_stage = hdr.sync_header.stage;
				cur_stage.write(0, meta.self_stage);
			}

			// Read ingress_message_id on corresponding port
			write_index = (bit<32>)(standard_metadata.ingress_port);
			if (hdr.sync_header.message_type == NORMAL_PKT){
				write_index = write_index + MAX_PORT_CNT;
			}
			else{
				write_index = write_index;
			}
			stored_ingress_message_id.read(cur_message_id, write_index);
			
			// Check whether there are some lost messages 	
			if ((hdr.sync_header.message_id - cur_message_id) != 1){
				send_to_cpu_error();
			}
			else{
				// store_ingress_message_id += 1
				stored_ingress_message_id.write(write_index, (cur_message_id + 1)); 

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
					luby_passive.apply(hdr, meta, standard_metadata);
				}
				else if (hdr.sync_header.message_type == START_BROADCAST){
					start_broadcast.apply(hdr,meta, standard_metadata);
				}
				else{
					send_to_cpu_error();
				}
			}
			//clone3(CloneType.I2E, (bit<32>)(standard_metadata.ingress_port + 1), meta);  // send an ACK anyway
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

control LubyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata)
{
    action drop() {
		mark_to_drop(standard_metadata);
    }
    apply {
        bit<1> is_deleted_1;
        bit<1> is_deleted_2;
        // Read d_n_b correponsing idex value
        d_n_b.read(is_deleted_1, (bit<32>)standard_metadata.egress_port);
        deleted_neighbors.read(is_deleted_2, (bit<32>)standard_metadata.egress_port);

		if (meta.d_n_b == 1) {
			if (is_deleted_1 == 1) {
				drop();
			} 
		} else if (is_deleted_2 == 1) {
			drop();
		}
		if (is_deleted_1 == 0 && is_deleted_2 == 1) {
			d_n_b.write((bit<32>)standard_metadata.egress_port, 1);
		}
    }
}

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata)
{
        LubyEgress() luby_egress;
	
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
		bit<1> do_not_send = 0;

		bit<32> cur_value;

		if ((standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) && (meta.is_cpu >= 1)) {    // I2E
			send_to_control_plane();   // clone a copy to the control plane
		}
		if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE){
			hdr.CPU.setValid();
			hdr.CPU.is_cpu = (bit<8>)meta.is_cpu;
			hdr.CPU.message_type = meta.old_message_type;
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
			}
			if (hdr.msg.isValid()){
				// meta.old_value = hdr.msg.value;
			}

			
			if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){    // cloned packet. Two cases: ACK_MSG or retransmission msg
				if (hdr.ipv4.isValid()){
					// check_and_retransmit
					hdr.sync_header.setValid();
					hdr.ipv4.setInvalid();
					hdr.ethernet.ethertype = TYPE_EXP;

					cur_global_ts = standard_metadata.egress_global_timestamp;
					
					stored_last_timestamp.read(sync_last_timestamp, (bit<32>)standard_metadata.egress_port);
					stored_last_timestamp.read(normal_last_timestamp, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
					stored_existence.read(cur_existence, (bit<32>)standard_metadata.egress_port);
					if (cur_existence == 0){
						sync_last_timestamp = cur_global_ts;
					}
					stored_existence.read(cur_existence, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
					if (cur_existence == 0){
						normal_last_timestamp = cur_global_ts;
					}

					if ((cur_global_ts - sync_last_timestamp < EG_TIMEOUT_MCSEC) && (cur_global_ts - normal_last_timestamp < EG_TIMEOUT_MCSEC)){
						drop();
						do_not_send = 1;
					}
					else if ((cur_global_ts - sync_last_timestamp) > (cur_global_ts - normal_last_timestamp)){
						
						stored_egress_message_id.read(cur_message_id, (bit<32>)standard_metadata.egress_port);
						stored_message_type.read(cur_message_type, (bit<32>)standard_metadata.egress_port);
						stored_stage.read(current_stage, (bit<32>)standard_metadata.egress_port);

						hdr.sync_header.message_type = cur_message_type;
						hdr.sync_header.message_id = cur_message_id;
						hdr.sync_header.stage = current_stage;
						if (hdr.msg.isValid()){
							hdr.msg.setInvalid();
						}

						stored_last_timestamp.write((bit<32>)standard_metadata.egress_port, standard_metadata.egress_global_timestamp);
						// In tofino model, each register array should only appear in only one action block, i.e., perform only one read-write operation. It is possible to implement that, but is much more tricky.
					}
					else{
						stored_egress_message_id.read(cur_message_id, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
						stored_message_type.read(cur_message_type, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
						stored_stage.read(current_stage, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
						stored_value.read(cur_value, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));

						hdr.sync_header.message_type = cur_message_type;
						hdr.sync_header.message_id = cur_message_id;
						hdr.sync_header.stage = current_stage;
						if (!hdr.msg.isValid()){
							hdr.msg.setValid();
						}
						hdr.msg.value = cur_value;

						stored_last_timestamp.write((bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT), standard_metadata.egress_global_timestamp);
					}
				}
				else{
					// no need to modify sync_header.message_id
					if (hdr.sync_header.message_type == NORMAL_PKT){
						hdr.sync_header.message_type = ACK_MSG_NORMAL;
					}
					else{
						hdr.sync_header.message_type = ACK_MSG_SYNC;
					}
					hdr.msg.setInvalid();
				}
			}
			else if (hdr.sync_header.message_type >= ACK_MSG_NORMAL){
				if (hdr.sync_header.message_type == ACK_MSG_NORMAL){
					stored_egress_message_id.read(cur_message_id, (bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT));
					if (cur_message_id == hdr.sync_header.message_id){
						stored_existence.write((bit<32>)(standard_metadata.egress_port + MAX_PORT_CNT), 0);
					}
				}
				else{
					stored_egress_message_id.read(cur_message_id, (bit<32>)standard_metadata.egress_port);
					if (cur_message_id == hdr.sync_header.message_id){
						stored_existence.write((bit<32>)(standard_metadata.egress_port), 0);
					}
				}
				// for debugging purpose:
				hdr.sync_header.message_type = 255;
				drop();
			}
			else{
				hdr.sync_header.stage = meta.self_stage;
				if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_REPLICATION){
					if (standard_metadata.egress_rid == 1){
						meta.message_type = SYNC_BROADCAST;
					}
					else if (standard_metadata.egress_rid == 2){
						meta.message_type = NORMAL_PKT;
					}
					else if (standard_metadata.egress_rid == 3){
						meta.message_type = START_BROADCAST;
					}
					else if (standard_metadata.egress_rid == 4){
						meta.message_type = FIN_REPLY;
					}
					else if (standard_metadata.egress_rid == 5){
						meta.message_type = SYNC_REPLY;
					}
				}
				hdr.sync_header.message_type = meta.message_type;
				if (meta.message_type == NORMAL_PKT){
					if (hdr.msg.isValid()) {
						// Apply luby egress ..
						luby_egress.apply(hdr, meta, standard_metadata);
					} else {
						mark_to_drop(standard_metadata);
					}
				}
				else{
					if (hdr.msg.isValid()){
						hdr.msg.setInvalid();
					}
				}

					// update stored-message
			        if (meta.egress_is_drop == 0) {
                                    if (meta.message_type == NORMAL_PKT){
        					write_index = (bit<32>) (standard_metadata.egress_port + MAX_PORT_CNT);
        				}
        				else{
        					write_index = (bit<32>) standard_metadata.egress_port;
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
			            } else {
                                        // Need to drop the packet
                                        // drop()
			            }
			        }

			lookup_nhop.apply();
			if (do_not_send == 0){
				send_to_control_plane();
			}
			//drop();
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



