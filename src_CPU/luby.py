import argparse
import threading
import time
import netns
import pdb
import random
import os
import copy

TERM_STAGE = 10

# Node state in Luby's algorithm
INVALID = 0
VALID = 1
# Several state constants in Luby's algorithm
SEND_VALUE = 0
RECV_VALUE = 1

# Several stage constants in Luby's algorithm
SYNC_RAND_VALUE = 0
SYNC_NODE_INFO = 1
SYNC_EDGE_INFO = 2

# Packet type
NODE_SELECTED = 0
NODE_UNSELECTED = 1
EDGE_SELECTED = 2
EDGE_UNSELECTED = 3

arg_parser = argparse.ArgumentParser(description="")
arg_parser.add_argument("--name", type=str, required=True)
arg_parser.add_argument("--pid", type=int, required=True)
arg_parser.add_argument("--cnt", type=int, required=True)
arg_parser.add_argument("--benchmark_file", type=str, required=True)
args = arg_parser.parse_args()
host_name, host_mnet_pid, node_cnt = args.name, args.pid, args.cnt

with netns.NetNS(nspid=host_mnet_pid):
    from parser import NORMAL_PKT, send_packets
    from scapy.sendrecv import AsyncSniffer
    from scapy.sessions import IPSession
    from sync_framework import Synchronized_Framework, pkt_callback
    from scapy.arch.linux import get_if_list
    from utils import *
    from parser import *
    from datetime import datetime

    import scapy
    from scapy.all import *


    class Payload_Format(Packet):
        name = "Payload_Format"
        fields_desc = [
            BitField("req_type", 0, 8),
        ]


    def initializer(log_file, host_name, neighbor, root_name, node_cnt, **kwargs):
        """Initialize the parameters for Luby algorithm"""
        cb_params = {"stage": 0, "state": SEND_VALUE, "global_valid": VALID, "global_selected": False,
                     "node_valid": VALID, "node_selected": 0, "log_file": log_file,
                     "host_name": host_name, "total_neighbors": copy.deepcopy(neighbor), "deleted_neighbors": {},
                     "term_stage": kwargs["term_stage"], "rand_value": .0, "deleted_cnt": 0}
        return cb_params


    def get_algo_stage(stage):
        if stage % 3 == 1:
            return SYNC_RAND_VALUE
        elif stage % 3 == 2:
            return SYNC_NODE_INFO
        else:
            return SYNC_EDGE_INFO


    def log(cb_params, str):
        cb_params['log_file'].write(str)
        cb_params['log_file'].flush()


    def stage_initializer(stage, cb_params):
        # Move on to the next stage
        cb_params["stage"] += 1
        # Start SEND_VALUE state
        cb_params["state"] = SEND_VALUE
        cb_params["msg_desired"] = len(cb_params['total_neighbors']) - cb_params['deleted_cnt']
        # Should be deep copy!!!
        cb_params["d_n_b"] = copy.deepcopy(cb_params["deleted_neighbors"])
        if get_algo_stage(cb_params['stage']) == SYNC_RAND_VALUE:
            # Global states maintained from start
            cb_params["global_valid"] = INVALID if cb_params["node_valid"] == INVALID else cb_params["global_valid"]
            cb_params["global_selected"] = True if cb_params["node_selected"] else cb_params["global_selected"]
            # Local states to stages in Luby's algorithm
            cb_params["node_selected"] = True
            cb_params["node_valid"] = VALID
            # Generate rand number in the range [0, 1] for exchanging with neighbors
            cb_params['rand_value'] = random.uniform(0, 1)
            # Log information
            # log(cb_params, "{} start SYNC_RAND_VALUE at stage {}\n".format(cb_params['host_name'], cb_params['stage']))

        return cb_params


    def multicast(payload, stage, cb_params):
        for nbr_ip in cb_params["total_neighbors"]:
            if nbr_ip not in cb_params["d_n_b"]:
                # log(cb_params, "Sent to {}\n".format(nbr_ip))
                send_packets(nbr_ip, NORMAL_PKT, stage, payload)


    def callback(src_ip, stage, buf, cb_params, start_flag):
        # Define (encoder, decoder) function pair
        def encode(x: float) -> Raw:
            return Raw(load=int2byteh(int(x * 256)))

        def decode(x: bytes) -> float:
            return byte2inth(x) / 256.0

        # We can make it have multiple sync rounds
        # First  round : exchange value to determine whether I am selected
        # Second round : which node should be deleted
        # Third  round : which edge should be deleted

        # Skip invalid nodes
        if cb_params["global_valid"] == INVALID:
            log(cb_params, "I am selected {}\n".format(cb_params["global_selected"]))
            return True, True, cb_params

        if start_flag:
            # Check whether has finished ...
            finish = cb_params['msg_desired'] == 0
            # Move state to receive value
            cb_params['state'] = RECV_VALUE

            # Start sending its random value to its valid neighbors
            if get_algo_stage(cb_params['stage']) == SYNC_RAND_VALUE:
                multicast(encode(cb_params['rand_value']), stage, cb_params)

            elif get_algo_stage(cb_params['stage']) == SYNC_NODE_INFO:
                # Send the node selected information
                if cb_params['node_selected']:
                    cb_params['node_valid'] = INVALID
                    multicast(Payload_Format(req_type=NODE_SELECTED), stage, cb_params)
                else:
                    multicast(Payload_Format(req_type=NODE_UNSELECTED), stage, cb_params)

            elif get_algo_stage(cb_params['stage']) == SYNC_EDGE_INFO:
                # Send the edge deleted information
                if cb_params['node_valid'] == VALID:
                    multicast(Payload_Format(req_type=EDGE_UNSELECTED), stage, cb_params)
                else:
                    multicast(Payload_Format(req_type=EDGE_SELECTED), stage, cb_params)

                # Termination check
                if finish and cb_params['node_valid'] == INVALID:
                    log(cb_params, "I am selected {}\n".format(cb_params["node_selected"]))
                    return True, True, cb_params

            return finish, False, cb_params

        else:
            # Decrease the desired number of messages
            cb_params["msg_desired"] -= 1
            # Evaluate finish state
            finish = cb_params['msg_desired'] == 0 and cb_params['state'] == RECV_VALUE

            if get_algo_stage(stage) == SYNC_RAND_VALUE:
                # Decode the rand value
                rand_value = decode(buf)
                # Update selected states based on incoming rand_value
                cb_params["node_selected"] = False if rand_value <= cb_params["rand_value"] else cb_params["node_selected"]
                # log(cb_params,
                    # "{} received rand value {} from {}\n".format(cb_params["host_name"], cb_params["rand_value"],
                                                                #  src_ip))
            elif get_algo_stage(stage) == SYNC_NODE_INFO:
                buf = Payload_Format(raw(buf))
                # Mark this node as unselected
                if buf.req_type == NODE_SELECTED:
                    cb_params['node_valid'] = INVALID
                    # log(cb_params, "{} received node delete info from {}\n".format(cb_params["host_name"], src_ip))

            elif get_algo_stage(stage) == SYNC_EDGE_INFO:
                buf = Payload_Format(raw(buf))
                # Delete this edge
                if buf.req_type == EDGE_SELECTED:
                    cb_params['deleted_cnt'] += 1
                    cb_params['deleted_neighbors'][src_ip] = 1
                    # log(cb_params, "{} received edge delete info from {}\n".format(cb_params["host_name"], src_ip))

                # Termination check
                if finish and cb_params['node_valid'] == INVALID:
                    log(cb_params, "I am selected {}\n".format(cb_params["node_selected"]))
                    return True, True, cb_params

            return finish, False, cb_params


    framework = Synchronized_Framework(callback, initializer, stage_initializer, ({0}, 1), host_name, host_mnet_pid,
                                       "h1",
                                       node_cnt, term_stage=node_cnt - 1, benchmark_fout=args.benchmark_file)
    sniffer = AsyncSniffer(iface=get_if_list(), prn=lambda x: pkt_callback(x, framework.queue), filter="udp",
                           session=IPSession)

    sniffer.start()
    # first start sniffering, and then start loop (prevent missing packets)
    time.sleep(node_cnt / 4)

    framework.main_loop()

    sniffer.stop()
    print("Thread on host {} finished!".format(host_name))
