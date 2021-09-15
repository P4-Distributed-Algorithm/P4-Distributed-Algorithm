import argparse
import threading
import time
import netns
import pdb
import random
import os
import copy



TERM_STAGE = 10

arg_parser = argparse.ArgumentParser(description="")
arg_parser.add_argument("--name", type=str, required=True)
arg_parser.add_argument("--pid", type=int, required=True)
arg_parser.add_argument("--cnt", type=int, required=True)
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

    def initializer(log_file, host_name, neighbor, root_name, node_cnt, **kwargs):
        #import pdb
        #pdb.set_trace()
        cb_params = {}
        cb_params["self_value"] = random.randint(1, 10000)
        cb_params["log_file"] = log_file
        cb_params["host_name"] = host_name
        cb_params["neighbor"] = copy.deepcopy(neighbor)
        cb_params["neighbor_cnt"] = len(neighbor.keys())
        cb_params["root_name"] = root_name
        cb_params["node_cnt"] = node_cnt

        cb_params["nbr_size"] = len(cb_params["neighbor"].keys())
        cb_params["finished"] = [0 for i in range(cb_params["nbr_size"])]
        cb_params["xor"] = 0

        cb_params["term_stage"] = kwargs["term_stage"]

        cb_params["state"] = 0
        
        return cb_params

    def stage_initializer(stage, cb_params):  # there is no need for a stage initializer for this algorithm
        pass

    def callback(src_ip, stage, buf, cb_params, start_flag):
        if start_flag == True:
            #print(cb_params["host_name"], cb_params["neighbor"].keys())
            for host_ip in cb_params["neighbor"].keys():
                send_packets(host_ip, NORMAL_PKT, stage, Raw(load=int2byteh(cb_params["self_value"])))

            cb_params["state"] += 1

        else:
            index = cb_params["neighbor"][src_ip]
            if cb_params["finished"][index] != cb_params["xor"]:
                cb_params["log_file"].write("Error: Found dup response.\n")
                return (True, True, cb_params)
            cb_params["finished"][index] ^= 1
            cb_params["nbr_size"] -= 1
            value = byte2inth(buf)
            cb_params["self_value"] = max(cb_params["self_value"], value)
            cb_params["log_file"].write("Stage: {}, src_ip: {}, value: {}, time: {}\n".format(stage, src_ip, cb_params["self_value"], datetime.now().time()))
            
            if cb_params["nbr_size"] == 0:
                cb_params["state"] += 1
        
        if cb_params["state"] == 2:
            cb_params["xor"] ^= 1
            cb_params["nbr_size"] = cb_params["neighbor_cnt"]

            cb_params["state"] = 0   # initiailize for the next round
            if stage + 1 >= cb_params["term_stage"]:
                return (True, True, cb_params)
            else:
                return (True, False, cb_params)
        else:
            return (False, False, cb_params)
    

    framework = Synchronized_Framework(callback, initializer, None, None, host_name, host_mnet_pid, "h1", node_cnt, term_stage=node_cnt-1)
    sniffer = AsyncSniffer(iface=get_if_list(), prn=lambda x: pkt_callback(x, framework.queue), filter="udp", session=IPSession)
    
    sniffer.start()
    # first start sniffering, and then start loop (prevent missing packets)
    time.sleep(1)

    framework.main_loop()

    sniffer.stop()
    print("Thread on host {} finished!".format(host_name))

        