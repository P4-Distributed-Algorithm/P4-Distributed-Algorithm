import argparse
from socket import TCP_WINDOW_CLAMP
import threading
import time
import netns
import pdb
import random
import os
import copy
import math

INF = 1000000000

arg_parser = argparse.ArgumentParser(description="")
arg_parser.add_argument("--name", type=str, required=True)
arg_parser.add_argument("--pid", type=int, required=True)
arg_parser.add_argument("--cnt", type=int, required=True)
arg_parser.add_argument("--benchmark_file", type=str, required=True)
args = arg_parser.parse_args()
host_name, host_mnet_pid, node_cnt = args.name, args.pid, args.cnt

if args.benchmark_file != "None":
    benchmark_file = args.benchmark_file
else:
    benchmark_file = None

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
            BitField("flag", 0, 8),
        ]

    FLAG_STUCK = 0
    FLAG_RAISE = 1
    NOTIFY_COVER = 0
    NOTIFY_COVER_REPLY = 1
    RAISE_STUCK = 2

    def lpm(x):
        for i in range(31):
            if (1 << i) <= x and x < (1 << (i + 1)):
                return i

    def lookup_log(x):
        x = x >> 24
        x = float(x) / 128.
        x = math.log2(x)
        return int(x * (1 << 31))

    def lookup_exp(x):
        x >>= 23
        x = float(x) / 256.
        x = 2. ** x
        return int(x * (1 << 31))

    def multiplication(x, y, shift_x, shift_y):
        # result shift is always -8
        x_highest = lpm(x)
        # x_highest = 0
        y_highest = lpm(y)
        #pdb.set_trace()
        #pdb.set_trace()
        cur_shift = x_highest + y_highest + shift_x + shift_y
        x <<= (32 - x_highest - 1)
        # x = int(x * (1 << 31))
        y <<= (32 - y_highest - 1)
        x = lookup_log(x)
        y = lookup_log(y)

        result = x + y
        if result >= (1 << 31):
            cur_shift += 1
            result ^= 1 << 31
        result = lookup_exp(result)
        return result >> (23 - cur_shift)


    def initializer(log_file, host_name, neighbor, root_name, node_cnt, **kwargs):
        #import pdb
        #pdb.set_trace()
        cb_params = {}
        cb_params["log_file"] = log_file
        cb_params["host_name"] = host_name
        cb_params["neighbor"] = copy.deepcopy(neighbor)
        cb_params["neighbor_cnt"] = len(cb_params["neighbor"])
        cb_params["alpha"] = int(256 * kwargs["alpha"])
        cb_params["beta"] = int(256 * kwargs["beta"])
        
        fin = open("graph_weight.txt", "r")
        while True:
            try:
                name1, ip1, name2, ip2, self_weight, others_delta = fin.readline().split()
                if name1 == host_name:
                    cb_params["neighbor"][ip2] = int(cb_params["beta"] * float(others_delta))
                    cb_params["self_weight"] = int(self_weight)
            except:
                break
        fin.close()

        cb_params["basis_delta_sum"] = 0

        cb_params["sum_deal"] = 0
        cb_params["deleted_neighbor"] = []
        cb_params["deal"] = dict()
        cb_params["delta"] = dict()

        for neighbor in cb_params["neighbor"].keys():
            cb_params["deal"][neighbor] = min(cb_params["neighbor"][neighbor], int(cb_params["beta"] * cb_params["self_weight"] / len(cb_params["neighbor"])))
        
            cb_params["delta"][neighbor] = cb_params["deal"][neighbor]
            cb_params["sum_deal"] += cb_params["deal"][neighbor]
        
        cb_params["sum_delta"] = cb_params["sum_deal"]

        cb_params["join"] = False
        cb_params["has_terminate"] = False
        
        print(cb_params)
        #time.sleep(1000)
        
        return cb_params
    
    def __wrap_send(dst_ip, pkt_type, stage, buf, channel_id=0):
        #print(host_name, dst_ip)
        #buf.show()
        send_packets(dst_ip, pkt_type, stage, buf, channel_id)

    def stage_initializer(stage, cb_params):  # there is no need for a stage initializer for this algorithm
        if stage % 2 == 0:
            for deleted_neighbor in cb_params["deleted_neighbor"]:
                cb_params["neighbor"].pop(deleted_neighbor)
            cb_params["deleted_neighbor"] = []

            cb_params["reply_remain"] = len(cb_params["neighbor"]) + 1
            if multiplication(cb_params["sum_deal"], cb_params["alpha"], -8, -8) <= multiplication(cb_params["beta"], 256 * cb_params["self_weight"], -8, -8):
                cb_params["self_stuck_state"] = FLAG_RAISE
            else:
                cb_params["self_stuck_state"] = FLAG_STUCK

            cb_params["sum_delta"] = cb_params["sum_deal"] = 0
        
        return cb_params
        

    def callback(src_ip, stage, buf, cb_params, start_flag):
        if start_flag == True:
            print(stage, ":", host_name, cb_params)
            if stage % 2 == 1:
                if cb_params["sum_delta"] + cb_params["basis_delta_sum"] >= multiplication(256 - cb_params["beta"], cb_params["self_weight"], -8, 0):
                    cb_params["join"] = True
                    for neighbor in cb_params["neighbor"].keys():
                        __wrap_send(neighbor, NORMAL_PKT, stage, buf=Payload_Format(req_type=NOTIFY_COVER))

                    cb_params["reply_remain"] = len(cb_params["neighbor"])
                    return False, False, cb_params
                else:
                    return True, False, cb_params
            
            else:
                cb_params["reply_remain"] -= 1
                for neighbor in cb_params["neighbor"].keys():
                    __wrap_send(neighbor, NORMAL_PKT, stage, buf=Payload_Format(req_type=RAISE_STUCK, flag=cb_params["self_stuck_state"]))

                if cb_params["reply_remain"] == 0:
                    return True, False, cb_params
                else:
                    return False, False, cb_params
        
        else:
            buf = Payload_Format(raw(buf))
            if buf.req_type == NOTIFY_COVER:
                cb_params["deleted_neighbor"].append(src_ip)
                cb_params["neighbor_cnt"] -= 1
                cb_params["sum_deal"] -= cb_params["deal"][src_ip]
                cb_params["sum_delta"] -= cb_params["delta"][src_ip]
                cb_params["basis_delta_sum"] += cb_params["delta"][src_ip]
                terminate = False
                if cb_params["neighbor_cnt"] == 0 and cb_params["has_terminate"] == False:
                    terminate = True
                    cb_params["has_terminate"] = True

                __wrap_send(src_ip, NORMAL_PKT, stage, buf=Payload_Format(req_type=NOTIFY_COVER_REPLY), channel_id=1)
                return False, terminate, cb_params

            elif buf.req_type == NOTIFY_COVER_REPLY:
                cb_params["reply_remain"] -= 1
                if cb_params["reply_remain"] == 0:
                    terminate = False
                    if cb_params["join"] == True and cb_params["has_terminate"] == False:
                        cb_params["has_terminate"] = True
                        terminate = True
                    return True, terminate, cb_params
                else:
                    return False, False, cb_params
            
            else:
                cb_params["reply_remain"] -= 1
                if buf.flag == FLAG_RAISE and cb_params["self_stuck_state"] == FLAG_RAISE:
                    cb_params["deal"][src_ip] = multiplication(cb_params["deal"][src_ip], cb_params["alpha"],-8, -8)
                cb_params["sum_deal"] += cb_params["deal"][src_ip]
                cb_params["delta"][src_ip] += cb_params["deal"][src_ip]
                cb_params["sum_delta"] += cb_params["delta"][src_ip]
                return cb_params["reply_remain"] == 0, False, cb_params

    
    def print_result(cb_params):
        fout = open("tree_result.txt", "a+")

        if cb_params["join"] == False:
            fout.write("{} 0\n".format(host_name))
        else:
            fout.write("{} 1\n".format(host_name))

        fout.close()


    framework = Synchronized_Framework(callback, initializer, stage_initializer, ([0], 2), host_name, host_mnet_pid, "h1", node_cnt, term_stage=node_cnt-1, alpha=1.5, beta=0.39 / (2 + 0.39),benchmark_fout=benchmark_file)
    sniffer = AsyncSniffer(iface=get_if_list(), prn=lambda x: pkt_callback(x, framework.queue), filter="udp", session=IPSession)
    
    sniffer.start()
    # first start sniffering, and then start loop (prevent missing packets)
    time.sleep(5)

    cb_params = framework.main_loop()

    print_result(cb_params)

    sniffer.stop()
    print("Thread on host {} finished!".format(host_name))

        