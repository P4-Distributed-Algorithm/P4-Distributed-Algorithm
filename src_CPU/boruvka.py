import argparse
import threading
import time
import netns
import pdb
import random
import os
import copy
from enum import Enum

INF = 1000000000

CAST_BELONGS = 0
REMOVE_EDGES = 1
CAST_MINIMUM = 2
CONNECT = 3

MIN_BROADCAST = 0
MIN_REPLY = 1
FIN_BROADCAST = 2
PULL_REQ = 3
PULL_REPLY = 4
PUSH_REQ = 5
ADDEDGE_REQ = 6
ADDEDGE_REPLY = 7
TERMINATE = 8


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

    class Payload_Format(Packet):
        name = "Payload_Format"
        fields_desc = [
            BitField("req_type", 0, 8),
            BitField("id", 0, 32),
            BitField("flag", 0, 8),
            BitField("min_val", 0, 32)
        ]

    def initializer(log_file, host_name, neighbor, root_name, node_cnt, **kwargs):
        cb_params = {}
        cb_params["stage"] = 0
        cb_params["log_file"] = log_file
        cb_params["host_name"] = host_name
        cb_params["neighbor"] = copy.deepcopy(neighbor)
        cb_params["neighbor_cnt"] = len(neighbor.keys())
        cb_params["root_name"] = root_name
        cb_params["node_cnt"] = node_cnt
        cb_params["self_id"] = int(host_name[1: ])

        cb_params["component_size"] = 1
        
        fin = open("graph_weight.txt", "r")
        while True:
            try:
                name1, ip1, name2, ip2, weight = fin.readline().split()
                if name1 != host_name:
                    name1 = name2
                    ip2 = ip1
                if name1 == host_name:
                    cb_params["neighbor"][ip2] = int(weight)
            except:
                break
        fin.close()
        
        cb_params["sub_stage"] = CAST_MINIMUM ^ 1
        cb_params["sons"] = set()
        cb_params["sons_cnt"] = 0
        cb_params["father"] = -1

        cb_params["new_sons"] = []
        cb_params["deleted_sons"] = []
        cb_params["deleted_neighbors"] = set()
        cb_params["new_father"] = -1
        
        return cb_params

    def stage_initializer(_, cb_params):
        cb_params["stage"] += 1
        cb_params["sub_stage"] = (cb_params["sub_stage"] + 1) % 4

        if cb_params["sub_stage"] == CAST_BELONGS:
            for son in cb_params["new_sons"]:
                cb_params["sons"].add(son)
                cb_params["sons_cnt"] += 1
            for son in cb_params["deleted_sons"]:
                if son not in cb_params["sons"]:
                    print("Error: failed to delete a son at node {}".format(cb_params["host_name"]))
                cb_params["sons"].remove(son)
                cb_params["sons_cnt"] -= 1
            

            cb_params["new_sons"] = []
            cb_params["deleted_sons"] = []
            if cb_params["new_father"] != -1:
                cb_params["father"] = cb_params["new_father"]
            cb_params["new_father"] = -1
            cb_params["request_id"] = -1
            cb_params["query_remain"] = 0
            for neighbor in cb_params["neighbor"].keys():
                if neighbor not in cb_params["sons"] and neighbor != cb_params["father"]:
                    cb_params["query_remain"] += 1
            print("---{}: query_remain: {}---".format(host_name, cb_params["query_remain"]))

            cb_params["log_file"].write("{} -> {}\n".format(cb_params["host_name"], cb_params["father"]))
            cb_params["log_file"].flush()

        elif cb_params["sub_stage"] == CAST_MINIMUM:
            for neighbor in cb_params["deleted_neighbors"]:
                cb_params["neighbor"].pop(neighbor)
            cb_params["deleted_neighbors"] = set()

            min_val = INF
            min_ip = ""
            for son in cb_params["neighbor"].keys():
                if son not in cb_params["sons"] and son != cb_params["father"]:
                    weight = cb_params["neighbor"][son]
                    if weight < min_val:
                        min_val = weight
                        min_ip = son
            print("------------ min_ip for host {} is {}".format(host_name, min_ip))
            cb_params["min_val"] = min_val
            cb_params["min_ip"] = min_ip
            
        return cb_params


    def __wrap_send(dst_ip, pkt_type, stage, buf, channel_id=0):
        #print(host_name, dst_ip)
        #buf.show()
        send_packets(dst_ip, pkt_type, stage, buf, channel_id)


    def terminate_broadcast(cb_params):
        cb_params["log_file"].write("{} -> {}\n".format(cb_params["host_name"], cb_params["father"]))
        for son in cb_params["sons"]:
            __wrap_send(son, NORMAL_PKT, cb_params["stage"], buf=Payload_Format(req_type=TERMINATE))
            
    
    def judge_and_restruct(cb_params):
        assert(cb_params["father"] == -1)
        finished = False

        if cb_params["request_id"] == -1 or cb_params["request_id"] < cb_params["self_id"]: # connect 
            cb_params["new_father"] = cb_params["min_ip"]

            if cb_params["min_ip"] not in cb_params["sons"]:
                __wrap_send(cb_params["min_ip"], NORMAL_PKT, cb_params["stage"], buf=Payload_Format(req_type=ADDEDGE_REQ, id=cb_params["self_id"], flag=1))

            else:
                cb_params["deleted_sons"].append(cb_params["min_ip"])
                __wrap_send(cb_params["min_ip"], NORMAL_PKT, cb_params["stage"], buf=Payload_Format(req_type=PUSH_REQ, id=cb_params["self_id"], flag=1))
                finished = True

            for son in cb_params["sons"]:
                if son != cb_params["min_ip"]:
                    __wrap_send(son, NORMAL_PKT, cb_params["stage"], buf=Payload_Format(req_type=FIN_BROADCAST))
        
        else:
            finished = True
            for son in cb_params["sons"]:
                __wrap_send(son, NORMAL_PKT, cb_params["stage"], buf=Payload_Format(req_type=FIN_BROADCAST))
        

        return cb_params, finished

    

    def callback(src_ip, stage, buf, cb_params, start_flag):
        finished = False
        terminate = False
        self_id = cb_params["self_id"]

        if start_flag == True:
            if cb_params["sub_stage"] == CAST_BELONGS:
                if cb_params["father"] == -1:
                    cb_params["belong_id"] = self_id
                    for son in cb_params["sons"]:
                        __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=FIN_BROADCAST, flag=1, id=self_id))
                    finished = True
            elif cb_params["sub_stage"] == REMOVE_EDGES:
                finished = True
                for neighbor in cb_params["neighbor"]:
                    if neighbor not in cb_params["sons"] and neighbor != cb_params["father"]:
                        finished = False
                        __wrap_send(neighbor, NORMAL_PKT, stage, buf=Payload_Format(req_type=ADDEDGE_REQ, flag=2, id=cb_params["belong_id"]))

            # guarantee that nodes do nothing if they are not the root of a subtree
            elif cb_params["sub_stage"] == CAST_MINIMUM:
                if cb_params["father"] == -1:
                    for son in cb_params["sons"]:
                        __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=MIN_BROADCAST))
                    cb_params["rem_cnt"] = cb_params["sons_cnt"]
                    if cb_params["rem_cnt"] == 0:
                        __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=ADDEDGE_REQ, flag=0, id=self_id))

            
            else:
                if cb_params["father"] == -1:
                    min_ip = cb_params["min_ip"]
                    if min_ip not in cb_params["sons"]:
                        cb_params, finished = judge_and_restruct(cb_params)
                    else:
                        __wrap_send(min_ip, NORMAL_PKT, stage, buf=Payload_Format(req_type=PULL_REQ))

        else:
            buf = Payload_Format(raw(buf))
            
            if buf.req_type == ADDEDGE_REQ:
                _flag = 0
                if buf.flag == 1:
                    cb_params["new_sons"].append(src_ip)
                elif buf.flag == 2:
                    _flag = 1
                    if cb_params["belong_id"] == buf.id:
                        cb_params["deleted_neighbors"].add(src_ip)
                        _flag = 2
                else:
                    if cb_params["min_ip"] == src_ip:
                        cb_params["request_id"] = buf.id
                __wrap_send(src_ip, NORMAL_PKT, stage, buf=Payload_Format(req_type=ADDEDGE_REPLY, flag=_flag), channel_id=1)

            elif buf.req_type == ADDEDGE_REPLY:
                if buf.flag >= 1:
                    cb_params["query_remain"] -= 1
                    if cb_params["query_remain"] == 0:
                        finished = True
                else:
                    finished = True
                if buf.flag == 2:
                    cb_params["deleted_neighbors"].add(src_ip)

            elif buf.req_type == TERMINATE:
                terminate_broadcast(cb_params)
                finished = True
                terminate = True
            
            elif buf.req_type == FIN_BROADCAST:
                if buf.flag == 1:
                    cb_params["belong_id"] = buf.id
                for son in cb_params["sons"]:
                    __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=FIN_BROADCAST, id=buf.id, flag=buf.flag))
                finished = True
            
            elif buf.req_type == MIN_BROADCAST:
                if cb_params["sub_stage"] != CAST_MINIMUM:
                    print("Error: Incorrect Sub_Stage")

                for son in cb_params["sons"]:
                    __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=MIN_BROADCAST))
                cb_params["rem_cnt"] = cb_params["sons_cnt"]
                if cb_params["rem_cnt"] == 0:
                    __wrap_send(cb_params["father"], NORMAL_PKT, stage, buf=Payload_Format(req_type=MIN_REPLY, min_val=cb_params["min_val"]))
            
            elif buf.req_type == MIN_REPLY:
                cb_params["rem_cnt"] -= 1
                if cb_params["min_val"] > buf.min_val:
                    cb_params["min_val"] = buf.min_val
                    cb_params["min_ip"] = src_ip

                if cb_params["rem_cnt"] == 0:
                    if cb_params["father"] != -1:
                        __wrap_send(cb_params["father"], NORMAL_PKT, stage, buf=Payload_Format(req_type=MIN_REPLY, min_val=cb_params["min_val"]))
                    else:
                        if cb_params["min_val"] == INF:
                            terminate = True
                            finished = True
                            terminate_broadcast(cb_params)

                        else:
                            for son in cb_params["sons"]:
                                if son != cb_params["min_ip"]:
                                    __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=FIN_BROADCAST))
                            if cb_params["min_ip"] not in cb_params["sons"]:
                                __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=ADDEDGE_REQ, id=self_id, flag=0))
                            else:
                                __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=PUSH_REQ, id=self_id, flag=0))
                                finished = True

            
            elif buf.req_type == PULL_REQ:
                if cb_params["min_ip"] not in cb_params["sons"]:   # leaf edge
                    __wrap_send(cb_params["father"], NORMAL_PKT, stage, buf=Payload_Format(req_type=PULL_REPLY, id=cb_params["request_id"]))                   
                else:
                    __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=PULL_REQ))

            elif buf.req_type == PULL_REPLY:
                cb_params["request_id"] = buf.id
                if cb_params["father"] != -1:
                    __wrap_send(cb_params["father"], NORMAL_PKT, stage, buf=Payload_Format(req_type=PULL_REPLY, id=cb_params["request_id"]))
                else:
                    cb_params, finished = judge_and_restruct(cb_params)     

            else:
                if buf.flag == 1:
                    if cb_params["min_ip"] in cb_params["sons"]:
                        cb_params["deleted_sons"].append(cb_params["min_ip"])
                    cb_params["new_father"] = cb_params["min_ip"]
                    cb_params["new_sons"].append(cb_params["father"])

                for son in cb_params["sons"]:
                    if son != cb_params["min_ip"]:
                        __wrap_send(son, NORMAL_PKT, stage, buf=Payload_Format(req_type=FIN_BROADCAST))
                    
                if cb_params["min_ip"] not in cb_params["sons"]:
                    __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=ADDEDGE_REQ, id=buf.id, flag=buf.flag))
                    
                else:
                    __wrap_send(cb_params["min_ip"], NORMAL_PKT, stage, buf=Payload_Format(req_type=PUSH_REQ, id=buf.id, flag=buf.flag))
                    finished = True

        return finished, terminate, cb_params







    def print_result(cb_params):
        fout = open("tree_result.txt", "a+")

        fin = open("graph_weight.txt", "r")
        while True:
            try:
                name1, ip1, name2, ip2, weight = fin.readline().split()
                if ip1 == cb_params["father"]:
                    fout.write("{} -> {}\n".format(name2, name1))
                
                elif ip2 == cb_params["father"]:
                    fout.write("{} -> {}\n".format(name1, name2))
            except:
                break
        
        fin.close()
        fout.close()
        


    framework = Synchronized_Framework(callback, initializer, stage_initializer, ([0, 1, 2, 3], 4), host_name, host_mnet_pid, "h1", node_cnt, term_stage=node_cnt-1)
    sniffer = AsyncSniffer(iface=get_if_list(), prn=lambda x: pkt_callback(x, framework.queue), filter="udp", session=IPSession)
    
    sniffer.start()
    # first start sniffering, and then start loop (prevent missing packets)
    time.sleep(1)

    cb_params = framework.main_loop()

    print_result(cb_params)

    sniffer.stop()
    print("Thread on host {} finished!".format(host_name))

        