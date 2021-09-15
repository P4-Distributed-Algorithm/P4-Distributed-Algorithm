# Queue is thread-safe in python
from os import sync
import queue
from parser import *
from scapy.all import *
from parser import *
from utils import *
from datetime import datetime
import copy
import pdb


class Payload_Format(Packet):
    name = "Payload_Format"
    fields_desc = [
        BitField("req_type", 0, 8),
        BitField("id", 0, 32),
        BitField("flag", 0, 8),
        BitField("min_val", 0, 32)
    ]

MAX_QUEUE_SIZE = 10000


class Synchronized_Framework(object):
    def __init__(self, callback, initializer, stage_initializer, sync_stage_specific, host_name, host_mnet_pid, root_name, node_cnt, **kwargs):
        self.callback = callback
        self.stage_initializer = stage_initializer
        if sync_stage_specific != None:
            self.sync_stage_set, self.sync_stage_mod = sync_stage_specific
        else:
            self.sync_stage_set = set()
            self.sync_stage_mod = 1
        self.root_name = root_name
        self.node_cnt = node_cnt

        self.is_terminate = 0
        self.sons_terminate = 0
        self.terminate_has_sent = 0
        self.brk = False
        self.log_file = open("log/{}_log.txt".format(host_name), "w")

        # initializing neighborhood
        fin = open("topo/topology.txt", "r")
        self.neighbor = dict()

        self.host_name = host_name
        self.host_mnet_pid = host_mnet_pid

        i = 0
        while True:
            try:
                h1_name, h1_ip, _, _, h2_name, h2_ip, _, _ = fin.readline().split()
                if h1_name == host_name:
                    self.neighbor[h2_ip] = i
                    i += 1
                if h2_name == host_name:
                    self.neighbor[h1_ip] = i
                    i += 1
            except:
                break
        fin.close()
        parser_init()

        #if self.host_name != "h1":
        #    time.sleep(10000)
        self.cb_params = initializer(self.log_file, self.host_name, self.neighbor, self.root_name, self.node_cnt, **kwargs)
        self.nbr_size = len(self.neighbor)

        self.queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.stage = 0

        self.sons = []
        self.exist_sons = {}
        self.sons_cnt = 0
        self.finished = 0
        self.self_finished = 0
        self.replied = 0

        self.bfs_visited = False
        if host_name == root_name:
            self.father = -1


        if "benchmark_fout" in kwargs and kwargs["benchmark_fout"] != None:
            self.benchmark_fout = open(kwargs["benchmark_fout"], "a+")
        else:
            self.benchmark_fout = None


    def broadcast(self, stage, message, message_type):
        for host_ip in self.neighbor.keys():
            #import pdb
            #pdb.set_trace()
            send_packets(host_ip, message_type, stage, message)

    def broadcast_sons(self, stage, message, start_broadcast=False):
        if stage % self.sync_stage_mod in self.sync_stage_set and start_broadcast == False:
            if self.is_terminate == 0 or self.is_terminate == stage:
                self.cb_params = self.stage_initializer(self.stage, self.cb_params)
            for host_ip in self.sons:
                send_packets(host_ip, SYNC_BROADCAST, stage, message)
        else:
            for host_ip in self.sons:
                send_packets(host_ip, START_BROADCAST, stage, message)
            if self.is_terminate == 0 or self.is_terminate == stage:
                finished, terminate, self.cb_params = self.callback(None, self.stage, None, self.cb_params, start_flag=True)
                if terminate == True:
                    print("Node %s terminated" % self.host_name)
                    if self.benchmark_fout != None:
                        self.benchmark_fout.write("End: {} {} {} {}\n".format(self.host_name, time.time(), self.stage, self.start_packet_cnt))
                        self.benchmark_fout.flush()
                
            else:
                finished = True
                terminate = True

            if terminate == True:
                self.is_terminate = stage

            if finished == True:
                print("On node {}, stage {} finished.".format(self.host_name, self.stage))
                self.update_and_reply(0)


    def update_and_reply(self, fin_type):
        if fin_type == 0:
            self.finished += 1 if self.self_finished == 0 else 0
            self.self_finished = 1
        else:
            self.finished += 1

        if self.finished == self.sons_cnt + 1:
            self.self_finished = 0
            self.finished = 0
            self.replied = 0
            if self.host_name != self.root_name:
                if self.is_terminate != 0 and self.sons_terminate == self.sons_cnt and self.terminate_has_sent == False:
                    send_packets(self.father, FIN_REPLY, 0, None)
                    self.terminate_has_sent = True
                else: 
                    send_packets(self.father, FIN_REPLY, self.stage, None)
            else:
                self.stage += 1
                print(self.host_name, self.sons_terminate)
                if self.is_terminate != 0 and self.sons_terminate == self.sons_cnt:
                    for host_ip in self.sons:
                        send_packets(host_ip, TERMINATE_BROADCAST, self.stage, None)
                        self.brk = True
                else:
                    self.broadcast_sons(self.stage, None)

    def sync_reply(self):
        self.replied += 1
        if self.replied >= self.sons_cnt:
            if self.father != -1:
                send_packets(self.father, SYNC_REPLY, self.stage, None)
            else:
                self.broadcast_sons(self.stage, None, True)

    def main_loop(self):
        #import os
        #os.system("route")
        
        self.start_packet_cnt = 0
        if self.host_name == self.root_name:
            self.collected_reply = 0
            self.broadcast(self.stage, None, BFS_BROADCAST)
            self.bfs_visited = True

        while True:
            resend()

            if not self.queue.empty():
                self.start_packet_cnt += 1
                packet = self.queue.get()
                src_ip, message_type, stage, buf = packet
                self.stage = max(self.stage, stage)
                # if stage != self.stage:
                #     print(src_ip, message_type, stage, self.stage)
                #     print("Error: on host {}, stage mismatched with current stage.".format(self.host_name))
                #     break
                    
                if message_type == NORMAL_PKT:
                    finished, terminated, self.cb_params = self.callback(src_ip, stage, buf, self.cb_params, start_flag=False)
                    
                    if terminated == True:
                        # self.benchmark_fout.write("End: {} {} {} {}\n".format(self.host_name, time.time(), self.stage, self.start_packet_cnt))
                        self.benchmark_fout.write("End: {} {} {} {}\n".format(self.host_name, time.time(), self.stage - 1, self.start_packet_cnt * 2))
                        self.fin_time = time.time()
                        self.fin_stage = self.stage
                        self.is_terminate = self.stage
                        print("Node %s terminated" % self.host_name)
                    
                    if finished == True:
                        self.log_file.write("On node {}, stage {} finished, time: {}.\n".format(self.host_name, self.stage, datetime.now().time()))

                        print("On node {}, stage {} finished.".format(self.host_name, self.stage))
                        self.update_and_reply(0)
                    
                    
                 
                elif message_type == BFS_BROADCAST:
                    if self.bfs_visited == False:
                        self.bfs_visited = True
                        self.father = src_ip
                        self.broadcast(self.stage, None, BFS_BROADCAST)
                        send_packets(src_ip, BFS_REPLY, self.stage, Raw(load=int2byteh(1)))

                elif message_type == BFS_REPLY:
                    if src_ip not in self.exist_sons:
                        self.sons_cnt += 1
                        self.sons.append(src_ip)
                        
                    self.exist_sons[src_ip] = byte2inth(buf)
                    
                    sum_reply = 0
                    for son_ip in self.sons:
                        sum_reply += self.exist_sons[son_ip]

                    if self.host_name == self.root_name:
                        if sum_reply == self.node_cnt - 1:
                            self.stage += 1
                            if self.benchmark_fout != None:
                                self.start_packet_cnt = 0
                                self.benchmark_fout.write("Start: {}\n".format(time.time()))
                                self.benchmark_fout.flush()
                            self.broadcast_sons(self.stage, None)

                    else:
                        send_packets(self.father, BFS_REPLY, self.stage, Raw(load=int2byteh(sum_reply + 1)))

                elif message_type == SYNC_BROADCAST:
                    self.broadcast_sons(self.stage, None, False)

                    if self.sons_cnt == 0:
                        self.sync_reply()
                
                elif message_type == FIN_REPLY:
                    if stage == 0:
                        self.sons_terminate += 1
                    self.update_and_reply(1)
                
                elif message_type == SYNC_REPLY:
                    
                    self.sync_reply()

                elif message_type == START_BROADCAST:
                    
                    self.broadcast_sons(self.stage, None, True)
                
                elif message_type == TERMINATE_BROADCAST:
                    for host_ip in self.sons:
                        send_packets(host_ip, TERMINATE_BROADCAST, self.stage, None)
                    self.brk = True
                
                if self.brk == True:
                    break
            else:
                time.sleep(0.01)
        
        self.benchmark_fout.write("End: {} {} {} {}\n".format(self.host_name, time.time(), self.stage - 1, self.start_packet_cnt * 2))
        self.benchmark_fout.flush()

        if self.benchmark_fout != None:
            self.benchmark_fout.close()

        return self.cb_params                

            

def pkt_callback(pkt, q):
    #import pdb
    #pdb.set_trace()
    #pkt.show()
    res = recv_packets(pkt)
    if res != None:
        q.put(res, block=True, timeout=1)

