import nnpy
import time
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
import sys
import threading
import argparse
import pdb
import os



class cpu_header(Packet):
    name = "cpu_header"
    fields_desc = [\
        BitField("msg_type", 0, 8),\
        BitField("stage", 0, 32),\
        BitField("value", 0, 32),\
        BitField("message_id", 0, 8),\
        BitField("dbg_info", 0, 32),\
        BitField("is_cpu", 0, 8)
    ]

class sync_header(Packet):
    name = "sync_header"
    fields_desc = [\
        BitField("msg_type", 0, 8),\
        BitField("stage", 0, 32),\
        BitField("message_id", 0, 8)
    ]

class payload_t(Packet):
    name = "payload_t"
    fields_desc = [\
        BitField("value", 0, 32)
    ]


class packetReceicer(threading.Thread):

    # initialization code
    def __init__(self, sw_name, topo_path):
        threading.Thread.__init__(self)

        self.topo = Topology(db=topo_path)  #set the topology

        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.flow = {}
        self.flag = True
        self.init()
        

    def init(self):
        self.add_mirror()
        self.counter = 0
        self.log_name = "../switch_log/" + self.sw_name + ".log"

        tmp_fout = open(self.log_name, "w")
        tmp_fout.write("Launching\n");
        tmp_fout.close()

        self.logs_info=open("../switch_log/" + self.sw_name + "_info.log", "w")
        self.logs_info.write("SWITCH[" + self.sw_name + "]\n")
        self.logs_info.close()

        log_file = open(self.log_name, "w")
        log_file.write("Monitering switch[" + self.sw_name + "]\n")
        log_file.close()

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port) # correspond to the 100 in p4 code
            #is there any probability to increase the mirro port to add cpu port?

    #######################################
    # runtime code



    def recv_msg_cpu(self, pkt):
        self.counter += 1
        
        pkt.show()
        self.gen_per_packet_log(pkt)

    def gen_per_packet_log(self, pkt):
        #pdb.set_trace()
        pkt_ether = pkt["Ethernet"]
        pkt_cpu = pkt["cpu_header"]
        pkt_sync = pkt["sync_header"]
        pkt_payload = pkt_sync.payload
        #pdb.set_trace()

        if str(pkt_payload) != "":
            new_value = payload_t(str(pkt_payload)).value
        else:
            new_value = 0


        log_file = open(self.log_name, "a+")
        
        log_file.write("{} -> {}\n".format(pkt_ether.src, pkt_ether.dst))
        log_file.write("Incoming packet: old_type: {}, old_stage: {}, old_value: {}, old_message_id: {}\n".format(
            pkt_cpu.msg_type, pkt_cpu.stage, pkt_cpu.value, pkt_cpu.message_id
        ))
        log_file.write("Output packet: type: {}, stage: {}, value: {}, message_id: {}\n".format(pkt_sync.msg_type, pkt_sync.stage, new_value, pkt_sync.message_id))

        log_file.write("Dbg:info: {}, is_cpu: {}\n".format(pkt_cpu.dbg_info, pkt_cpu.is_cpu))
        
        log_file.close()
    

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        #the cpu has two ports   could use two thread to sniff
        print(cpu_port_intf)

        bind_layers(Ether, cpu_header, type=0x88b5)
        bind_layers(cpu_header, sync_header)

        print(sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu))
    
    def run(self):
        self.run_cpu_port_loop()


if __name__ == "__main__":
    # usage : python test.py [sw_name]
    # hint: the sw_name must open the cpu_port function in p4app.json
    # "cpu_port" : true

    parser = argparse.ArgumentParser()
    
    parser.add_argument("-s", "--switch", help="this switch's name")
    args = parser.parse_args()

    topo_path = "../p4src_simple/topology.db"
    
    controllers = []

    if args.switch == None:
        num_switch = 7

        for i in range(num_switch):
            controllers.append(packetReceicer("s" + str(i + 1), topo_path))

        for i in range(num_switch):
            controllers[i].start()
        
        for i in range(num_switch):
            controllers[i].join()

    else:
        sw_name = args.switch
        controllers.append(packetReceicer(sw_name, topo_path).run_cpu_port_loop())
