from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
import socket, struct, pickle, os
from scapy.all import Ether, sniff, Packet, BitField
import time
import sys
import argparse
import pdb
import random
import threading
import netns

parser = argparse.ArgumentParser(description="")
parser.add_argument("-n", type=str, required=True)
parser.add_argument("-p", type=int, required=True)
args = parser.parse_args()
host_name, host_mnet_pid = args.n, args.p


with netns.NetNS(nspid=host_mnet_pid):
    from scapy.all import *

    class payload_t(Packet):
        name = "payload_t"
        fields_desc = [\
            BitField("idx", 0, 32),\
        ]


    # os.system("bash config.sh")

    class RoutingController(object):

        def __init__(self, _target_host):
            self.topo = Topology(db="../p4src_simple/topology.db")  #set the topology
            self.controllers = {}                   #the switches
            self.custom_calcs={}
            self.register_num={}
            self.registers={}
            self.num_of_switches = len(self.topo.get_p4switches())
            self.target_host = _target_host

            self.init_hosts()

            # self.get_nsid()
            

        # def get_nsid(self):
        #     self.nsid = dict()
        #     fin = open("host.config", "r")
        #     for i in range(len(self.hosts)):
        #         host_name = fin.readline().split()[0]
        #         host_nsid = int(fin.readline().split()[0])
        #         self.nsid[host_name] = host_nsid
            

        def init_hosts(self):
            host = self.target_host
            
            directed_switch = self.topo.get_switches_connected_to(host)[0]
            #pdb.set_trace()

            self.src_mac = self.topo.node_to_node_mac(host, directed_switch)
            self.dst_mac = self.topo.node_to_node_mac(directed_switch, host)
            self.src_ip = self.topo.node_to_node_interface_ip(host, directed_switch).split("/")[0]
            self.dst_ip = self.topo.node_to_node_interface_ip(directed_switch, host).split("/")[0]
            if self.dst_ip == "None":
                self.dst_ip = copy.deepcopy(self.src_ip)
            self.intf = self.topo.get_host_first_interface(host)
            
        def main(self):
            idx = 0
            while True:
                fin = open("indicator.txt", "r")
                command = fin.readline()[0]
                fin.close()
                if command == "e":
                    break
                
                idx += 1
                pkt = Ether(type=0x0800, src=self.src_mac, dst=self.dst_mac) / IP(dst=self.dst_ip, src=self.src_ip) / payload_t(idx=idx)
                sendp(pkt, iface=self.intf)

                if idx % 1000 == 0:
                    print("sending a packet to {}".format(self.dst_ip))
                time.sleep(0.005) # 5ms
                #time.sleep(10000)


    controller = RoutingController(host_name).main()
