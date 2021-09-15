from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
import socket, struct, pickle, os
from scapy.all import Ether, sniff, Packet, BitField
import time
import sys
import argparse
import pdb

class register_reader(object):
    def __init__(self):
        self.topo = Topology(db="../p4src_simple/topology.db")  #set the topology
        self.controllers = {}                   #the switches
        self.custom_calcs={}
        self.register_num={}
        self.registers={}
        self.init()
        

    def init(self):
        self.num_of_switches = len(self.topo.get_p4switches())
        #import pdb
        #pdb.set_trace()
        self.connect_to_switches()
        

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():# topology line 632
            thrift_port = self.topo.get_thrift_port(p4switch) 
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def register_read(self):
        tot_message = 0
        for p4switch in self.topo.get_p4switches():
            tot_message += self.controllers[p4switch].register_read("egress_counter", 0)
        return tot_message
    

if __name__ == "__main__":

    reader = register_reader()

    
    print(reader.register_read())
