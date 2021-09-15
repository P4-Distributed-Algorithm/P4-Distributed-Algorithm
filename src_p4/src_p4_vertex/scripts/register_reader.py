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
        self.connect_to_switches()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():# topology line 632
            thrift_port = self.topo.get_thrift_port(p4switch) 
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def register_read(self, sw_name, reg_name, index):
        print(sw_name)
        print(self.controllers[sw_name].register_read(reg_name, index))
    

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="")
    arg_parser.add_argument("--sw_name", type=str, required=True)
    arg_parser.add_argument("--reg_name", type=str, required=True)
    #arg_parser.add_argument("--index", type=int, required=True)
    args = arg_parser.parse_args()

    reader = register_reader()

    #if args.index != -1:
    #    reader.register_read(args.sw_name, args.reg_name, args.index)
    #else:
    if args.sw_name == "all":
        for sw_name in reader.controllers.keys():
            reader.register_read(sw_name, args.reg_name, None)
    else:
        reader.register_read(args.sw_name, args.reg_name, None)