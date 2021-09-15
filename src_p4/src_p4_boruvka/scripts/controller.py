from networkx.classes.function import all_neighbors
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
import socket, struct, pickle, os
from scapy.all import Ether, sniff, Packet, BitField
import time
import sys
import argparse
import pdb
import copy
import random
import argparse
import Queue
import copy

arg_parser = argparse.ArgumentParser(description="")
arg_parser.add_argument("--topo_weight", type=str, default="None")
args = arg_parser.parse_args()


os.system("bash config.sh")

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

BUCKET_NUM = 64
BIN_NUM  = 8
TIME_INTERVAL = 1000
TOPO = "arbitrary"

class RoutingController(object):

    def __init__(self):
        self.topo = Topology(db="../p4src_simple/topology.db")  #set the topology
        self.controllers = {}                   #the switches
        self.custom_calcs={}
        self.register_num={}
        self.registers={}
        self.init()
        self.generate_weight()
    
    def generate_weight(self):
        visited_weight = set()
        if args.topo_weight == "None":
            fout = open("weight_graph.txt", "w")
            self.weights = dict()
            for sw_name, controller in self.controllers.items():
                self_id = int(sw_name[1:])
                neighbor_list = self.topo.get_switches_connected_to(sw_name)

                for neighbor in neighbor_list:
                    neighbor_id = int(neighbor[1:])
                    if neighbor_id < self_id:
                        weight = random.randint(1, 10000)
                        while weight in visited_weight:
                            weight = random.randint(1, 10000)
                        visited_weight.add(weight)
                        self.weights[(neighbor_id, self_id)] = weight
                        self.weights[(self_id, neighbor_id)] = weight
                        fout.write("s{} -> s{}: {}\n".format(self_id, neighbor_id, weight))
        else:
            fin = open(args.topo_weight, "r")
            self.weights = dict()
            while True:
                try:
                    sw1, _, sw2, weight = fin.readline().split()
                    sw1 = int(sw1[1:])
                    sw2 = int(sw2[1: -1])
                    weight = int(weight)
                    self.weights[(sw1, sw2)] = weight
                    self.weights[(sw2, sw1)] = weight
                except:
                    break


    def init(self):
        self.num_of_switches = len(self.topo.get_p4switches())
        self.connect_to_switches()
        self.build_tree()     
        self.reset_states()
        self.set_table_defaults()
        self.set_custom_calcs()
        self.reset_all_registers()
        
    def build_tree(self):
        self.father = dict()
        self.sons = dict()
        self.diameter = 6
        
        if TOPO == "fat_tree":
            self.root_switch = 1
            for sw_name, controller in self.controllers.items():
                self_id = int(sw_name[1:])
                self.father[sw_name] = "s10000"
                tmp_id = 10000
                self.sons[sw_name] = set()
                neighbor_list = self.topo.get_switches_connected_to(sw_name)

                for neighbor in neighbor_list:
                    neighbor_id = int(neighbor[1:])
                    #if neighbor_id < tmp_id and neighbor_id < self_id:
                    if neighbor_id < self_id:
                        self.father[sw_name] = neighbor
                        tmp_id = neighbor_id

            for sw_name, controller in self.controllers.items():
                if self.father[sw_name] != "s10000":
                    self.sons[self.father[sw_name]].add(sw_name)
        
        else:
            # for arbitraty topology, you have to apply BFS algorithm to build the spanning tree

            n_switch = len(self.topo.get_p4switches())
            visited = [0 for i in range(n_switch + 1)]
            depth = [0 for i in range(n_switch + 1)]
            subtree_dep = [0 for i in range(n_switch + 1)]
            queue = [1]
            q = Queue.Queue()
            q.put(1)
            visited[1] = 1
            sons = dict()
            father = dict()
            for sw_name, controller in self.controllers.items():
                self.sons[sw_name] = set()
                sons[int(sw_name[1:])] = set()
                self.father[sw_name] = "s10000"
                father[int(sw_name[1:])] = 0
            while q.empty() == False:
                x = q.get()
                
                neighbors = self.topo.get_switches_connected_to("s{}".format(x))
                for neighbor in neighbors:
                    neighbor_id = int(neighbor[1:])
                    if visited[neighbor_id] == 0:
                        sons[x].add(neighbor_id)
                        father[neighbor_id] = x
                        q.put(neighbor_id)
                        queue.append(neighbor_id)
                        visited[neighbor_id] = 1
                        depth[neighbor_id] = depth[x] + 1
            
            for i in range(len(queue) - 1, -1, -1):
                subtree_dep[father[queue[i]]] = subtree_dep[queue[i]] + 1

            def get_second(sons, depth):
                first_dep = -1
                second_dep = -2
                first = 0
                second = 0
                for son in sons:
                    if depth[son] > first_dep:
                        second_dep, second = first_dep, first
                        first_dep, first = depth[son], son
                    elif depth[son] > second_dep:
                        second_dep, second = depth[son], son
                return first, second

            x = 1
            outer_dep = 0
            sons2 = copy.deepcopy(sons)

            while True:
                y, z = get_second(sons[x], subtree_dep)
                if y == 0 or subtree_dep[y] >= max(outer_dep, 0 if z == 0 else subtree_dep[z] + 1) + 1:
                    father[x] = y
                    sons2[y].add(x)
                    sons2[x].remove(y)
                    x = y
                    outer_dep = max(outer_dep, 0 if z == 0 else subtree_dep[z] + 1) + 1
                else:
                    break
            sons = sons2
            
            for sw_name, controller in self.controllers.items():
                self.father[sw_name] = "s{}".format(father[int(sw_name[1:])])
                for son in sons[int(sw_name[1:])]:
                    self.sons[sw_name].add("s{}".format(son))
            self.father["s{}".format(x)] = "s10000"
            


            self.diameter = subtree_dep[x] * 2
            fout = open("diameter.txt", "w")
            fout.write("{} {}\n".format(x, self.diameter))
            fout.close()
            self.root_switch = x

    

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():# topology line 632
            print(p4switch)
            thrift_port = self.topo.get_thrift_port(p4switch) 
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def reset_states(self):
        for controllers in self.controllers.values():
            print(controllers)
            controllers.reset_state()

    def set_table_defaults(self):
        for sw_name, controllers in self.controllers.items():
            print(sw_name, self.father[sw_name])
            if sw_name == "s{}".format(self.root_switch):
                father_name = 0xffffffffffff
                father_port = 0
            else:
                father_name = self.topo.node_to_node_mac(self.father[sw_name], sw_name)
                father_port = self.topo.node_to_node_port_num(sw_name, self.father[sw_name])

            controllers.table_set_default("get_general_info", "modify_general_info", [
                str(father_name), 
                str(father_port), 
                str(self.num_of_switches), 
                str(len(self.sons[sw_name])), 
                str(len(self.topo.get_switches_connected_to(sw_name)))
            ])
            controllers.table_set_default("get_target_algo_info", "modify_target_algo_info", [
                str(int(sw_name[1: ])),
                str(1000000000)
            ])
            
            controllers.table_set_default("lookup_nhop", "set_nhop", [str(0), str(0)])
    
    def set_custom_calcs(self):
        for p4switch in self.topo.get_p4switches():
            self.custom_calcs[p4switch] = self.controllers[p4switch].get_custom_crc_calcs()
            self.register_num[p4switch] = len(self.custom_calcs[p4switch])     

    def reset_all_registers(self):
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                controller.register_reset(register)   


    def route(self):
        # set_table

        #pdb.set_trace()
        for sw_name, controllers in self.controllers.items():
            if sw_name == "s{}".format(self.root_switch):
                
                host = self.topo.get_hosts_connected_to(sw_name)[0]
                src_mac = self.topo.node_to_node_mac(host, sw_name)
                dst_mac = self.topo.node_to_node_mac(sw_name, host)

                fout = open("host2.config", "w")
                fout.write("{} {}\n".format(src_mac, dst_mac))
                fout.close()

        for sw_name, controllers in self.controllers.items():
            sw_id = int(sw_name[1:])

            neighbor_list = self.topo.get_switches_connected_to(sw_name)


            for neighbor_name in neighbor_list:
                nb_sw_id = int(neighbor_name[1:])
                dst_mac = self.topo.node_to_node_mac(neighbor_name, sw_name)
                egress_port = self.topo.node_to_node_port_num(sw_name, neighbor_name)
                src_mac = self.topo.node_to_node_mac(sw_name, neighbor_name)
                
                self.controllers[sw_name].table_add("lookup_nhop", "set_nhop", [str(egress_port)], [str(src_mac), str(dst_mac)])

                self.controllers[sw_name].table_add("get_target_algo_info", "modify_target_algo_info", [str(dst_mac)], [
                    str(sw_id),
                    str(self.weights[(sw_id, nb_sw_id)])
                ])
                #pdb.set_trace()

            
        for sw_name, controller in self.controllers.items():
            #pdb.set_trace()
            neighbor_list = self.topo.get_switches_connected_to(sw_name)
            special = [0, 3]

            all_port_list = []
            for neighbor_name in neighbor_list:
                all_port_list.append(self.topo.node_to_node_port_num(sw_name, neighbor_name))
            son_port_list = []
            
            for son_name in self.sons[sw_name]:
                son_port_list.append(self.topo.node_to_node_port_num(sw_name, son_name))
            son_with_father = copy.deepcopy(son_port_list)
            if (self.father[sw_name] != "s10000"):
                son_with_father.append(self.father[sw_name])

            for upper_neighbor_name in neighbor_list + [0, 3]:
                if upper_neighbor_name in special:
                    upper_egress_port = upper_neighbor_name
                    #pdb.set_trace()
                else:
                    upper_egress_port = self.topo.node_to_node_port_num(sw_name, upper_neighbor_name) + 4
                for i in range(0, 6):
                    mc_grp = (upper_egress_port * 256) + i
                    self.controllers[sw_name].mc_mgrp_create(mc_grp)

                    if upper_egress_port >= 4:
                        node2 = self.controllers[sw_name].mc_node_create(4, [upper_egress_port - 4])
                    elif upper_egress_port == 3: # == 3
                        node2 = self.controllers[sw_name].mc_node_create(4, all_port_list)

                    if upper_egress_port >= 3:
                        self.controllers[sw_name].mc_node_associate(mc_grp, node2)

                    if i == 1:
                        node1 = self.controllers[sw_name].mc_node_create(1, son_port_list)
                        self.controllers[sw_name].mc_node_associate(mc_grp, node1)
                    elif i == 2:
                        node1 = self.controllers[sw_name].mc_node_create(2, son_port_list)
                        self.controllers[sw_name].mc_node_associate(mc_grp, node1)
                        if self.father[sw_name] != "s10000":
                            node1 = self.controllers[sw_name].mc_node_create(1, [self.topo.node_to_node_port_num(sw_name, self.father[sw_name])])
                            self.controllers[sw_name].mc_node_associate(mc_grp, node1)
                    elif i == 3:
                        node1 = self.controllers[sw_name].mc_node_create(1, all_port_list)
                        self.controllers[sw_name].mc_node_associate(mc_grp, node1)
                    elif i == 4:
                        if self.father[sw_name] != "s10000":
                            #pdb.set_trace()
                            node1 = self.controllers[sw_name].mc_node_create(1, [self.topo.node_to_node_port_num(sw_name, self.father[sw_name])])
                            self.controllers[sw_name].mc_node_associate(mc_grp, node1)
                    elif i == 5:
                        node1 = self.controllers[sw_name].mc_node_create(2, son_port_list)
                        self.controllers[sw_name].mc_node_associate(mc_grp, node1)

        
        for sw_name, controller in self.controllers.items():
            neighbor_list = self.topo.get_switches_connected_to(sw_name)
            for neighbor_name in neighbor_list:
                egress_port = self.topo.node_to_node_port_num(sw_name, neighbor_name)
                self.controllers[sw_name].mirroring_add(egress_port + 1, egress_port)
            self.controllers[sw_name].mirroring_add_mc(0, 3)
        
        readable_topo = open("readable_topo.txt", "w")
        readable_topo.write("Spanning_tree\n")
        for sw_name in self.controllers.keys():
            if sw_name != "s{}".format(self.root_switch):
                readable_topo.write("{} -> {}\n".format(sw_name, self.father[sw_name]))

        for sw_name, controller in self.controllers.items():
            neighbor_list = self.topo.get_switches_connected_to(sw_name)
            for neighbor_name in neighbor_list:
                egress_port = self.topo.node_to_node_port_num(sw_name, neighbor_name)
                dst_mac = self.topo.node_to_node_mac(neighbor_name, sw_name)
                src_mac = self.topo.node_to_node_mac(sw_name, neighbor_name)

                readable_topo.write("{} -> {}. src = {}, dst = {}, egress_port = {}\n".format(
                    sw_name, neighbor_name, src_mac, dst_mac, egress_port
                )) 

        for sw_name, controller in self.controllers.items():
            self.controllers[sw_name].register_write("gen_tree_father", 0, 255)
            self.controllers[sw_name].register_write("gen_tree_new_father", 0, 255)
            
            neighbor_list = self.topo.get_switches_connected_to(sw_name)
            self.controllers[sw_name].register_write("tot_neighbor", 0, len(neighbor_list))
            for neighbor_name in neighbor_list:
                egress_port = self.topo.node_to_node_port_num(sw_name, neighbor_name)
                self.controllers[sw_name].register_write("is_neighbor", egress_port, 1)
                self.controllers[sw_name].register_write("new_is_neighbor", egress_port, 1)



    def main(self):
        self.route()

        for switch_id, switch_name in enumerate(self.controllers.keys()):
            print("{} {}".format(switch_id, switch_name))



if __name__ == "__main__":
    controllers = RoutingController().main()
