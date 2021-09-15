from os import sync
from mininet.link import Intf
from scapy import fields
from scapy.all import *
from scapy.layers.l2 import Ether
import pdb
from datetime import datetime
import copy
import time
import threading


from utils import int2byteh

class Sync_Hdr(Packet):
    name = "Sync_header"
    fields_desc = [
        BitField("message_type", 0, 8),
        BitField("stage", 0, 32),
        BitField("channel_id", 0, 8),
        BitField("message_id", 0, 32)
    ]

BFS_BROADCAST = 0
BFS_REPLY = 1
SYNC_BROADCAST = 2
SYNC_REPLY = 3
START_BROADCAST = 4
FIN_REPLY = 5
NORMAL_PKT = 6
TERMINATE_BROADCAST = 7
ACK_MSG = 8

TIMEOUT = 11

lock = threading.Lock()

ingress_message_id = dict()
egress_message_id = dict()

stored_packet = dict()


bind_layers(UDP, Sync_Hdr, dport=31213)
lists_of_if = get_if_list()
lists_of_ips = [get_if_addr(interf) for interf in lists_of_if if interf != "lo"]

route_table = dict()

def parser_init():
    fin = open("topo/topology.txt")
    while True:
        try:
            _, h1_ip, h1_intf, h1_mac, _, h2_ip, h2_intf, h2_mac = fin.readline().split()
            route_table[h2_ip] = {"src_ip": h1_ip, "src_mac": h1_mac, "dst_mac": h2_mac, "intf": h1_intf}
            route_table[h1_ip] = {"src_ip": h2_ip, "src_mac": h2_mac, "dst_mac": h1_mac, "intf": h2_intf}
        except:
            break
    fin.close()

def send_packets(dst_ip, message_type, stage, buf=None, channel_id=0):
    if buf == None:
        buf = Raw(load=int2byteh(0))
    channel_id += 1
    #buf.show()
    #buf = Raw(load=raw(buf))
    #buf.show()
    lock.acquire()
    if dst_ip not in egress_message_id:
        egress_message_id[dst_ip] = [0, 0, 0]
        stored_packet[dst_ip] = []
        ingress_message_id[dst_ip] = [0, 0, 0]
    if message_type != NORMAL_PKT:
        channel_id = 0
    pkt = Ether(type=0x0800, src=route_table[dst_ip]["src_mac"], dst=route_table[dst_ip]["dst_mac"]) / \
        IP(dst=dst_ip, src=route_table[dst_ip]["src_ip"]) / UDP(sport=31213, dport=31213) / Sync_Hdr \
        (message_type=message_type, stage=stage, message_id=egress_message_id[dst_ip][channel_id], channel_id=channel_id) / buf
    
    global tot_packet_exclude_ack

    egress_message_id[dst_ip][channel_id] += 1

    stored_packet[dst_ip].append([copy.deepcopy(pkt), time.time(), channel_id])
    lock.release()
    sendp(pkt, iface=route_table[dst_ip]["intf"])
    

def recv_packets(pkt):
    
    if pkt.getlayer(IP).src in lists_of_ips:
        return None

    src_ip = pkt.getlayer(IP).src
    sync_layer = pkt.getlayer(Sync_Hdr)
    message_type  = sync_layer.message_type
    stage = sync_layer.stage
    buf = sync_layer.payload    # to be debugged

    if message_type == ACK_MSG:
        channel_id = sync_layer.channel_id
        lock.acquire()
        for stored_ip in stored_packet.keys():
            if src_ip == stored_ip:
                for i, st_pkt in enumerate(stored_packet[src_ip]):
                    if sync_layer.message_id == st_pkt[0].getlayer(Sync_Hdr).message_id and channel_id == st_pkt[2]:
                        stored_packet[src_ip].pop(i)
        lock.release()
        return None
    else:
        channel_id = sync_layer.channel_id
        lock.acquire()
        if src_ip not in ingress_message_id:
            egress_message_id[src_ip] = [0, 0, 0]
            stored_packet[src_ip] = []
            ingress_message_id[src_ip] = [0, 0, 0]
        
        flag = False
        if ingress_message_id[src_ip][channel_id] <= sync_layer.message_id:
            ingress_message_id[src_ip][channel_id] = sync_layer.message_id + 1
            flag = True
        
        # send an ACK anyway
        pkt = Ether(type=0x0800, src=route_table[src_ip]["src_mac"], dst=route_table[src_ip]["dst_mac"]) / \
            IP(dst=src_ip, src=route_table[src_ip]["src_ip"]) / UDP(sport=31213, dport=31213) / \
            Sync_Hdr(message_type=ACK_MSG, stage=stage, message_id=sync_layer.message_id, channel_id=channel_id)
        sendp(pkt, iface=route_table[src_ip]["intf"])

        lock.release()

        if flag == True:
            return (src_ip, message_type, stage, buf)
        else:
            return None


def resend():
    lock.acquire()
    for stored_ip in stored_packet.keys():
        for i, st_pkt in enumerate(stored_packet[stored_ip]):
            if time.time() - st_pkt[1] > TIMEOUT:
                #pdb.set_trace()
                pkt = st_pkt[0]
                st_pkt[1] = time.time()
                sendp(pkt, iface=route_table[pkt.getlayer(IP).dst]["intf"])
    lock.release()

