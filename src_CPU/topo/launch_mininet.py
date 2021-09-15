from mininet.net import Mininet
from mininet.log import output
from mininet.cli import CLI
from mininet.link import TCIntf
import json
import copy
import pdb

def is_switch(str):
    return str[0] == 's'

def is_host(str):
    return str[0] == 'h'

if __name__ == "__main__":
    net = Mininet()

    hosts = dict()
    # switches = dict()

    fin = open("topology.json", "r")
    topology = json.load(fin)

    for i, host_name in enumerate(sorted(topology["hosts"].keys())):
        
        net.addHost(host_name, ip=None)
        hosts[host_name] = [net.hosts[i], 0]
    
    # for switch_name in sorted(topology["switches"].keys()):
    #     cur_ip[2] += 1
    #     if cur_ip[2] == 256:
    #         cur_ip[1] += 1
    #         cur_ip[2] = 0
        
    #     ip_str = "{}.{}.{}.{}".format(cur_ip[0], cur_ip[1], cur_ip[2], cur_ip[3])
    #     switches[switch_name] = (self.addSwitch(switch_name, ip=ip_str), ip_str)
    
    fout = open("topology.txt", "w")
    i = 0
    cur_ip = [10, 0, 0, 0]

    links = []
        
    for link in topology["links"]:
        i += 1
        cur_ip[2] += 1
        if cur_ip[2] == 256:
            cur_ip[1] += 1
            cur_ip[2] = 0
        
        node_name1 = link[0]
        node_name2 = link[1]

        bw = link[2]["bw"]
        delay = link[2]["delay"]
        loss = link[2]["loss"]
        queue_len = link[2]["queue_length"]

        node_item1 = hosts[node_name1]
        node_item2 = hosts[node_name2]

        cur_ip_str1 = "{}.{}.{}.2".format(cur_ip[0], cur_ip[1], cur_ip[2])
        cur_ip_str2 = "{}.{}.{}.1".format(cur_ip[0], cur_ip[1], cur_ip[2])

        #fout.write("{} {} {} {}\n".format(node_name1, cur_ip_str1, node_name2, cur_ip_str2))
        

        intf1 = "{}-eth{}".format(node_item1[0].name, node_item1[1])
        intf2 = "{}-eth{}".format(node_item2[0].name, node_item2[1])
        links.append([node_name1, cur_ip_str1, node_name2, cur_ip_str2, intf1, intf2])

        net.addLink(node_item1[0], node_item2[0], intfName1=intf1, intfName2=intf2, intf=TCIntf, bw=bw, delay=delay, loss=loss, max_queue_size=queue_len)
        

        node_item1[0].intf(intf1).setIP(cur_ip_str1, 24)
        node_item2[0].intf(intf2).setIP(cur_ip_str2, 24)

        node_item1[1] += 1
        node_item2[1] += 1

    for i, link in enumerate(net.links):
        fout.write("{} {} {} {} {} {} {} {}\n".format(links[i][0], links[i][1], links[i][4], link.intf1.mac, links[i][2], links[i][3], links[i][5], link.intf2.mac))
    fout.close()
    
    fin.close()

    net.start()
    client = CLI(net)
    client.run()
    #net.stop()
    
    
