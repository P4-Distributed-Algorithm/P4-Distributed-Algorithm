from mininet.topo import Topo
import json
import pdb
import copy

def is_switch(str):
    return str[0] == 's'

def is_host(str):
    return str[0] == 'h'

class MyTopo(Topo):
    def build(self):
        "Create custom topo."
        
        hosts = dict()
        # switches = dict()

        fin = open("topology.json", "r")
        topology = json.load(fin)

        cur_ip = [10, 0, 0, 1]

        for host_name in sorted(topology["hosts"].keys()):
            cur_ip[2] += 1
            if cur_ip[2] == 256:
                cur_ip[1] += 1
                cur_ip[2] = 0
            
            #ip_str = "{}.{}.{}.{}".format(cur_ip[0], cur_ip[1], cur_ip[2], cur_ip[3])
            hosts[host_name] = (self.addHost(host_name, ip=None), copy.copy(cur_ip))
        
        # for switch_name in sorted(topology["switches"].keys()):
        #     cur_ip[2] += 1
        #     if cur_ip[2] == 256:
        #         cur_ip[1] += 1
        #         cur_ip[2] = 0
            
        #     ip_str = "{}.{}.{}.{}".format(cur_ip[0], cur_ip[1], cur_ip[2], cur_ip[3])
        #     switches[switch_name] = (self.addSwitch(switch_name, ip=ip_str), ip_str)
        
        pdb.set_trace()
        fout = open("topology.txt", "w")
        for link in topology["links"]:
            node_name1 = link[0]
            node_name2 = link[1]

            bw = link[2]["bw"]
            delay = link[2]["delay"]
            queue_len = link[2]["queue_length"]

            node_item1 = hosts[node_name1]
            node_item2 = hosts[node_name2]

            cur_ip1 = node_item1[1]
            cur_ip2 = node_item2[1]

            cur_ip_str1 = "{}.{}.{}.{}".format(cur_ip1[0], cur_ip1[1], cur_ip1[2], cur_ip1[3])
            cur_ip_str2 = "{}.{}.{}.{}".format(cur_ip2[0], cur_ip2[1], cur_ip2[2], cur_ip2[3])

            fout.write("{} {}\n".format(cur_ip_str1, cur_ip_str2))

            intf1 = "{}-eth{}".format(node_item1[0], cur_ip1[3])
            intf2 = "{}-eth{}".format(node_item2[0], cur_ip1[3])

            self.addLink(node_item1[0], node_item2[0], intfName1=intf1, intfName2=intf2, bw=bw, delay=delay, max_queue_size=queue_len)

            node_item1[0].intf(intf1).setIP(cur_ip_str1, 24)
            node_item2[0].intf(intf2).setIP(cur_ip_str2, 24)

            cur_ip1[3] += 1
            cur_ip2[3] += 1


        
        fout.close()
        fin.close()


topos = {'mytopo': ( lambda: MyTopo()) }