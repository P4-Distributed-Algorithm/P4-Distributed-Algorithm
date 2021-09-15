import copy
import random
import argparse
topo_data = {}

parser = argparse.ArgumentParser("")
parser.add_argument("--k_port", type=int, default=4)
parser.add_argument("--loss_rate", type=float, default=0)
parser.add_argument("--base_delay", type=int, default=1000)
args = parser.parse_args()
loss_rate = args.loss_rate
base_delay = args.base_delay
k = args.k_port

links = []

import pdb
#pdb.set_trace()
for i in range(k):
    core_sw = i + 1
    for j in range(k):
        aggre_sw = k + (j) * (k // 2) + i // 2 + 1
        delay = str(random.randint(0, 10) + base_delay) + "ms"
        common_link_setting = {"bw": 1, "queue_length": 1000000, "delay": delay, "loss": loss_rate}
        cur_link = ["s%d" % core_sw, "s%d" % aggre_sw, copy.deepcopy(common_link_setting)]
        links.append(cur_link)

for i in range(k):
    for j1 in range(k // 2):
        for j2 in range(k // 2):
            aggre_sw = k + (i) * (k // 2) + j1 + 1
            tor_sw = k + k * (k // 2) + (i) * (k // 2) + j2 + 1
            delay = str(random.randint(0, 10) + base_delay) + "ms"
            common_link_setting = {"bw": 1, "queue_length": 1000000, "delay": delay, "loss": loss_rate}
            cur_link = ["s%d" % aggre_sw, "s%d" % tor_sw, copy.deepcopy(common_link_setting)]
            links.append(cur_link)

for i in range(k + k * k):
    delay = str(random.randint(0, 10) + base_delay) + "ms"
    common_link_setting = {"bw": 1, "queue_length": 1000000, "delay": delay, "loss": 0}
    cur_link = ["h%d" % (i + 1), "s%d" % (i + 1), copy.deepcopy(common_link_setting)]
    links.append(cur_link)

topo_data["links"] = links
hosts = dict()
for i in range(k + k * k):
    hosts["h%d" % (i + 1)] = dict()
topo_data["hosts"] = hosts
switches = dict()
for i in range(k + k * k):
    switches["s%d" % (i + 1)] = {"cpu_port": True}
topo_data["switches"] = switches

import json
my_json_string = json.dumps(topo_data)
fout = open("topo.json", "w")
fout.write(my_json_string)
fout.close()
