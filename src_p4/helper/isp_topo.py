from networkx import read_gml
from networkx import *
import glob
import random
import copy
import json
import pdb
import argparse

parser = argparse.ArgumentParser("")
parser.add_argument("--loss_rate", type=float, default=0)
parser.add_argument("--base_delay", type=int, default=1000)
args = parser.parse_args()
loss_rate = args.loss_rate
base_delay = args.base_delay

topo_path = "../raw_topo_data/"
topo_files = glob.glob(topo_path + "*.gml")

file_id = 0

for topo_file in topo_files:
    topo_data = dict()
    try:
        topo = read_gml(topo_file)
        # import pdb
        # pdb.set_trace()
    except:
        continue
    #pdb.set_trace()
    nodes = list(topo.nodes)
    edges = list(topo.edges)
    
    G = Graph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
    print(diameter(G))
    print(max([val for (node, val) in G.degree()]))

    indexing = dict()
    switches = dict()
    hosts = dict()
    idx = 0
    for node in nodes:
        idx += 1
        indexing[node] = idx
        switches["s%d" % idx] = {"cpu_port": True}
        hosts["h%d" % idx] = dict()
    topo_data["switches"] = switches
    topo_data["hosts"] = hosts
    
    links = []
    for edge in edges:
        delay = str(random.randint(0, 10) + base_delay) + "ms"
        common_link_setting = {"bw": 1, "queue_length": 1000000, "delay": delay, "loss": loss_rate}
        sw1 = "s%d" % indexing[edge[0]]
        sw2 = "s%d" % indexing[edge[1]]
        cur_link = [sw1, sw2, copy.deepcopy(common_link_setting)]
        links.append(cur_link)

    for i in range(1, idx):
        delay = str(random.randint(0, 10) + base_delay) + "ms"
        common_link_setting = {"bw": 1, "queue_length": 1000000, "delay": delay, "loss": 0}
        cur_link = ["h%d" % i, "s%d" % i, copy.deepcopy(common_link_setting)]
        links.append(cur_link)
    
    topo_data["links"] = links
    topo_data["country"] = vars(topo)["graph"]["GeoLocation"]

    json_string = json.dumps(topo_data)
    fout = open("../topo_data/topo{}.json".format(file_id), "w")
    fout.write(json_string)
    fout.close()
    file_id += 1
