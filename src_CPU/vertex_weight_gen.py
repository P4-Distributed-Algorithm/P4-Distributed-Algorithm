import random

fin = open("topo/topology.txt", "r")
fout = open("graph_weight.txt", "w")


edges = []

node_weight = dict()
host_cnt = 300
node_deg = dict()
for i in range(host_cnt):
    node_deg["h{}".format(i + 1)] = 0

while True:
    try:
        line_content = fin.readline().replace("\n", "")
        h1, _, _, _, h2, _, _, _ = line_content.split()
        node_weight[h1] = random.randint(1, 100)
        node_weight[h2] = random.randint(1, 100)
        node_deg[h1] += 1
        node_deg[h2] += 1
        if line_content == "":
            break
        edges.append(line_content)
    except:
        break

edge_cnt = len(edges)
print(node_weight)
print(node_deg)

for i, line_content in enumerate(edges):
    h1, h1_ip, _, _, h2, h2_ip, _, _ = line_content.split()
    # fout.write("{} {} {}\n".format(line_content, node_weight[h1], (float)(node_weight[h2]) / node_deg[h2]))
    fout.write("{} {} {} {} {} {}\n".format(h2, h2_ip, h1, h1_ip, node_weight[h2], (float)(node_weight[h1]) / node_deg[h1]))
    fout.write("{} {} {} {} {} {}\n".format(h1, h1_ip, h2, h2_ip, node_weight[h1], (float)(node_weight[h2]) / node_deg[h2]))
fout.close()
