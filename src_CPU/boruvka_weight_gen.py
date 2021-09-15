fin = open("topo/topology.txt", "r")
fout = open("graph_weight.txt", "w")

edges = []
while True:
    try:
        line_content = fin.readline().replace("\n", "")
        if line_content == "":
            break
        edges.append(line_content)
    except:
        break

edge_cnt = len(edges)

import random
for i, line_content in enumerate(edges):
    rand_weight = random.randint(1, 20) * edge_cnt + i
    fout.write("{} {}\n".format(line_content, rand_weight))
