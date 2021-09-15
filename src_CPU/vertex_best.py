import random
import time

fin = open("graph_weight.txt", "r")

edges = dict()

node_weight = dict()
host_cnt = 300

for i in range(300):
    edges["h{}".format(i + 1)] = []

host_cnt = 0
while True:
    try:
        line_content = fin.readline().replace("\n", "")
        h1, _, h2, _, weight, _ = line_content.split()
        node_weight[h1] = int(weight)
        host_cnt = max(max(host_cnt, int(h1[1:])), int(h2[1:]))
        edges[h1].append(h2)
        if line_content == "":
            break
    except:
        break
import pdb
#print(host_cnt)

best = 1000000000
# best = 1000000000
# print(node_weight)
# for S in range(1 << host_cnt):
#     tot_weight = 0
#     for host in node_weight.keys():
#         host_id = int(host[1:]) - 1
#         if (S & (1 << host_id)) != 0:
#             tot_weight += node_weight[host]

#     if tot_weight > best:
#         continue

#     flag = True
#     for host in node_weight.keys():
#         host_id = int(host[1:]) - 1
#         for neighbor in edges[host]:
#             neighbor_host_id = int(neighbor[1:]) - 1
#             if (S & (1 << host_id)) == 0 and (S & (1 << neighbor_host_id)) == 0:
#                 flag = False
    
#     if flag == True:
#         best = tot_weight

# print(best)

our_solution = 0
fin = open("tree_result.txt", "r")
for i in range(host_cnt):
    h1, is_choose = fin.readline().replace("\n", "").split()
    is_choose = int(is_choose)
    if is_choose == 1:
        our_solution += node_weight[h1]

print(our_solution)

if our_solution > 2.4 * best:
    print("Error")
    time.sleep(1000000)

fout = open("result_ratio.txt", "w")
fout.write("{}\n".format(our_solution / best))
fout.close()