import argparse
import time
arg_parser = argparse.ArgumentParser(description="")
arg_parser.add_argument("--benchmark_file", type=str, default="bench.txt")
arg_parser.add_argument("--program", type=str, default="vertex_cover_original")
args = arg_parser.parse_args()

host_cnt = 0

def load_config():
    fin = open("host.config", "r")
    global host_cnt
    host_info = []
    while True:
        try:
            host_name, host_mnet_pid = fin.readline().split()[0], int(fin.readline())
            host_info.append((host_name, host_mnet_pid))

            host_cnt += 1
            print(host_name, host_mnet_pid)
        except:
            break
    
    return host_info

import threading
class Main_Local_Thread(threading.Thread):
    def __init__(self, host_name, host_mnet_pid):
        self.host_name = host_name
        self.host_mnet_pid = host_mnet_pid
    def run(self):
        import os
        os.system("python3 {} --name {} --pid {} --cnt {} --benchmark_file {}".format(args.program, self.host_name, self.host_mnet_pid, host_cnt, args.benchmark_file))

if __name__ == "__main__":
    host_info = load_config()
    for host_name, host_mnet_pid in host_info:
        td = threading.Thread(target=Main_Local_Thread(host_name, host_mnet_pid).run)
        td.start()
        #time.sleep(1000)
