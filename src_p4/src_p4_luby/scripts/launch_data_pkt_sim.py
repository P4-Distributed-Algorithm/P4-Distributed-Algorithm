import time
def load_config():
    fin = open("host.config", "r")

    host_info = []
    while True:
        try:
            host_name, host_mnet_pid = fin.readline().split()[0], int(fin.readline())

            host_info.append((host_name, host_mnet_pid))
            print(host_name, host_mnet_pid)
            _ = fin.readline()
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
        os.system("python data_pkt_simulator.py -n {} -p {}".format(self.host_name, self.host_mnet_pid))

if __name__ == "__main__":
    host_info = load_config()
    for host_name, host_mnet_pid in host_info:
        td = threading.Thread(target=Main_Local_Thread(host_name, host_mnet_pid).run)
        td.start()
        
