import netns
import pdb

fin = open("host.config", "r")
_ = fin.readline()
host_mnet_pid = int(fin.readline().split()[0])


with netns.NetNS(nspid=host_mnet_pid):
    from scapy.all import *
    class sync_header(Packet):
        name = "sync_header"
        fields_desc = [\
            BitField("msg_type", 0, 8),\
            BitField("stage", 0, 32),\
            BitField("message_id", 0, 8)
        ]

    class payload_t(Packet):
        name = "payload_t"
        fields_desc = [\
            BitField("value", 0, 32)
        ]

    fin = open("host2.config", "r")
    src, dst = fin.readline().split()

    #pdb.set_trace()
    # Inject one SYNC_BROADCAST packet 
    pkt = Ether(type=0x88b5, src=src, dst=dst) / sync_header(msg_type=0, stage=1, message_id=1)
    

    fin = open("diameter.txt", "r")
    switch, _ = fin.readline().split()
    sendp(pkt, iface="h{}-eth0".format(switch))