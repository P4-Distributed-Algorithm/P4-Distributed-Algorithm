import ctypes
import os
import sys

def setns(tgt_pid):
    libc = ctypes.CDLL('libc.so.6')
    ns_fd = os.open("/proc/{}/ns/mnt".format(tgt_pid), os.O_RDONLY)
    libc.setns(ns_fd, 0)
    #import pdb
    #pdb.set_trace()

def int2byteh(x):
    return (x).to_bytes(4, "little")

def int2byten(x):
    return (x).to_bytes(4, "big")

def byte2inth(b):
    return int.from_bytes(b, "little")

def byte2intn(b):
    return int.from_bytes(b, "big")
