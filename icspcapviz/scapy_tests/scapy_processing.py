import os,sys
from copy import copy
from scapy.all import *
import numpy as np
from scipy.stats import entropy

inf = sys.argv[1]

packets = rdpcap(inf)

hist_list = {}
default_hist = {}
for b in range(0,256): default_hist[b] = 0
for p in packets:
    if not p.haslayer('TCP') or not p.haslayer('Raw'):
        continue
    data = p['Raw'].load
    sip = p['IP'].src
    dip = p['IP'].dst
    pport = 0
    if p['TCP'].sport < p['TCP'].dport:
        pport = p['TCP'].sport
    else:
        pport = p['TCP'].dport
    cur_edge = ()
    for edge in hist_list.keys():
        if sip in edge and dip in edge and pport in edge:
            cur_edge = edge
    if not cur_edge:
        cur_edge = (sip,dip,pport)
        hist_list[cur_edge] = b''
    hist_list[cur_edge] += data


# We might get Numpy divide error. Suppress it.
np.seterr(invalid='ignore')
min_ent = 0.0
print("##### Calculating Entropy #####")
from math import log2
for e in hist_list.keys():
    #print("Edge: %s --- %d --- %s data:\n%s"%(e[0],e[2],e[1],hist_list[e]))

    try:
        # Review the bytes' entropy value. Values >= 7 may be encrypted or compressed
        ent_calc = round(entropy(np.frombuffer(hist_list[e],dtype=np.uint8)),2)

        if ent_calc >= min_ent: print("Edge: %s --- %d --- %s LEN: %s ENT: %s"%(e[0],e[2],e[1],len(hist_list[e]),ent_calc))
    except:
        # TODO: FIXME the data length is not always correct
        continue