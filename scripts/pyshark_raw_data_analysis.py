import os,sys
import pyshark
import numpy as np
from scipy.stats import entropy

# Global Variables
RAW=False
ENT=False
if len(sys.argv) > 2:
    if 'raw' in sys.argv[2:]:
        RAW=True
    if 'ent' in sys.argv[2:]:
        ENT=True

# Process PCAP
inf = sys.argv[1]
packets = pyshark.FileCapture(inf)

# Process Packets
for p in packets:
    # Check direction, assume smaller port is server and application
    if p.tcp.srcport > p.tcp.dstport:
        dir = 'Query:           '
    else:
        dir = 'Response:'
    # Check for DATA layer (DATA that Wireshark doesn't understand)
    if 'DATA' in p.highest_layer:
        print("%s: %s:%s %s %s:%s %s %s Len: %s"%(p.frame_info.number,p.ip.src,p.tcp.srcport,'->',p.ip.dst,p.tcp.dstport,dir,p.DATA.data,int(len(p.DATA.data)/2)))
        if RAW: print("%s Raw: %s"%(' '*46,bytes.fromhex(p.DATA.data)))
        # Review the bytes' entropy value. Values >= 7 may be encrypted or compressed
        if ENT: print("%s ENT: %s"%(' '*46,round(entropy(np.frombuffer(bytes.fromhex(p.DATA.data),dtype=np.uint32)),2)))