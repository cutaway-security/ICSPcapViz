# Easy method to determine service port name by port number
from socket import getservbyname, getservbyport
import numpy as np
from scipy.stats import entropy
    
####################
# Inventory functions
####################
def get_protocols(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and return a list of protocols
    """
    protos = []                                                        
    for p in inPackets: 
        pl = '' 
        # Test for protocol layers beyond TCP/UDP
        if len(p.layers) > 3: pl = p.layers[3].layer_name 
        if pl and pl not in protos: protos.append(pl) 
    return protos

def get_hardware_addresses(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and return a dictionary of interfaces.
    Dictionary key is interface hardware address and value is list of IP addresses.
    """
    # TODO: Use ICSPcapViz ieee vendor files for interfaces vendor names
    interfaces = {}
    for p in inPackets:
        # If packet doesn't have an ethernet address then just move on
        try: 
            src_ether = p.eth.src
            dst_ether = p.eth.dst
        except:
            continue
        if src_ether not in str(interfaces.keys()): interfaces[src_ether] = []
        if dst_ether not in str(interfaces.keys()): interfaces[dst_ether] = []

        # If packet doesn't have an IP address then just move on
        try:
            src_ip = p.ip.src
            dst_ip = p.ip.dst
        except:
            continue
        if src_ip not in interfaces[src_ether]: interfaces[src_ether].append(src_ip)
        if dst_ip not in interfaces[dst_ether]: interfaces[dst_ether].append(dst_ip)
    return interfaces

def get_target_lists(inPackets):
    """
    Analyze a pyshark.capture.file_capture. FileCapture object and return a dictionary of services.
    Dictionary key is service name and value is list of IP addresses.
    """
    # TODO: Use ICSPcapViz services ini files for ICS protocols
    services = {}     
    for p in inPackets:
        # Reset fields
        src_ip,dst_ip,src_port,dst_port,trans = '','','','',''

        # Review packets for fields. Will continue if not TCP/UDP
        try:
            src_ip,dst_ip,trans = p.ip.src,p.ip.dst,p.transport_layer
            if trans == 'TCP': src_port,dst_port = int(p.tcp.srcport),int(p.tcp.dstport)
            if trans == 'UDP': src_port,dst_port = int(p.udp.srcport),int(p.udp.dstport)
        except:
            continue

        # Locate lowest service port value, this should be the listening service / application
        # Source port is lower   
        if src_port and src_port < dst_port:
            try:
                srv_name = str(src_port) + "/" + getservbyport(src_port,trans.lower()) + "/" + trans
            except:
                # Port numbers that are not associated with a known service will error
                srv_name = str(src_port) + "/" + "Unknown" + "/" + trans
            if srv_name not in str(services.keys()): services[srv_name] = []
            if src_ip not in services[srv_name]: services[srv_name].append(src_ip)

        # Destination port is lower   
        if src_port and src_port > dst_port:
            try:
                srv_name = str(dst_port) + "/" + getservbyport(dst_port,trans.lower()) + "/" + trans
            except:
                # Port numbers that are not associated with a known service will error
                srv_name = str(dst_port) + "/" + "Unknown" + "/" + trans
            if srv_name not in str(services.keys()): services[srv_name] = []
            if dst_ip not in services[srv_name]: services[srv_name].append(dst_ip)
    return services
    
####################
# Print functions
####################
def print_unknown_raw(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and search for packets with un-decoded data.
    Print data information and raw data bytes.
    """
    for p in inPackets:
        if '<TCP Layer>' not in str(p.layers) or 'DATA' != p.highest_layer:
            continue
        # Check direction, assume smaller port is server and application
        # TODO: should probably do the same for UDP
        if p.tcp.srcport > p.tcp.dstport:
            dir = 'Query:           '
        else:
            dir = 'Response:'
        try:
            print("%s: %s:%s -> %s:%s %s %s Len: %s"%(p.frame_info.number,p.ip.src,p.tcp.srcport,p.ip.dst,p.tcp.dstport,dir,p.DATA.data,int(len(p.DATA.data)/2)))
            print("%s Raw: %s"%(' '*46,bytes.fromhex(p.DATA.data)))
        except:
            continue

def print_unknown_entropy(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object and search for packets with un-decoded data.
    Print data information and the entropy of the raw data.
    """
    for p in inPackets:
        if '<TCP Layer>' not in str(p.layers) or 'DATA' != p.highest_layer:
            continue
        # Check direction, assume smaller port is server and application
        # TODO: should probably do the same for UDP
        if p.tcp.srcport > p.tcp.dstport:
            dir = 'Query:           '
        else:
            dir = 'Response:'
        try:
            #print("%s: %s:%s -> %s:%s %s %s Len: %s"%(p.frame_info.number,p.ip.src,p.tcp.srcport,p.ip.dst,p.tcp.dstport,dir,p.DATA.data,int(len(p.DATA.data)/2)))
            # Review the bytes' entropy value. Values >= 7 may be encrypted or compressed
            print("Frame Number: %s ENT: %s"%(p.frame_info.number,round(entropy(np.frombuffer(bytes.fromhex(p.DATA.data),dtype=np.uint32)),2)))
        except:
            # TODO: FIXME the data length is not always correct
            continue