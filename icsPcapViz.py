#!/usr/bin/env python3
import os,sys,re
import configparser
import pyshark
from py2neo import Graph, Node, Relationship

####################
# Globals
####################
MAJOR_VER  = '0'
MINOR_VER  = '4.0'
VERSION    = '.'.join([MAJOR_VER,MINOR_VER])
SEPERATOR  = "==================================="
DEBUG      = False
INF        = False
SERV1      = './ieee_services.ini'
SERV2      = './ics_services.ini'
PACKETS    = False
NEOGRAPH   = False
TCP        = True 
UDP        = False
ICMP       = False
ARP        = False
NEO_PASSWD = 'admin'
NODE_NAME  = 'Host'
DISPLAY_FILTER = None

####################
# FUNCTIONS
####################
def usage():
    print("%s: %s"%(sys.argv[0],VERSION))
    print("")
    print("%s -f <capture_file> [-h] [-v] [-d] [-p <neo4j_passwd>] [-t] [-u] [-n <node_name>] [-c <display_filter>] [-i] [-a]"%(sys.argv[0]))
    print("    -h: This is it.")
    print("    -v: version info.")
    print("    -d: Turn on debugging. Default: off")
    print("    -f <capture_file>: PCAP file that contains the data. Required")
    print("    -p: <neo4j_passwd>: Neo4J password Default: admin. Yes, this will be in your shell history.")
    print("    -t: Do NOT process TCP packets. Default: True")
    print("    -u: Process UDP packets. Default: False")
    print("    -n <node_name>: Special node names to identify a subnet. Default: Host")
    print("    -c <display_filter>: Display filter to use search PCAP. Default: None")
    print("    -i: Process ICMP packets. Default: False [NOT IMPLEMENTED]")
    print("    -a: Process ARP packets. Default: False [NOT IMPLEMENTED]")
    print("")
    print("Be sure to start your Neo4J database. Read README for guidance.")
    print("")
    print("Processing PCAPs can take time. Be patient.")
    print("Yes, you can write a progress bar and submit a pull request.")
    sys.exit()

def version():
    print("%s: %s"%(sys.argv[0],VERSION))
    sys.exit()

def getKeyByVal(d, val):
    keys = [k for k, v in d.items() if v == val]
    if keys:
        return keys[0]
    return None

# Process TCP / UDP packets
def processProtocol(inHosts,inData,inGraph):
    # Process each server application as s
    for dst in list(inData.keys()):
        if DEBUG: print('IP: %s Eth: %s'%(dst,getKeyByVal(inHosts,dst)))
        s = Node(NODE_NAME, name=str(dst))
        s['ethaddr'] = str(getKeyByVal(inHosts,dst))
        dstSubnet=str(dst).split('.')
        s['subnetA'] = str(dstSubnet[0])
        s['subnetB'] = str('.'.join([dstSubnet[0],dstSubnet[1]]))
        s['subnetC'] = str('.'.join([dstSubnet[0],dstSubnet[1],dstSubnet[2]]))
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node(NODE_NAME,name=str(src))
            c['ethaddr'] = str(getKeyByVal(inHosts,src))
            srcSubnet=str(dst).split('.')
            c['subnetA'] = str(srcSubnet[0])
            c['subnetB'] = str('.'.join([srcSubnet[0],srcSubnet[1]]))
            c['subnetC'] = str('.'.join([srcSubnet[0],srcSubnet[1],srcSubnet[2]]))    
            for conn in inData[dst][src]:
                c['vlan'] = str(conn['vlan'])
                if conn['vlan']:
                    SENDtcp = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']) + "/VLAN:" + str(conn['vlan']))
                else:
                    SENDtcp = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']))
                # client is the source, so it goes first
                inGraph.merge(SENDtcp(c, s), NODE_NAME, 'name')

# Process ICMP packets
def processICMP():
    print("%s: ICMP is not implemented.")
    usage() # NOT IMPLEMENTED

# Process ARP packets
def processARP():
    print("%s: ARP is not implemented.")
    usage() # NOT IMPLEMENTED

if __name__ == "__main__":

    ops = ['-h','-d','-f', '-p', '-t', '-u', '-i', '-a', '-v', '-n', '-c']
    if len(sys.argv) < 2:
        usage()

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
        if op == '-v':
            version()
        if op == '-d':
            DEBUG = True
        if op == '-f':
            INF = sys.argv.pop(1)
        if op == '-p':
            INF = sys.argv.pop(1)
        if op == '-t':
            TCP = False
        if op == '-u':
            UDP = True
        if op == '-i':
            ICMP = True
            usage() # NOT IMPLEMENTED
        if op == '-a':
            ARP = True
            usage() # NOT IMPLEMENTED
        if op == '-n':
            NODE_NAME = sys.argv.pop(1)
        if op == '-c':
            DISPLAY_FILTER = sys.argv.pop(1)
        if op not in ops:
            usage()

    # Test PCAP File
    if not INF:
        usage()
    try:
        # TODO: Updated to include vendor names for hardware addresses NOT WORKING
        #PACKETS = pyshark.FileCapture(INF, use_ek=True, custom_parameters={'-N': 'm'})

        # Apply user defined Display Filter
        if DISPLAY_FILTER:
            PACKETS = pyshark.FileCapture(INF, display_filter=DISPLAY_FILTER)
        else:
            PACKETS = pyshark.FileCapture(INF)
    except:
        print("%s: Failed to open PCAP file: %s."%(sys.arv[0],INF))
        usage()

    # Use services configuration file: TCP, UDP
    config = configparser.ConfigParser()
    try:
        config.read(SERV1)
    except:
        print("%s: Failed to open services configuration file: %s."%(sys.arv[0],SERV1))
    try:
        config.read(SERV2)
    except:
        print("%s: Failed to open services configuration file: %s."%(sys.arv[0],SERV2))

    # Connect to Neo4J Database
    try:
        NEOGRAPH = Graph(password=NEO_PASSWD)
    except:
        print("%s: Failed to connect to Neo4J database."%(sys.arv[0]))
        usage()

    # Storage variables
    host_addrs = {}
    proto_conn_dict = {}

    # Process packets
    for p in PACKETS:
        # New storage for packet source data
        proto_src_dict = {}

        # Check for TCP or UDP layer or continue
        pProto = ''
        tProto = ''
        if 'TCP Layer' in str(p.layers) and TCP:
            pProto = p.tcp
            tProto = 'TCP'
        # UDP Layer test includes avoiding IPv6 packets by checking for IP Layer
        elif 'UDP Layer' in str(p.layers) and 'IP Layer' in str(p.layers) and UDP: 
            pProto = p.udp
            tProto = 'UDP'
        else:
            continue

        # Update host_addrs
        host_keys = list(host_addrs.keys())
        if p.eth.dst not in host_keys: host_addrs[p.eth.dst] = p.ip.dst
        if p.eth.src not in host_keys: host_addrs[p.eth.src] = p.ip.src

        # Check VLAN tag
        dvlan = ''
        vid   = ''
        vtype = ''
        if 'VLAN Layer' in str(p.layers):
            vdata = p['VLAN']
            if 'id' in list(vdata.field_names): vid = str(vdata.id)
            if 'etype' in list(vdata.field_names): vtype = str(vdata.etype)
        if vid: 
            dvlan = vid
            if vtype: dvlan = dvlan + "/" + vtype

        # Prefer ports that are less than 1024 to identify service
        srvport = 0
        if str(pProto.dstport) in config[tProto]: # could cause false flow direction
            srvport = pProto.dstport
            srchost = p.ip.src
            dsthost = p.ip.dst
            dsteth  = p.eth.dst
            srceth  = p.eth.src
        elif str(pProto.srcport) in config[tProto]:
            srvport = pProto.srcport
            srchost = p.ip.dst
            dsthost = p.ip.src
            dsteth  = p.eth.src
            srceth  = p.eth.dst
        elif int(pProto.dstport) < 1024:
            srvport = pProto.dstport
            srchost = p.ip.src
            dsthost = p.ip.dst
            dsteth  = p.eth.dst
            srceth  = p.eth.src
        elif int(pProto.srcport) < 1024: 
            srvport = pProto.srcport
            srchost = p.ip.dst
            dsthost = p.ip.src
            dsteth  = p.eth.src
            srceth  = p.eth.dst
        elif int(pProto.dstport) <= int(pProto.srcport): # if = then could be false direction
            srvport = pProto.dstport
            srchost = p.ip.src
            dsthost = p.ip.dst
            dsteth  = p.eth.dst
            srceth  = p.eth.src
        elif int(pProto.srcport) < int(pProto.dstport):
            srvport = pProto.srcport
            srchost = p.ip.dst
            dsthost = p.ip.src
            dsteth  = p.eth.src
            srceth  = p.eth.dst

        # If port number selected, find a service name
        if srvport:
            if str(srvport) in config[tProto]: 
                nameport = config[tProto][str(srvport)]
            else:
                nameport = p.highest_layer
        else:
            continue

        # Process packet
        proto_conn_keys = list(proto_conn_dict.keys())

        # Check for saved conns to destination
        if srvport not in proto_conn_keys:
            proto_conn_dict[dsthost] = {}

        # Process saved services
        src_keys = list(proto_conn_dict[dsthost].keys())

        if srchost not in src_keys:
            proto_conn_dict[dsthost][srchost] = []
        else:
            # Add VLAN tags, don't stomp
            if proto_conn_dict[dsthost][srchost]['vlan']:
                dvlan = ','.join([dvlan,proto_conn_dict[dsthost][srchost]['vlan']])
        # Save source
        fullproto = tProto + "/" + nameport
        proto_src_dict = {'dstport':srvport,'proto':fullproto,'vlan':dvlan}
        proto_conn_dict[dsthost][srchost].append(proto_src_dict)

processProtocol(host_addrs,proto_conn_dict,NEOGRAPH)
#if UDP:
    #processProtocol(host_addrs,udp_conn_dict,NEOGRAPH,'UDP')
if ICMP:
    processICMP()
if ARP:
    processARP()