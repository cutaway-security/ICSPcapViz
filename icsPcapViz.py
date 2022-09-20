#!/usr/bin/env python3
import os,sys,re
import configparser
import pyshark
from py2neo import Graph, Node, Relationship

####################
# Globals
####################
MAJOR_VER  = '0'
MINOR_VER  = '2.0'
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

####################
# FUNCTIONS
####################
def usage():
    print("%s: %s"%(sys.argv[0],VERSION))
    print("")
    print("%s [-h] [-d] [-n int] [-l int] [-s int] [-m] [-M list] [-e] [-z] [-f <binary file>]"%(sys.argv[0]))
    print("    -h: This is it.")
    print("    -v: version info.")
    print("    -d: Turn on debugging. Default: off")
    print("    -f <pcap>: pcap file that contains the data. Required")
    print("    -p: <passwd>: Neo4J password Default: admin. Yes, this will be in your shell history.")
    print("    -t: Process TCP packets. Default: True")
    print("    -u: Process UDP packets. Default: False")
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

# Process TCP packets
def processTCP(inHosts,inData,inGraph):
    # TCP Process each server application as s
    for dst in list(inData.keys()):
        if DEBUG: print('IP: %s Eth: %s'%(dst,getKeyByVal(inHosts,dst)))
        s = Node("Host", name=str(dst))
        s['ethaddr'] = str(getKeyByVal(inHosts,dst))
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node("Host",name=str(src))
            c['ethaddr'] = str(getKeyByVal(inHosts,src))
            for conn in inData[dst][src]:
                c['vlan']    = str(conn['vlan'])
                if DEBUG: print('c[dvlan]: %s'%(c['vlan']))
                if conn['vlan']:
                    SENDtcp = Relationship.type(str(conn['proto']) + " " + str(conn['dstport']) + "/TCP/VLAN:" + str(conn['vlan']))
                else:
                    SENDtcp = Relationship.type(str(conn['proto']) + " " + str(conn['dstport']) + "/TCP")
                # client is the source, so it goes first
                inGraph.merge(SENDtcp(c, s), "Host", "name")

# Process UDP packets
def processUDP(inHosts,inData,inGraph):
    # UDP Process each server application as s
    for dst in list(inData.keys()):
        s = Node("Host", name=str(dst))
        #s['ethaddr'] = getKeyByVal(inHosts,dst)
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node("Host",name=str(src))
            #c['ethaddr'] = getKeyByVal(inHosts,src)
            for conn in inData[dst][src]:
                SENDudp = Relationship.type(str(conn['proto']) + " " + str(conn['dstport']) + "/UDP")
                # client is the source, so it goes first
                inGraph.merge(SENDudp(c, s), "Host", "name")

# Process ICMP packets
def processICMP():
    print("%s: ICMP is not implemented.")
    usage() # NOT IMPLEMENTED

# Process ARP packets
def processARP():
    print("%s: ARP is not implemented.")
    usage() # NOT IMPLEMENTED

if __name__ == "__main__":

    ops = ['-h','-d','-f', '-p', '-t', '-u', '-i', '-a', '-v']
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
        if op not in ops:
            usage()

    # Test PCAP File
    if not INF:
        usage()
    try:
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
    udp_conn_dict = {}
    tcp_conn_dict = {}

    # Process packets
    for p in PACKETS:
        # New storage for packet source data
        tcp_src_dict = {}
        udp_src_dict = {}

        # Check for TCP layer or continue
        if 'TCP Layer' in str(p.layers):
            # Update host_addrs
            host_keys = list(host_addrs.keys())
            if p.eth.dst not in host_keys: host_addrs[p.eth.dst] = p.ip.dst
            if p.eth.src not in host_keys: host_addrs[p.eth.src] = p.ip.src
            # Prefer ports that are less than 1024 to identify service
            srvport = 0
            if str(p.tcp.dstport) in config['TCP']: # could cause false flow direction
                srvport = p.tcp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif str(p.tcp.srcport) in config['TCP']:
                srvport = p.tcp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst
            elif int(p.tcp.dstport) < 1024:
                srvport = p.tcp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif int(p.tcp.srcport) < 1024: 
                srvport = p.tcp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst
            elif int(p.tcp.dstport) <= int(p.tcp.srcport): # if = then could be false direction
                srvport = p.tcp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif int(p.tcp.srcport) < int(p.tcp.dstport):
                srvport = p.tcp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst

            
            # If port number selected, find a service name
            if srvport:
                if str(srvport) in config['TCP']: 
                    nameport = config['TCP'][str(srvport)]
                else:
                    nameport = p.highest_layer
            else:
                if DEBUG: print("Packet not selected: %s"%(str(p.layers)))
                continue

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

            # Process packet
            tcp_conn_keys = list(tcp_conn_dict.keys())
            # Check for saved conns to destination
            if srvport not in tcp_conn_keys:
                tcp_conn_dict[dsthost] = {}
            src_keys = list(tcp_conn_dict[dsthost].keys())
            if srchost not in src_keys:
                tcp_conn_dict[dsthost][srchost] = []
            # Save source
            tcp_src_dict = {'dstport':srvport,'proto':nameport,'vlan':dvlan}
            tcp_conn_dict[dsthost][srchost].append(tcp_src_dict)

        # Check for UDP layer or continue, check IP later to skip IPv6
        if 'UDP Layer' in str(p.layers) and 'IP Layer' in str(p.layers):
            # Update host_addrs
            host_keys = list(host_addrs.keys())
            if p.eth.dst not in host_keys: host_addrs[p.eth.dst] = p.ip.dst
            if p.eth.src not in host_keys: host_addrs[p.eth.src] = p.ip.src
            # Prefer ports that are less than 1024 to identify service
            srvport = 0
            if str(p.udp.dstport) in config['UDP']: # could cause false flow direction
                srvport = p.udp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif str(p.udp.srcport) in config['UDP']:
                srvport = p.udp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst
            elif int(p.udp.dstport) < 1024:
                srvport = p.udp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif int(p.udp.srcport) < 1024: 
                srvport = p.udp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst
            elif int(p.udp.dstport) <= int(p.udp.srcport): # if = then could be false direction
                srvport = p.udp.dstport
                srchost = p.ip.src
                dsthost = p.ip.dst
                dsteth  = p.eth.dst
                srceth  = p.eth.src
            elif int(p.udp.srcport) < int(p.udp.dstport):
                srvport = p.udp.srcport
                srchost = p.ip.dst
                dsthost = p.ip.src
                dsteth  = p.eth.src
                srceth  = p.eth.dst

            # If port number selected, find a service name
            if srvport:
                if str(srvport) in config['UDP']: 
                    nameport = config['UDP'][str(srvport)]
                else:
                    nameport = p.highest_layer
            else:
                continue

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

            # Process packet
            udp_conn_keys = list(udp_conn_dict.keys())
            # Check for saved conns to destination
            if srvport not in udp_conn_keys:
                udp_conn_dict[dsthost] = {}
            src_keys = list(udp_conn_dict[dsthost].keys())
            if srchost not in src_keys:
                udp_conn_dict[dsthost][srchost] = []
            # Save source
            udp_src_dict = {'dstport':srvport,'proto':nameport,'vlan':dvlan}
            udp_conn_dict[dsthost][srchost].append(udp_src_dict)

if TCP:
    processTCP(host_addrs,tcp_conn_dict,NEOGRAPH)
if UDP:
    processUDP(host_addrs,udp_conn_dict,NEOGRAPH)
if ICMP:
    processICMP()
if ARP:
    processARP()