#!/usr/bin/env python3
import os,sys,re
import pyshark
from py2neo import Graph, Node, Relationship

####################
# Globals
####################
SEPERATOR  = "==================================="
DEBUG      = False
INF        = False
PACKETS    = False
NEOGRAPH   = False
TCP        = True 
UDP        = False
ICMP       = False
ARP        = False
WIN        = False
ALL        = False
NEO_PASSWD = 'admin'

####################
# FUNCTIONS
####################
def usage():
    print("%s [-h] [-d] [-n int] [-l int] [-s int] [-m] [-M list] [-e] [-z] [-f <binary file>]"%(sys.argv[0]))
    print("    -h: This is it.")
    print("    -d: Turn on debugging.  Default: off")
    print("    -f <pcap>: pcap file that contains the data. Required")
    print("    -p: <passwd>: Neo4J password Default: admin. Yes, this will be in your shell history.")
    print("    -t: Process TC) packets. Default: True")
    print("    -u: Process UDP packets. Default: False")
    print("    -i: Process ICMP packets. Default: False [NOT IMPLEMENTED]")
    print("    -a: Process ARP packets. Default: False [NOT IMPLEMENTED]")
    print("    -w: Process Windows packets. Default: False")
    print("    -e: Disable ignoring packets based on protocol and ports. Default: False")
    print("        Warning, some packets are ignored to improve data flow representations.")
    print("")
    print("Be sure to start your Neo4J database. Read README for guideance.")
    print("")
    print("Processing PCAPs can take time. Be patient.")
    print("Yes, you can write a progress bar and submit a pull request.")
    sys.exit()

def processTCP(inData,inGraph):
    # TCP Process each server application as s
    for dst in list(inData.keys()):
        s = Node("Host", name=str(dst))
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node("Host",name=str(src))
            for conn in inData[dst][src]:
                SENDtcp = Relationship.type(str(conn['proto']) + " " + str(conn['dstport']) + "/TCP")
                # client is the source, so it goes first
                inGraph.merge(SENDtcp(c, s), "Host", "name")

def processUDP(inData,inGraph):
    # UDP Process each server application as s
    for dst in list(inData.keys()):
        s = Node("Host", name=str(dst))
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node("Host",name=str(src))
            for conn in inData[dst][src]:
                SENDudp = Relationship.type(str(conn['proto']) + " " + str(conn['dstport']) + "/UDP")
                # client is the source, so it goes first
                inGraph.merge(SENDudp(c, s), "Host", "name")

def processICMP():
    print("%s: ICMP is not implemented.")
    usage() # NOT IMPLEMENTED

def processARP():
    print("%s: ARP is not implemented.")
    usage() # NOT IMPLEMENTED

if __name__ == "__main__":

    ops = ['-h','-d','-f', '-p', '-t', '-u', '-i', '-a', '-w', '-e']
    if len(sys.argv) < 2:
        usage()

    while len(sys.argv) > 1:
        op = sys.argv.pop(1)
        if op == '-h':
            usage()
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
        if op == '-w':
            WIN = True
        if op == '-e':
            ALL = True
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

    # Connect to Neo4J Database
    try:
        NEOGRAPH = Graph(password=NEO_PASSWD)
    except:
        print("%s: Failed to connect to Neo4J database."%(sys.arv[0]))
        usage()

    ####################
    # Control variables
    ####################
    if not ALL:
        # Ignore Protocols - used to manage parsing and reduce node clutter
        ## '_WS.MALFORMED' because data is error or duplicate
        ## 'TCP' if this is the highest layer, then it is an ACK or FIN
        tcp_ignore_protos = ['_WS.MALFORMED','TCP']
        ## 'DHCPV6' because this can produce noise and might be assessment system
        ## 'SSDP' discover protocol
        ## 'LLMNR' discover protocol
        udp_ignore_protos = ['_WS.MALFORMED','DHCPV6','SSDP','LLMNR']
        # Ignore ports - avoid normal IT traffic that will clutter diagrams
        ignore_ports  = []
        if not WIN:
            tcp_ignore_protos.extend(['SMB','SMB2','NBSS'])
            ignore_ports.extend([137,139,445])
        # Expected ports - helps to label industrial protocols correctly
        # Note: these are the names used by Wireshark to identify the protocol
        expected_dst_ports = {'CIP':[44818],'CIPCM':[44818],'COTP':[102],'MODBUS':[502],'S7COMM':[102],'SSL':[443,8443,3389],'TDS':[1433]}
        expected_dst_protos = {102:['S7COMM','COTP'],502:['MODBUS'],1433:['TDS'],3389:['SSL'],44818:['CIP','CIPCM']}

    # Storage variables
    udp_conn_dict = {}
    tcp_conn_dict = {}

    # Process packets
    for p in PACKETS:
        # New storage for packet source data
        tcp_src_dict = {}
        udp_src_dict = {}

        # Check for TCP layer or continue
        if 'TCP Layer' in str(p.layers):
            # Skip things we don't want
            ## Skip packet errors and known bypassible protocols
            if p.highest_layer in tcp_ignore_protos: 
                #print("Rejecting: %s"%(p.highest_layer))
                continue
            ## Skip non-industrial protocol traffic
            if p.tcp.srcport in ignore_ports or p.tcp.dstport in ignore_ports: continue
            ## Force destination port to weed out responses
            if p.highest_layer in list(expected_dst_ports.keys()):
                if not (int(p.tcp.dstport) in expected_dst_ports[p.highest_layer]): 
                    #print("Rejecting: %s Port: %s"%(p.highest_layer,p.tcp.dstport))
                    continue 

            # Process packet
            tcp_conn_keys = list(tcp_conn_dict.keys())
            # Check for saved conns to destintation
            if p.ip.dst not in tcp_conn_keys:
                tcp_conn_dict[p.ip.dst] = {}
            dst_keys = list(tcp_conn_dict[p.ip.dst].keys())
            if p.ip.src not in dst_keys:
                tcp_conn_dict[p.ip.dst][p.ip.src] = []
            # Save source
            tcp_src_dict = {'srcport':p.tcp.srcport,'dstport':p.tcp.dstport,'proto':p.highest_layer}
            # Skip if we have already recorded this type of connection
            if tcp_src_dict not in tcp_conn_dict[p.ip.dst][p.ip.src]:
                # Skip if we have similar srcport and dstport combinations
                sim_conns = False
                for e in tcp_conn_dict[p.ip.dst][p.ip.src]:
                    if (tcp_src_dict['srcport'] == e['srcport'] and tcp_src_dict['dstport'] == e['dstport']) or (tcp_src_dict['srcport'] == e['dstport'] and tcp_src_dict['dstport'] == e['srcport']):
                        sim_conns = True
                        # Test for higher layer protocol than TCP
                        if e['proto'] == 'TCP' and not (tcp_src_dict['proto'] == e['proto']):
                            e['proto'] = tcp_src_dict['proto']
                if not sim_conns: 
                    tcp_conn_dict[p.ip.dst][p.ip.src].append(tcp_src_dict)

        # Check for UDP layer or continue
        if 'UDP Layer' in str(p.layers):       # Process
            # Skip things we don't want
            ## Skip packet errors and known bypassible protocols
            if p.highest_layer in udp_ignore_protos or 'IPV6 Layer' in p.layers: 
                #print("Rejecting: %s"%(p.highest_layer))
                continue
            ## Skip broadcast addresses
            if re.search(".255$",p.ip.dst):
                continue

            # Process packet
            udp_conn_keys = list(udp_conn_dict.keys())
            # Check for saved conns to destintation
            if p.ip.dst not in udp_conn_keys:
                udp_conn_dict[p.ip.dst] = {}
            dst_keys = list(udp_conn_dict[p.ip.dst].keys())
            if p.ip.src not in dst_keys:
                udp_conn_dict[p.ip.dst][p.ip.src] = []
            # Save source
            udp_src_dict = {'srcport':p.udp.srcport,'dstport':p.udp.dstport,'proto':p.highest_layer}
            # Skip if we have already recorded this type of connection
            if udp_src_dict not in udp_conn_dict[p.ip.dst][p.ip.src]:
                # Skip if we have similar srcport and dstport combinations
                sim_conns = False
                for e in udp_conn_dict[p.ip.dst][p.ip.src]:
                    if (udp_src_dict['srcport'] == e['srcport'] and udp_src_dict['dstport'] == e['dstport']) or (udp_src_dict['srcport'] == e['dstport'] and udp_src_dict['dstport'] == e['srcport']):
                        sim_conns = True
                        # Test for higher layer protocol than TCP
                        if e['proto'] == 'TCP' and not (udp_src_dict['proto'] == e['proto']):
                            e['proto'] = udp_src_dict['proto']
                if not sim_conns: 
                    udp_conn_dict[p.ip.dst][p.ip.src].append(udp_src_dict)

if TCP:
    processTCP(tcp_conn_dict,NEOGRAPH)
if UDP:
    processUDP(udp_conn_dict,NEOGRAPH)
if ICMP:
    processICMP()
if ARP:
    processARP()