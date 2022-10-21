#!/usr/bin/env python3
import os,sys
import argparse
from py2neo import Graph, Node, Relationship
from processing.common import * 
from data.dataObjects import *
from alive_progress import alive_bar

####################
# Globals
####################
PACKETS    = False

####################
# FUNCTIONS
####################
def usage(parser,message=''):
    if message: print("%s ERROR: %s"%(sys.argv[0],message))
    print("")
    parser.print_help(sys.stderr)
    print("")
    sys.exit()

####################
# MAIN PROCESSING
####################
if __name__ == "__main__":

    # Process user arguments
    parser = argparse.ArgumentParser(description='Analyze network packet captures and map hosts.')
    parser.add_argument('-d','--debug', action='store_true', help='Print debugging statements')
    parser.add_argument('-v','--version', action='store_true', help='Print version')
    parser.add_argument('-f', '--file', dest='pcapname', nargs='?', default='', metavar='PCAP', help='Path to network packet capture file')
    parser.add_argument('-j','--json', dest='jsondir', nargs='?', default='', help='Path to directory to write JSON files', metavar='JSONDIR')
    parser.add_argument('-p','--neopasswd', dest='neopasswd', default='admin', help='Password for Neo4J database (Default: admin)', metavar='ADMIN')
    parser.add_argument('-t','--tcp', action='store_false', help='Disable processing TCP packets')
    parser.add_argument('-u','--udp', action='store_true', help='Enable processing UDP packets')
    parser.add_argument('-a','--arp', action='store_true', help='Enable processing ARP packets')
    parser.add_argument('-i','--icmp', action='store_true', help='Enable processing ICMP packets')
    parser.add_argument('-n','--nodename', dest='nodename', nargs='?', default='Host', metavar='NODENAME', help='Names for nodes in Neo4j (Default: Host)')
    parser.add_argument('-F','--filter', dest='displayfilter', nargs='?', default='', metavar='DISPLAY_FILTER', help='Wireshark / Tshark display filter')

    # Object for user arguments
    args = parser.parse_args()

    # Test Version
    if args.version:
        version(sys.argv[0])

    # Test PCAP File
    if not args.pcapname: usage(parser,message="No PCAP filename provided.")
    if not os.path.exists(args.pcapname):
        usage(parser,message="PCAP file does not exist: %s"%(args.pcapname))
    try:
        PACKETS = get_packets(args.pcapname,inFilter=args.displayfilter)
    except:
        usage(parser,message="Failed to process PCAP file: %s."%(args.pcapname))

    # Use services configuration file: TCP, UDP
    config = ''
    config = get_service_references()
    if not config:
        usage(parser,message="Failed to open services configuration files.")

    # Vendor MAC Information
    vdict = {}
    vdict = get_mac_vendors()
    if not vdict:
        usage(parser,message="Failed to open interface vendor hardware address reference file.")

    # Storage variables
    host_addrs = {}
    proto_conn_dict = {}

    # Process packets
    with alive_bar(len(PACKETS)) as bar:
        # Double time from alive_bar stats to get actual processing time, packets processed twice
        for p in PACKETS:
            # New storage for packet source data
            proto_src_dict = {}

            # Check for TCP or UDP layer or continue
            pProto = ''
            tProto = ''
            if 'TCP Layer' in str(p.layers) and args.tcp:
                pProto = p.tcp
                tProto = 'TCP'
            # UDP Layer test includes avoiding IPv6 packets by checking for IP Layer
            elif 'UDP Layer' in str(p.layers) and 'IP Layer' in str(p.layers) and args.udp: 
                pProto = p.udp
                tProto = 'UDP'
            else:
                continue

            # Update host_addrs
            host_keys  = list(host_addrs.keys())
            vdict_keys = list(vdict.keys())
            vdst, vsrc = '',''
            if p.eth.dst[0:8].upper() in vdict_keys: vdst = vdict[p.eth.dst[0:8].upper()]
            if p.eth.src[0:8].upper() in vdict_keys: vsrc = vdict[p.eth.src[0:8].upper()]
            if p.eth.dst not in host_keys: host_addrs[p.eth.dst] = [p.ip.dst, vdst]
            if p.eth.src not in host_keys: host_addrs[p.eth.src] = [p.ip.src, vsrc]

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
            if dsthost not in proto_conn_keys:
                proto_conn_dict[dsthost] = {}

            # Process saved services
            src_keys = list(proto_conn_dict[dsthost].keys())

            if srchost not in src_keys:
                proto_conn_dict[dsthost][srchost] = []

            # Review stored Service ports and update
            noSrvDst = True
            for srvDst in proto_conn_dict[dsthost][srchost]:
                if srvDst['dstport'] == str(srvport):
                    noSrvDst = False
                    # Add VLAN tags, don't stomp
                    if srvDst['vlan']:
                        dvlan = ','.join([dvlan,srvDst['vlan']])
                        break

            # Service port not detected, add new
            if noSrvDst:
                # Save source
                fullproto = tProto + "/" + nameport
                proto_src_dict = {'dstport':srvport,'proto':fullproto,'vlan':dvlan}
                proto_conn_dict[dsthost][srchost].append(proto_src_dict)
            
            bar()

    # Output JSON data to selected location
    if args.jsondir:
        if os.path.exists(args.jsondir):
            presults = print_json(args.jsondir,args.pcapname,proto_conn_dict,host_addrs)
            if presults:
                usage(parser,message=presults)

    # Connect to Neo4J Database
    try:
        neo_graph = Graph(password=args.neopasswd)
    except:
        usage(parser,message="Failed to connect to Neo4J database.")

    process_protocols(host_addrs,proto_conn_dict,neo_graph,args.nodename)
