import os,sys
import datetime
import json
import pyshark
from py2neo import Graph, Node, Relationship

MAJOR_VER  = '1'
MINOR_VER  = '1.1'
VERSION    = '.'.join([MAJOR_VER,MINOR_VER])
SEPERATOR  = "##############################"
# ICS packets are small, this will be a best guess
AVG_PACKET_SIZE = 170

##################
# Utility Functions
##################

def version(inName):
    print("%s: %s"%(inName,VERSION))
    sys.exit()

# Expected Data format == {'eth addr': ['vendor info',[ip addrs]]}
def get_eth_by_ip(data, val):
    # Expect IP and vendor information in data
    keys = data.keys()
    for k in keys:
        # Loop through values
        if val in data[k][1]:
            return k
    return ''

##################
# Processing Functions
##################

# Get packets from the PCAP file
def get_packets(inFile,inFilter=''):
    """
    Read a PCAP file and return a pyshark.capture.file_capture.FileCapture object
    """
    if inFilter: 
        packets = pyshark.FileCapture(inFile, display_filter=inFilter) 
    else:   
        packets = pyshark.FileCapture(inFile)
    return packets

# Get lines from a file
def get_file(inFile):
    """
    Read a file and return list after removing newlines and spaces.
    Does not catch exceptions. 
    """
    lines = open(inFile,'r').readlines()
    for e in range(len(lines)):
        lines[e] = lines[e].strip()
    return lines

# Process TCP / UDP packets
def process_protocols(inHosts,inData,inGraph,inNodeName):
    # Process each server application as s
    for dst in list(inData.keys()):
        shost_eth = ''
        s = Node(inNodeName, name=str(dst))
        shost_eth = get_eth_by_ip(inHosts,dst)
        print('shost %s: %s'%(dst,shost_eth))
        if inHosts[shost_eth][1]:
            s['ethaddr'],s['vendor'] = str(shost_eth),inHosts[shost_eth][0]
        else:
            s['ethaddr'],s['vendor'] = str(shost_eth),''
        dstSubnet=str(dst).split('.')
        s['subnetA'] = str(dstSubnet[0])
        s['subnetB'] = str('.'.join([dstSubnet[0],dstSubnet[1]]))
        s['subnetC'] = str('.'.join([dstSubnet[0],dstSubnet[1],dstSubnet[2]]))
        s['vlan'] = ''
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            chost_eth = ''
            c = Node(inNodeName,name=str(src))
            chost_eth = get_eth_by_ip(inHosts,src)
            print('chost %s: %s'%(src,chost_eth))
            if inHosts[chost_eth][1]:
                c['ethaddr'],c['vendor'] = str(chost_eth),inHosts[chost_eth][0]
            else:
                c['ethaddr'],c['vendor'] = str(chost_eth),''
            srcSubnet=str(dst).split('.')
            c['subnetA'] = str(srcSubnet[0])
            c['subnetB'] = str('.'.join([srcSubnet[0],srcSubnet[1]]))
            c['subnetC'] = str('.'.join([srcSubnet[0],srcSubnet[1],srcSubnet[2]]))    
            for conn in inData[dst][src]:
                c['vlan'] = str(conn['vlan'])
                if not s['vlan']: s['vlan'] = str(conn['vlan'])
                if conn['vlan']:
                    setRel = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']) + "/VLAN:" + str(conn['vlan']))
                else:
                    setRel = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']))
                # client is the source, so it goes first
                inGraph.merge(setRel(c, s), inNodeName, 'name')

# Process ICMP packets
def process_icmp():
    return("ICMP is not implemented.")

# Process ARP packets
def process_arp():
    return("ICMP is not implemented.")

##################
# Printing Functions
##################
def print_dictionary_list(inDict):
    """
    Print interface information
    TODO: Update to include vendor names
    """
    for e in inDict.keys(): 
        if inDict[e]: 
            print("%s: %s"%(e,','.join(inDict[e]))) 

def print_json(inJson,inFile,inProtos,inHosts):

    curr_time = datetime.datetime.now().strftime("%Y%m%d%H%M")
    # Output connections to JSON
    conn_json = inJson + '/' + inFile.split('/')[-1].split('.')[0] + '_connections_' + curr_time + '.json'
    try:
        jconns = open(conn_json,'w')   
        jconn_object = json.dumps(inProtos, indent = 4) 
        jconns.write(jconn_object)
        jconns.close()
    except:
        return "Failed to open protocol JSON file for writing, %s."%(conn_json)
    # Output hosts to JSON
    host_json = inJson + '/' + inFile.split('/')[-1].split('.')[0] + '_hosts_' + curr_time + '.json'
    try:
        jhosts = open(host_json,'w')   
        jhost_object = json.dumps(inHosts, indent = 4) 
        jhosts.write(jhost_object)
        jhosts.close()
    except:
        return "Failed to open hosts JSON file for writing, %s."%(conn_json)
    # Return empty string on success
    return ''