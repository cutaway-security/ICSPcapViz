import os,sys
import datetime
import json
import pyshark
from py2neo import Graph, Node, Relationship


MAJOR_VER  = '1'
MINOR_VER  = '1.0'
VERSION    = '.'.join([MAJOR_VER,MINOR_VER])
SEPERATOR  = "==================================="

##################
# Utility Functions
##################

def version(inName):
    print("%s: %s"%(inName,VERSION))
    sys.exit()

def get_key_by_value(data, val):
    # Expect IP and vendor information in data
    keys = data.keys()
    for k in keys:
        if data[k][0] == val:
            return [str(data[k][0]),str(data[k][1])]
    return '',''

##################
# Processing Functions
##################

# Get packets from the PCAP file
def get_packets(inFile,inFilter=''):
    """
    Read a PCAP file and return a pyshark.capture.file_capture.FileCapture object
    """

    if inFilter: 
        return pyshark.FileCapture(inFile, display_filter=inFilter) 
    else:   
        return pyshark.FileCapture(inFile)


# Process TCP / UDP packets
def process_protocols(inHosts,inData,inGraph,inNodeName):
    # Process each server application as s
    for dst in list(inData.keys()):
        s = Node(inNodeName, name=str(dst))
        s['ethaddr'],s['vendor'] = get_key_by_value(inHosts,dst)
        dstSubnet=str(dst).split('.')
        s['subnetA'] = str(dstSubnet[0])
        s['subnetB'] = str('.'.join([dstSubnet[0],dstSubnet[1]]))
        s['subnetC'] = str('.'.join([dstSubnet[0],dstSubnet[1],dstSubnet[2]]))
        s['vlan'] = ''
        # Process each client talking to an application as c
        for src in list(inData[dst].keys()):
            c = Node(inNodeName,name=str(src))
            c['ethaddr'],c['vendor'] = get_key_by_value(inHosts,src)
            srcSubnet=str(dst).split('.')
            c['subnetA'] = str(srcSubnet[0])
            c['subnetB'] = str('.'.join([srcSubnet[0],srcSubnet[1]]))
            c['subnetC'] = str('.'.join([srcSubnet[0],srcSubnet[1],srcSubnet[2]]))    
            for conn in inData[dst][src]:
                c['vlan'] = str(conn['vlan'])
                if not s['vlan']: s['vlan'] = str(conn['vlan'])
                if conn['vlan']:
                    SENDtcp = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']) + "/VLAN:" + str(conn['vlan']))
                else:
                    SENDtcp = Relationship.type(str(conn['proto']) + "/" + str(conn['dstport']))
                # client is the source, so it goes first
                inGraph.merge(SENDtcp(c, s), inNodeName, 'name')

# Process ICMP packets
def process_icmp():
    return("ICMP is not implemented.")

# Process ARP packets
def process_arp():
    return("ICMP is not implemented.")

##################
# Printing Functions
##################

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