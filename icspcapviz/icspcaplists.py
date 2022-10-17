#!/usr/bin/env python3
import os,sys
import argparse
from processing.common import * 
from data.dataObjects import *

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
    parser.add_argument('-f', '--file', dest='pcapname', nargs='?', default=sys.stdin, required=True, metavar='PCAP', help='Path to network packet capture file')
    parser.add_argument('-c','--filter', dest='displayfilter', nargs='?', default='', metavar='DISPLAY_FILTER', help='Wireshark / Tshark display filter')

    # Object for user arguments
    args = parser.parse_args()

    # Test PCAP File
    if not os.path.exists(args.pcapname):
        usage(parser,message="PCAP file does not exist: %s"%(args.pcapname))
    try:
        PACKETS = get_packets(args.pcapname,inFilter=args.displayfilter)
    except:
        usage(parser,message="Failed to process PCAP file: %s."%(args.pcapname))