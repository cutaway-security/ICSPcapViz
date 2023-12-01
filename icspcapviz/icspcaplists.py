#!/usr/bin/env python3
import os,sys
import argparse
from processing.common import * 
import processing.credentials as creds
import processing.protocols as proto
import processing.inventory as inven
import processing.entropy as entropy
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
    parser.add_argument('-f', '--file', dest='pcapname', nargs='?', default='', required=True, metavar='PCAP', help='Path to network packet capture file')
    parser.add_argument('-w', '--wordlist', dest='wordlist', nargs='?', default='', metavar='WORDLIST', help='Path to file with list of words for passwords')
    parser.add_argument('-F','--filter', dest='displayfilter', nargs='?', default='', metavar='DISPLAY_FILTER', help='Wireshark / Tshark display filter')
    parser.add_argument('-c','--creds', dest='creds', nargs='?', choices=['all','ntlm','http','kerberos'], default='', const='all', help='Locate and print output for credentials. Choices: \'all\': Default, run all modules. \'ntlm\': process ntlmssp module. \'http\': process HTTP Basic Auth module. \'kerberos\': process kerberos module.')
    parser.add_argument('-p','--protos', dest='protos', nargs='?', choices=['all','dnp3data','dnp3sav5'], default='', const='all', help='Locate and print output for ICS protocols. Choices: \'all\': Default, process all ICS protocol modules. \'dnp3data\': process DNP3 data module to show data chunks. \'dnp3sav5\': process DNP3 SAv5 module to list Secure Authentication version 5 challenge and response in PWDump format.')
    parser.add_argument('-i','--inventory', dest='inven', nargs='?', choices=['all','protocols','hardware','services','raw'], default='', const='all', help='Locate and print output for ICS protocols. Choices: \'all\': Default, process all inventory modules. \'protocols\': list all protocols. \'hardware\': list all hardware addresses and IP addresses. \'services\': list all services with IP addresses. \'raw\': show raw bytes for packets with unknown data.')
    parser.add_argument('-e','--entropy', dest='entropy', nargs='?', choices=['all','entropy','histogram'], default='', const='all', help='Locate and print output for ICS protocols. Choices: \'all\': Default, process all inventory modules. \'entropy\': show entropy values for packets with unknown data to detect encryption or compression. \'histogram\': show histogram for values from packets to detect plain text, encrypted, or compressed data.')

    # Object for user arguments
    args = parser.parse_args()

    # Test PCAP File
    if not os.path.exists(args.pcapname):
        usage(parser,message="PCAP file does not exist: %s"%(args.pcapname))
    try:
        PACKETS = get_packets(args.pcapname,inFilter=args.displayfilter)
    except:
        usage(parser,message="Failed to process PCAP file: %s."%(args.pcapname))

    ###############################
    # Process credentials found in the PCAP.
    # Modules: ntlm,http,kerberos
    ###############################
    if args.creds:
        # Process NTLM SSP credentials
        if args.creds == 'ntlm' or args.creds == 'all':
            ntlm_auths = {}
            ntlm_auths = creds.get_ntlmssp_creds(PACKETS)
            if ntlm_auths: 
                print("%s"%(SEPERATOR))
                print("# NTLM SSP authentication challenge / response in PWDump Format - remove comment lines.")
                print("%s"%(SEPERATOR))
                creds.print_ntlmssp_creds(ntlm_auths)
                print()
        # Process NTLM SSP credentials
        if args.creds == 'http' or args.creds == 'all':
            print("%s"%(SEPERATOR))
            print("# HTTP Basic Auth - NOT IMPLEMENTED.")
            print("%s"%(SEPERATOR))
            print()
        # Process NTLM SSP credentials
        if args.creds == 'kerberos' or args.creds == 'all':
            print("%s"%(SEPERATOR))
            print("# Kerberos authentication - NOT IMPLEMENTED.")
            print("%s"%(SEPERATOR))
            print()

    ###############################
    # Process ICS protocols found in the PCAP.
    # Modules: dnp3data,dnp3sav5
    ###############################
    if args.protos:
        # Process DNP3 Data Chunks module
        if args.protos == 'dnp3data' or args.protos == 'all':
            print("%s"%(SEPERATOR))
            print("# DNP3 Data Chunks")
            print("%s"%(SEPERATOR))
            proto.print_dnp3_data_chunks(PACKETS)
            print()
        # Process DNP3 Secure Authentication v5 module
        if args.protos == 'dnp3sav5' or args.protos == 'all':
            word_list = vendor_wordlist
            if args.wordlist:
                try:
                    word_list = get_file(args.wordlist)
                except:
                    pass
            print("%s"%(SEPERATOR))
            print("# Process DNP3 SAv5 Challenge / Responses to identify HMAC secret")
            print("%s"%(SEPERATOR))
            proto.get_dnp3_sav5_hmac(PACKETS,word_list)
            print()

    ###############################
    # Generate inventory lists from communications found in the PCAP.
    # Modules: protocols,hardware,services,raw,entropy
    ###############################
    if args.inven:
        # Print protocols module
        if args.inven == 'protocols' or args.inven == 'all':
            print("%s"%(SEPERATOR))
            print("# List of Protocols")
            print("%s"%(SEPERATOR))
            print("Protocols: %s"%(','.join(inven.get_protocols(PACKETS))))
            print()
        # Print hardware addresses with IPs module
        if args.inven == 'hardware' or args.inven == 'all':
            print("%s"%(SEPERATOR))
            print("# Hardware addresses with IP addresses.")
            print("%s"%(SEPERATOR))
            print_dictionary_list(inven.get_hardware_addresses(PACKETS))
            print()
        # Print protocols module
        if args.inven == 'services' or args.inven == 'all':
            print("%s"%(SEPERATOR))
            print("# List of services with host IP addresses")
            print("%s"%(SEPERATOR))
            print_dictionary_list(inven.get_target_lists(PACKETS))
            print()
        # Print raw bytes module
        '''
        if args.inven == 'raw' or args.inven == 'all':
            print("%s"%(SEPERATOR))
            print("# Print raw bytes for packets with unknown data")
            print("%s"%(SEPERATOR))
            inven.print_unknown_raw(PACKETS)
            print()
        '''

    ###############################
    # Generate entropy lists from communications found in the PCAP.
    # Modules: entropy,histogram
    ###############################
    if args.entropy:
        # Print entropy of raw bytes module
        if args.entropy == 'entropy' or args.entropy == 'all':
            print("%s"%(SEPERATOR))
            print("# Print entropy of raw bytes for packets")
            print("%s"%(SEPERATOR))
            entropy.print_entropy(PACKETS)
            print()
        
        # Print histogram of raw bytes module
        if args.entropy == 'histogram' or args.entropy == 'all':
            print("%s"%(SEPERATOR))
            print("# Print entropy of raw bytes for packets")
            print("%s"%(SEPERATOR))
            entropy.print_histogram(PACKETS)
            print()