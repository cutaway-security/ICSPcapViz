import os,sys
import pyshark
import crcmod.predefined

# User defined PCAP file
inf = sys.argv[1]                                            
packets = pyshark.FileCapture(inf)  

###################
# Globals
###################
DEBUG=False

###################
# Functions
###################
# Check DNP3 CRC Value - Processes data in chunks
def chk_crc(data):
    # TODO: convert this to test the CRC for each chunk and return an error if detected
    # Store the checksum for each chunk to be returned in list
    results = []
    # Prep the DNP3 CRC function
    crcdnp = crcmod.predefined.mkCrcFun('crc-16-dnp')
    # Manage chunk bytes by counting
    dlen = 0
    while dlen < len(data):
        # Grab the next 16 bytes
        r = crcdnp(data[dlen:dlen+16]).to_bytes(2,'little')
        # Store results
        results.append(r)
        if DEBUG: print("chk_crc: Tested %s: %s"%(data[dlen:dlen+16],r))
        # Skip ahead 16 bytes + 2 crc bytes
        dlen += 18
    # Return a list of CRC bytes for testing
    return results

# Process data chunks and remove the CRC bytes
def dnp_data(data):
    # Start a byte array
    results = b''
    # Manage chunk bytes by counting
    dlen = 0 
    while dlen < len(data):
        # Append bytes to byte array
        results += data[dlen:dlen+16]
        # Skip ahead 16 bytes + 2 crc bytes
        dlen += 18
    # Return combined chunk data
    return results

# Process packets and produce a CSV output to assist with data chunk analysis.   
# TODO: Pull out HMAC challenge / response bytes.                            
for p in packets: 
    dnp3_csv_header = "Frame Number,Transport Control,App Layer Code,Function Code,Direction,Combined Data Chunks"
    # Only process DNP3 packets
    if 'DNP3' == p.highest_layer: 
        print("%s,%s,%s,%s,%s->%s,%s"%( 
            p.frame_info.number, # Include packet frame number for reference to Wireshark
            bytes.hex(int(p.dnp3.ctl,16).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
            bytes.hex(int(p.dnp3.al_ctl,16).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
            bytes.hex(int(p.dnp3.al_func).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
            p.dnp3.src,p.dnp3.dst, # DNP3 end point address reference
            bytes.hex(dnp_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:]) # Combine data chunks and remove control bytes / codes
            )
        )