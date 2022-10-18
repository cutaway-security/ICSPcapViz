import crcmod.predefined
import hmac
import hashlib
from alive_progress import alive_bar
from data.dataObjects import *

###################
# Globals
###################
HASH  = hashlib.md5   # Control the hashing method
WHASH = True          # Control hashing the test key or not

###################
# DNP3 Functions
###################
def get_dnp3_chk_crc(inData):
    """
    Function accepts DNP3 packet bytes and splits them into chunks then removes CRC bytes for the chunk.
    Returns a list of CRC bytes for each data chunk.
    """
    # TODO: convert this to test the CRC for each chunk and return an error if check fails
    # Store the checksum for each chunk to be returned in list
    results = []
    # Prep the DNP3 CRC function
    crcdnp = crcmod.predefined.mkCrcFun('crc-16-dnp')
    # Manage chunk bytes by counting
    dlen = 0
    while dlen < len(inData):
        # Grab the next 16 bytes
        r = crcdnp(inData[dlen:dlen+16]).to_bytes(2,'little')
        # Store results
        results.append(r)
        # Skip ahead 16 bytes + 2 crc bytes
        dlen += 18
    # Return a list of CRC bytes for testing
    return results

def get_dnp3_data(inData):
    """
    Process DNP3 data chunks and remove the CRC bytes.
    Return the chunks combined into a byte array.
    """
    # Start a byte array
    results = b''
    # Manage chunk bytes by counting
    dlen = 0 
    while dlen < len(inData):
        # Append bytes to byte array
        results += inData[dlen:dlen+16]
        # Skip ahead 16 bytes + 2 crc bytes
        dlen += 18
    # Return combined chunk data
    return results

def print_dnp3_data_chunks(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object for DNP3 data.
    Return DNP3 data in CSV formatted output to STDOUT
    """
    # Process packets and produce a CSV output to assist with data chunk analysis.   
    dnp3_csv_header = "Frame Number,Transport Control,App Layer Code,Function Code,Direction,Combined Data Chunks"
    print("%s"%(dnp3_csv_header))
    for p in inPackets: 
        # Only process DNP3 packets
        if 'DNP3' == p.highest_layer: 
            print("%s,%s,%s,%s,%s->%s,%s"%( 
                p.frame_info.number, # Include packet frame number for reference to Wireshark
                bytes.hex(int(p.dnp3.ctl,16).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
                bytes.hex(int(p.dnp3.al_ctl,16).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
                bytes.hex(int(p.dnp3.al_func).to_bytes(1,byteorder='big')), # Print byte value as it will appear in Wireshark for easy reference
                p.dnp3.src,p.dnp3.dst, # DNP3 end point address reference
                bytes.hex(get_dnp3_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:]) # Combine data chunks and remove control bytes / codes
                )
            )

def get_dnp3_sav5_hmac(inPackets,wlist):
    """
    Process DNP3 packets, review for Challenge / Responses, and test HMACs against a word list.
    """
    # Parse Packets
    dnp3_sav5 = {}
    unit_id    = ''
    app_ctl    = ''
    dnp3_chall = ''
    dnp3_resp  = ''
    for p in inPackets:
        # Only process DNP3 packets
        if 'DNP3' == p.highest_layer:
            # Test of Auth Response
            if int(p.dnp3.al_func) == 0x83:
                app_ctl = p.dnp3.al_ctl
                # Grab combined chunks
                d = bytes.hex(get_dnp3_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:])
                # Check length to weed out long values (Aggressive Mode?)
                if len(d)/2 == 20:
                    # This should be the challenge token, grab 4 bytes from end
                    dnp3_chall = d[-8:]
                    # Identify the unit
                    unit_id    = p.dnp3.src
            # Test of Auth Request
            if int(p.dnp3.al_func) == 0x20:
                # Test if we have skipped to another transaction, if so, clear things and skip
                if app_ctl != p.dnp3.al_ctl:
                    unit_id    = ''
                    app_ctl    = ''
                    dnp3_chall = ''
                    dnp3_resp  = ''
                    continue
                # Grab combined chunks
                d = bytes.hex(get_dnp3_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:])
                # Check length to weed out long values (Aggressive Mode?)
                if len(d)/2 == 28 and dnp3_chall:
                    # This should be the HMAC hash response, grab 16 bytes from end
                    dnp3_resp = d[-32:]
                    # Save challenge / response for each different unit as the keys might be different per unit
                    if unit_id not in list(dnp3_sav5.keys()): dnp3_sav5[unit_id] = {}
                    dnp3_sav5[unit_id][dnp3_chall] = dnp3_resp
                    # We added a challenge / response to dictionary, so clean variables
                    unit_id    = ''
                    app_ctl    = ''
                    dnp3_chall = ''
                    dnp3_resp  = ''

    # Process each unit by unit_id
    unitkeys = list(dnp3_sav5.keys())
    for uid in unitkeys:
        print("Processing unit %s challenge/responses against %s test keys"%(uid,len(wlist)))
        # Process each unit's challenge and response
        wlkeys = list(dnp3_sav5[uid].keys())
        for chall in wlkeys:
            # Make sure we have both a challenge and a response, else skip
            if not dnp3_sav5[uid][chall]: continue
            print("Testing %s:%s"%(chall,dnp3_sav5[uid][chall]))
            # Show progress with alive_bar, somehow it monitors the for loop processing the wordlist
            with alive_bar(len(wlist)) as bar:
                for w in wlist:
                    # Get rid of newline in case value comes from file
                    w = w.strip()
                    # Hash the wordlist value or just use it
                    if WHASH: 
                        test_val = HASH(w.encode('utf8')).digest()
                    else:
                        # Just use the plain string
                        test_val = w.encode('utf8')
                    hmac_value = hmac.new( test_val, chall.encode('utf8'), HASH )
                    # Test the HMAC and the Response value, stop processing on first success
                    if hmac_value.hexdigest() == dnp3_sav5[uid][chall].encode('utf8'): 
                        print("%s:%s against %s:%s"%('SUCCESS',w,chall,dnp3_sav5[uid][chall]))
                        break
                    bar()
            # Only process one challenge / response per unit
            # TODO: should the user be able to test ALL challenge / response pairs per unit?
            break