import os,sys
import pyshark
import crcmod.predefined
import hmac
import hashlib
from alive_progress import alive_bar

###################
# Globals
###################
DEBUG = False
HASH  = hashlib.md5   # Control the hashing method
WHASH = True          # Control hashing the test key or not
# Default wordlist of common words, in case user doesn't provide list
wlist = [
    'ge','Ge','GE',
    'habitat','Habitat','HABITAT',
    'schneider','Schneider','SCHNEIDER','SE',
    'siemens','Siemens','SIEMENS',
    'rockwell','Rockwell','ROCKWELL',
    'allenbradley','AllenBradley','ALLENBRADLEY','allen-bradley','Allen-Bradley','ALLEN-BRADLEY','abb','Abb','ABB',
    'token','Token','TOKEN',
    'secret','Secret','SECRET',
    'secure','Secure','SECURE',
    'hmac','Hmac','HMAC',
    'private','Private','PRIVATE',
    'private!','Private!','PRIVATE!',
    'admin','Admin','ADMIN','administrator','Administrator','ADMINISTRATOR'
]

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

###################
# Main Processing
###################

# User defined PCAP file
inf = sys.argv[1]
# Check if user provided external word list
if len(sys.argv) > 2:              
    wnf = sys.argv[2]
    wlist   = open(wnf,'r').readlines()

# Get Packets      
packets = pyshark.FileCapture(inf)  

# Parse Packets
dnp3_sav5 = {}
unit_id    = ''
app_ctl    = ''
dnp3_chall = ''
dnp3_resp  = ''
for p in packets:
    # Only process DNP3 packets
    if 'DNP3' == p.highest_layer:
        # Test of Auth Response
        if int(p.dnp3.al_func) == 0x83:
            app_ctl = p.dnp3.al_ctl
            # Grab combined chunks
            d = bytes.hex(dnp_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:])
            # Check length to weed out long values (Aggressive Mode?)
            if len(d)/2 == 20:
                # This should be the challenge token, grab 4 bytes from end
                if DEBUG: print("%s Challenge: %s"%(p.frame_info.number,d[-8:]))
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
            d = bytes.hex(dnp_data(bytes.fromhex(p.tcp.payload.replace(':',''))[10:-2])[3:])
            # Check length to weed out long values (Aggressive Mode?)
            if len(d)/2 == 28 and dnp3_chall:
                # This should be the HMAC hash response, grab 16 bytes from end
                if DEBUG: print("%s Response: %s"%(p.frame_info.number,d[-32:]))
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
                if DEBUG: print("    Trying %s: %s"%(w,hmac_value.hexdigest()))
                bar()
        # Only process one challenge / response per unit
        # TODO: should the user be able to test ALL challenge / response pairs per unit?
        break