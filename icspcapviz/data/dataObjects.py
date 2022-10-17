import os,sys
import configparser

####################
# Globals
####################
SERV1      = 'data/ieee_services.ini'
SERV2      = 'data/ics_services.ini'
VENDOR_MAC = 'data/wireshark_manuf_reference.txt'

####################
# Lists
####################
# List of words that are associated with vendors
vendor_wordlist = [
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

####################
# Functions
####################
def get_service_references():

    # Create and return configparser object
    config = configparser.ConfigParser()
    try:
        # Pull in default service and port references
        config.read(SERV1)
        # Add and overwrite references with ICS references
        config.read(SERV2)
    except:
        # Return empty string on error
        return ''
    return config

def get_mac_vendors():
    vdict = {}
    try:
        VMAC = open(VENDOR_MAC,'r').readlines()
    except:
        # Return an empty list on error
        print("get_mac_vendor: except: %s"%(os.getcwd()))
        print("get_mac_vendor: except: %s"%(os.path.dirname(os.path.realpath(VENDOR_MAC))))
        return vdict
    # Process each line in file
    for l in VMAC:
        # Remove white space from entries
        l = l.replace('\t',' ').rstrip()
        # Remove empty lines and comments
        if l == '' or l[0] == '#': continue
        vdict[l.split(' ')[0]] = ' '.join(l.split(' ')[1:])

    # Return values
    return vdict