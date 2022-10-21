#from _processing_common import get_packets,process_protocols,process_icmp,process_arp,print_json
from _processing_common import *
import _processing_credentials as creds
import _processing_inventory as inven
import _processing_protocols as proto
#from _data_dataObjects import vendor_wordlist,get_service_references,get_mac_vendors
from _data_dataObjects import *

# References for __init__.py TODO: remove
# https://pcarleton.com/2016/09/06/python-init/
# https://github.com/python/cpython/blob/main/Lib/collections/__init__.py
# https://docs.python-guide.org/writing/structure/