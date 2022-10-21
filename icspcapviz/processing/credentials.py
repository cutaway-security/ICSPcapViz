###################
# HTTP Basic Auth Functions
###################
# TBD

###################
# SNMP Basic Auth Functions
###################
# TBD

###################
# Kerberos Basic Auth Functions
###################
# TBD

###################
# FTP Basic Auth Functions
###################
# TBD

###################
# NTLMSSP Functions
###################
ntlm_auth_filter = '(ntlmssp.messagetype == 0x00000002) || (ntlmssp.messagetype == 0x00000003)'

def get_ntlmssp_creds(inPackets):
    """
    Analyze a pyshark.capture.file_capture.FileCapture object filtered using ntlm_auth_filter.
    Return a dictionary of NTLMSSP challenge and responses.
    Dictionary key is smb.uid or dcerpc.cn_call_id and values are 'username','hostname','ntlmserverchallenge','ntproof','ntresponse'.
    """
    # Main Processing
    auths = {}
    for p in inPackets:
        # Determine if packet is SMB or RPC
        try:
            if 'SMB Layer' in str(p.layers):
                p_layer = 'SMB'
                # Use UID to track session
                auth_attempt = p.smb.uid
                mess_type    = int(p.smb.ntlmssp_messagetype,16)
            elif 'DCERPC' in str(p.layers):
                p_layer = 'DCERPC'
                # User Call ID to track session
                auth_attempt = p.dcerpc.cn_call_id
                mess_type    = int(p.dcerpc.ntlmssp_messagetype,16)
            else:
                # No SMB or DCERPC so carry on
                continue
        except:
            # Error, carry on
            continue

        # Challenge and Response Fields: https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol
        # Process Server Challenge     
        if (mess_type == 0x00000002):
            if (auth_attempt not in list(auths.keys())): 
                auths[auth_attempt] = {'username':'','hostname':'','ntlmserverchallenge':'','ntproof':'','ntresponse':''}
            if p_layer == 'SMB':
                auths[auth_attempt]['ntlmserverchallenge'] = p.smb.ntlmssp_ntlmserverchallenge.replace(':','')
            if p_layer == 'DCERPC':
                auths[auth_attempt]['ntlmserverchallenge'] = p.dcerpc.ntlmssp_ntlmserverchallenge.replace(':','')
        
        # Process Client Response
        if (mess_type == 0x00000003):
            if (auth_attempt not in list(auths.keys())):
                continue
            if p_layer == 'SMB':
                auths[auth_attempt]['username']   = p.smb.ntlmssp_auth_username
                auths[auth_attempt]['hostname']   = p.smb.ntlmssp_auth_hostname
                nt_resp                           = p.smb.ntlmssp_auth_ntresponse.replace(':','')
            if p_layer == 'DCERPC':
                auths[auth_attempt]['username']   = p.dcerpc.ntlmssp_auth_username
                auths[auth_attempt]['hostname']   = p.dcerpc.ntlmssp_auth_hostname
                nt_resp                           = p.dcerpc.ntlmssp_auth_ntresponse.replace(':','')
            # Some responses are garbage, length is a good test for issues
            if len(nt_resp) < 48: 
                del auths[auth_attempt]
                continue
            auths[auth_attempt]['ntproof']        = nt_resp[:32]
            auths[auth_attempt]['ntresponse']     = nt_resp[32:]
    return auths

def print_ntlmssp_creds(inAuths):
    """
    Print NTLMSSP credential dump results in PWDUMP format for hashcat
    hashcat --force -m 5600 hashes_pyshark.txt rockyou.txt
    hashcat --force -m 5600 --show hashes_pyshark.txt
    """
    for a in inAuths.keys():
        auth = inAuths[a]
        print("%s::%s:%s:%s:%s"%(auth['username'],auth['hostname'],auth['ntlmserverchallenge'],auth['ntproof'],auth['ntresponse']))