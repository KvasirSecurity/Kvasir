# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Metasploit password functions
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from .utils import lookup_hash


##-------------------------------------------------------------------------
def process_msfcsv(line):
    """
    Process a metasploit creds output csv file and returns a dictionary. Looks up hash values if provided.

    :param line: Line from a metasploit creds csv file
    :return: {'ip': ipaddress, 'port': port, 'user': username, 'pass': password, 'hash': ntlm_hash, 'msg': message}

    >>> process_msfcsv()
    """
    # host,port,user,pass,type,active?
    retval = {}
    hash_types = ['smb', 'rakp_hmac_sha1_hash', 'smb_challenge']
    import csv
    for data in csv.reader([line]):
        retval['ip'] = data[0]
        retval['port'] = data[1]
        retval['user'] = data[2]
        retval['pass'] = data[3]
        retval['type'] = data[4]
        retval['msg'] = 'from metasploit'
        # isactive = data[5] # unused

    if retval['type'] in hash_types:
        retval['hash'] = retval['pass']
        retval['pass'] = lookup_hash(retval['hash'])
    else:
        retval['hash'] = None

    retval['error'] = False
    return retval


##-------------------------------------------------------------------------
def _doctest():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _doctest()

"""
Metasploit creds testing:

creds add-ntlm bob aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 contosso
creds add-password frank p455w0rd
ssh-keygen -f /tmp/temp_rsa
creds add-ssh-key bob /tmp/temp_rsa
"""
