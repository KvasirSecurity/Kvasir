# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Hydra password functions
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from skaldship.passwords.utils import lookup_hash
from skaldship.log import log
import logging

##-------------------------------------------------------------------------
def process_hydra(line):
    """
    Process a hydra line and return a dictionary:

    { 'ip'  : ip address
      'port': port info - can be port # or module name
      'user': username,
      'pass': password,
      'hash': ntlm hash if smbnt hash used
      'msg' : status message
    }
    """
    # line: [22][ssh] host: 1.1.1.1   login: username   password: pw1234
    retval = {}
    try:
        data = line.split()
    except Exception, e:
        log("Error processing hydra line: %s -- %s" % (e, line), logging.ERROR)
        return retval

    if data[1] == "host:":
        # these fields are always there.. sometimes password is not
        retval['port'] = data[0][1:data[0].find("]")]
        retval['ip'] = data[2]
        retval['user'] = data[4]

        if "password:" not in data:
            # no password provided, adjust the field modulator cap'n
            retval['pass'] = None
            if len(data) == 6:
                retval['msg'] = data[5]
        else:
            retval['pass'] = data[6]
            if len(data) == 8:
                retval['msg'] = data[7]

        # handle specific SMB errors:
        #if "[smb]" in data and "Error:" in data:

        if len(retval['pass']) == 68 and retval['pass'][65:68] == ":::":
            # we have an ntlm hash cap'n
            retval['hash'] = ":".join(retval['pass'].split(':')[:2])
            retval['pass'] = lookup_hash(retval['hash'])
            retval['type'] = 'smb'
        else:
            retval['type'] = 'cleartext'
            retval['hash'] = None

    retval['error'] = False
    return retval


##-------------------------------------------------------------------------
def _doctest():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _doctest()
