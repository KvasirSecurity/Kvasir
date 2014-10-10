# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2014 Kurt Grutzmacher
##
## Nessus Plugin parser for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

import re


##-------------------------------------------------------------------------
class NessusPlugins():
    """
    Class for Nessus Plugin parsing
    """

    def __init__(self):
        """
        Nothing here.
        """
        pass

    def plugin_10264(self, plugin_output):
        for snmp in re.findall(' - (.*)', plugin_output):
            db.t_snmp.update_or_insert(f_hosts_id=host_id, f_community=snmp)
            db.commit()
        return


##-------------------------------------------------------------------------
def main():
    pass

if __name__ == '__main__':
    main()
