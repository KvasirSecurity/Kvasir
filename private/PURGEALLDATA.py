#!/usr/bin/env python
# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## PURGE ALL THE DATA
##
## Run from a shell using web2py.
##
## ./web2py.py -R applications/$appname/private/PURGEALLDATA.py -S $appname -M -A -y -k
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-y', action='store_true', required=True, help='YES, purge it!')
parser.add_argument('-k', action='store_true', default=True, help='Keep user table')
options = parser.parse_args()

if options.y:
    if not options.k:
        db.auth_user.truncate(mode="CASCADE")
    
    db.t_hosts.truncate(mode="CASCADE")
    db.t_services.truncate(mode="CASCADE")
    db.t_os.truncate(mode="CASCADE")
    db.t_host_os_refs.truncate(mode="CASCADE")
    db.t_apps.truncate(mode="CASCADE")
    db.t_services_apps_refs.truncate(mode="CASCADE")
    db.t_service_vulns.truncate(mode="CASCADE")
    db.t_service_info.truncate(mode="CASCADE")
    db.t_accounts.truncate(mode="CASCADE")
    db.t_host_notes.truncate(mode="CASCADE")
    db.t_evidence.truncate(mode="CASCADE")
    db.t_snmp.truncate(mode="CASCADE")
    db.t_vulndata.truncate(mode="CASCADE")
    db.commit()
