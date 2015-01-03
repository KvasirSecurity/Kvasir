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
## Backup/Restore Kvasir database as CSV
##
## Run from a shell using web2py.
##
## Export:
##   ./web2py.py -R applications/$appname/private/db_csv.py -S $appname -M -A -e $appname.csv.gz
##
## Import:
##   ./web2py.py -R applications/$appname/private/db_csv.py -S $appname -M -A -i <filename>
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

import sys
import re
import gzip
from optparse import OptionParser
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO


##--------------------------------------------------------------------

optparser = OptionParser(version=__version__)

optparser.add_option("-i", "--import", dest="infile",
    action="store", default=None, help="Import CSV file")
optparser.add_option("-W", "--wipe", dest="wipe",
    action="store_true", default=False, help="Wipe any existing DB data")
optparser.add_option("-e", "--export", dest="export",
    action="store", default=False, help="Export to CSV file")
optparser.add_option("-g", "--gzip", dest="gzip",
    action="store_true", default=False, help="GZip Compression")

(options, params) = optparser.parse_args()

if options.export:
    if options.gzip or options.export.endswith('.gz'):
        of = gzip.open(options.export, 'wb')
    else:
        of = open(options.export, 'wb')
    db.export_to_csv_file(of)
    of.close()

elif options.infile:
    fname = options.infile
    if options.wipe:
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
        db.commit()

        if fname.endswith('.gz'):
            fobj = gzip.open(fname, 'rb')
        else:
            fobj = open(fname, 'rb')

        db.import_from_csv_file(fobj)

else:
    optparser.print_help()
