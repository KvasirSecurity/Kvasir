#!/usr/bin/env python
# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Import Nmap scan from the command line for Kvasir
##
## Run from a shell using web2py:
##
## ./web2py.py -R applications/$appname/private/import_nmap.py -S $appname -M -A -f filename -g asset_group -e engineer 
##
## Author: Edward Zaborowski
##--------------------------------------#
"""

import sys
import getpass
from optparse import OptionParser, OptionGroup

##--------------------------------------------------------------------

optparser = OptionParser(version=__version__)

optparser.add_option("-f", "--filename", dest="filename",
  action="store", default=None, help="Nmap XML filename")
optparser.add_option("-g", "--group", dest="group",
  action="store", default=None, help="Asset group for imported hosts")
optparser.add_option("-e", "--engineer", dest="engineer",
  action="store", default=None, help="Name of importing engineer")
  
(options, params) = optparser.parse_args()

msf_settings = msf_get_config(session)

msf_settings = {'workspace': None, 'url': msf_settings['url'], 'key': msf_settings['key']}

task = scheduler.queue_task(
  scanner_import,
  pvars=dict(
    scanner='nmap',
    filename=filename,
    addnoports=False,
    asset_group=group,
    engineer=engineer,
    msf_settings=msf_settings,
    ip_ignore_list=[],
    ip_include_list=[],
    update_hosts=True
  ),
  group_name=settings.scheduler_group_name,
  sync_output=5,
  timeout=settings.scheduler_timeout
)

if task.id:
  exit('Success.')
else:
  exit('Error submitting job: %s' % (task.errors))
  
  
  


