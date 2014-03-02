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

import sys,time
import getpass
from optparse import OptionParser, OptionGroup
from skaldship.general import check_datadir
from skaldship.metasploit import msf_get_config

##--------------------------------------------------------------------

optparser = OptionParser(version=__version__)

optparser.add_option("-f", "--filename", dest="filename",
  action="store", default=None, help="Nmap XML filename")
  
(options, params) = optparser.parse_args()

msf_settings = msf_get_config(session)

msf_settings = {'workspace': None, 'url': msf_settings['url'], 'key': msf_settings['key']}

task_vars = dict(
    scanner='nmap',
    filename=options.filename,
    addnoports=False,
    asset_group="automatic",
    engineer="1",
    msf_settings=msf_settings,
    ip_ignore_list=[],
    ip_include_list=[],
    update_hosts=True
  )

task = scheduler.queue_task(
  scanner_import,
  pvars=task_vars,
  group_name=settings.scheduler_group_name,
  sync_output=5,
  timeout=settings.scheduler_timeout,
  immediate=True
)

db.commit()

if task.id:
  print task_vars
  print task
  exit('Success (%s).' % task.id)
else:
  exit('Error submitting job: %s' % (task.errors))
  
  
  


