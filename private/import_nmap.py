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
## Import Nmap scan from the command line for Kvasir
##
## Run from a shell using web2py:
##
## ./web2py.py -R applications/$appname/private/import_nmap.py -S $appname -M -A -f filename -g asset_group -e engineer 
##
## Author: Edward Zaborowski
##--------------------------------------#
"""

import sys, time
import getpass
from optparse import OptionParser, OptionGroup
from skaldship.metasploit import msf_get_config

# #--------------------------------------------------------------------

optparser = OptionParser(version=__version__)

optparser.add_option("-f", "--filename", dest="filename",
                     action="store", default=None, help="Nmap XML filename")
optparser.add_option("-g", "--group", dest="asset_group",
                     action="store", default="default", help="Asset group to assign hosts (default: 'default')")
optparser.add_option("-e", "--engineer", dest="engineer",
                     action="store", default=getpass.getuser(), help="User to import data.")
optparser.add_option("-n", "--noports", dest="noports",
                     action="store_true", default=False, help="Add hosts without ports.")
optparser.add_option("-u", "--update", dest="update_hosts",
                     action="store_true", default=False, help="Update hosts.")
optparser.add_option("-m", "--msfidx", dest="msfidx",
                     action="store", default=0, help="Metasploit workspace index")

(options, params) = optparser.parse_args()

rows = db(db.auth_user.username == options.engineer)

if rows.count() != 1:
    exit("An error was encountered when selecting a user. Please try with a valid user name.")

msf_settings = msf_get_config(session)

msf_workspaces = [None]

try:
    # check to see if we have a Metasploit RPC instance configured and talking
    from MetasploitProAPI import MetasploitProAPI

    msf_api = MetasploitProAPI(host=msf_settings['url'], apikey=msf_settings['key'])
    working_msf_api = msf_api.login()
except:
    working_msf_api = False

if working_msf_api:
    for w in msf_api.pro_workspaces().keys():
        msf_workspaces.append(w)

try:
    msf_workspace = msf_workspaces[int(options.msfidx)]
except IndexError:
    exit("An invalid workspace index has been provided. Aborting.")

msf_settings = {'workspace': msf_workspace, 'url': msf_settings['url'], 'key': msf_settings['key']}

task_vars = dict(
    scanner='nmap',
    filename=options.filename,
    addnoports=options.noports,
    asset_group=options.asset_group,
    engineer="%s" % rows.select().first().id,
    msf_settings=msf_settings,
    ip_ignore_list=[],
    ip_include_list=[],
    update_hosts=options.update_hosts
)

task = scheduler.queue_task(
    scanner_import,
    pvars=task_vars,
    group_name=settings.scheduler_group_name,
    sync_output=5,
    timeout=settings.scheduler_timeout,
    immediate=True
)

if task.id:
    db.commit()
    exit('Success (%s).' % task.id)
else:
    exit('Error submitting job: %s' % (task.errors))
