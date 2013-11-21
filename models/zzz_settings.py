# -*- coding: utf-8 -*-

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Global settings which are not dependent for initial setup
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

import socket

settings.title = 'Kvasir'
settings.subtitle = 'Beware of evil dwarves'

# Customer information for XML Report generator
settings.customer = settings.kvasir_config.get('customer', '')
settings.assessment_type = settings.kvasir_config.get('assessment_type', '')
settings.start_date = settings.kvasir_config.get('start_date', '')
settings.end_date = settings.kvasir_config.get('end_date', '')

# Global display / HTML
settings.author = 'Cisco Systems Security Posture Assessment Team'
settings.author_email = 'kvasirdevs@external.cisco.com'
settings.keywords = ''
settings.description = ''

# Authentication.
login = settings.kvasir_config.get('login', {})
settings.login_method = login.get('method', 'local')
settings.login_config = login.get('config', '')
del login

# CVSS or Severity
settings.use_cvss = settings.kvasir_config.get('use_cvss', False)

# Password upload default directory ($APPNAME/data/passwords/misc)
settings.password_upload_dir = settings.kvasir_config.get('password_upload_dir', 'data/passwords/misc')

# Launch command
settings.launch_command = settings.kvasir_config.get(
    'launch_command',
    "xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e script _LOGFILE_"
)

# Nmap
nmap_config = settings.kvasir_config.get('nmap', {})
settings.nmap_binary = nmap_config.get('binary', '/usr/local/bin/nmap')
settings.nmap_sharedir = nmap_config.get('sharedir', '/usr/local/share/nmap')
settings.nmap_scriptdir = nmap_config.get('scriptdir', '/usr/local/share/nmap/scripts')
settings.nmap_nselibdir = nmap_config.get('nselibdir', '/usr/local/share/nmap/nselib')
del nmap_config

# ShodanHQ
settings.shodanhq_apikey = settings.kvasir_config.get('shodanhq_api_key', '')

# web2py scheduler
settings.scheduler_group_name = settings.kvasir_config.get('scheduler_group_name', socket.gethostname())
settings.scheduler_timeout = settings.kvasir_config.get('scheduler_timeout', 3600)   # 1 hour timeout default
