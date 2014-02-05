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
import platform
import os

try:
    import yaml
    from yaml.parser import ParserError
except ImportError:
    raise ImportError('PyYAML required. Please install it before continuing')

from gluon.storage import Storage
settings = Storage()

settings.kvasir_config = {}
kv_cfg_filename = os.path.join(os.environ.get('HOME'), '.kvasir', 'kvasir.yaml')
try:
    settings.kvasir_config = yaml.load(open(kv_cfg_filename, 'r'))
except IOError, e:
    kv_cfg_filename = os.environ.get('KVASIR_CONFIG', 'kvasir.yaml')
    try:
        settings.kvasir_config = yaml.load(open(kv_cfg_filename, 'r'))
    except IOError, e:
        kv_cfg_filename = os.path.join('applications', request.application, 'kvasir.yaml')
        try:
            settings.kvasir_config = yaml.load(open(kv_cfg_filename, 'r'))
        except IOError, e:
            raise IOError('Unable to load kvasir.yaml configuration. Please place it in $HOME/.kvasir or your application directory')
except yaml.parser.ParserError, e:
    raise yaml.parser.ParserError('Error parsing %s: %s' % (kv_cfg_filename, str(e)))

settings.kv_yaml_file = kv_cfg_filename

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

# Scheduler
settings.scheduler_group_name = settings.kvasir_config.get('scheduler_group_name', socket.gethostname())
settings.scheduler_timeout = settings.kvasir_config.get('scheduler_timeout', 3600)   # 1 hour timeout default

# Launch command
settings.launch_command = settings.kvasir_config.get('launch_command', None)
if not settings.launch_command:
    # set default launch_command based on running OS
    platform_system = platform.system()
    if platform_system == 'Darwin':
        settings.launch_command = "osascript terminal.scpt _IP_ _DATADIR_ _LOGFILE_"
    elif platform_system == 'Linux':
        settings.launch_command = "gnome-terminal --window -t 'manual hacking: _IP_' -e 'script _LOGFILE_'"
    else:
        settings.launch_command = "xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e script _LOGFILE_"

# Nmap
nmap_config = settings.kvasir_config.get('nmap', {})
settings.nmap_binary = nmap_config.get('binary', '/usr/local/bin/nmap')
settings.nmap_sharedir = nmap_config.get('sharedir', '/usr/local/share/nmap')
settings.nmap_scriptdir = nmap_config.get('scriptdir', '/usr/local/share/nmap/scripts')
settings.nmap_nselibdir = nmap_config.get('nselibdir', '/usr/local/share/nmap/nselib')
del nmap_config

# ShodanHQ
settings.shodanhq_apikey = settings.kvasir_config.get('shodanhq_api_key', '')

# pwnwiki.github.io
settings.pwnwiki_path = settings.kvasir_config.get('pwnwiki_path', None)

# exploitdb
settings.exploitdb_path = settings.kvasir_config.get('exploitdb_path', None)

