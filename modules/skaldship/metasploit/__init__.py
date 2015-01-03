# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir Skaldship Metasploit Module Library
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

__all__ = ["msf_get_config", "pro"]

from gluon import current


##-------------------------------------------------------------------------
def msf_get_config(session=None):
    """
    Returns a dict of metasploit configuration settings based on yaml or session
    """

    msf_config = current.globalenv['settings']['kvasir_config'].get('metasploit') or {}

    config = {
        'key': session.get('msf_key', msf_config.get('api_key')),
        'url': session.get('msf_url', msf_config.get('url', 'https://localhost:3790')),
        'msfrpcd': (session.get('msf_rpcd'), msf_config.get('msfrpcd', 'ssl://msf:msf@localhost:55553/')),
        'ws_num': session.get('msf_workspace_num', 1), 'workspace': session.get('msf_workspace', 'default'),
        'user': session.get('msf_user', None)
    }

    return config
