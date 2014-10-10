# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2014 Kurt Grutzmacher
##
## Nessus Hosts for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from gluon import current
from gluon.validators import IS_IPADDRESS
from skaldship.hosts import get_host_record
from skaldship.log import log
import logging

try:
    from lxml import etree
except ImportError:
    import sys
    if not sys.hexversion >= 0x02070000:
        raise Exception('python-lxml or Python 2.7 or higher required for Nessus parsing')
    try:
        from xml.etree import cElementTree as etree
    except ImportError:
        try:
            from xml.etree import ElementTree as etree
        except:
            raise Exception('No valid ElementTree parser found')


##-------------------------------------------------------------------------
class NessusHosts:
    def __init__(self, engineer, asset_group, ip_include, ip_exclude, update_hosts):
        self.db = current.globalenv['db']
        self.engineer = engineer
        self.asset_group = asset_group
        self.ip_include = ip_include
        self.ip_exclude = ip_exclude
        self.update_hosts = update_hosts
        self.stats = {
            'added': 0,
            'skipped': 0,
            'updated': 0,
        }

    def parse(self, host_properties):
        """
        Parse out the <HostProperties> xml content or CSV line.

        There can be a number of <tag> entries that are either useful to us in
        t_hosts or other areas. These are processed and returned as dictionary
        entries in 'hostdata'

        :param host_properties: A <HostProperties> section from .nessus or a CSV line
        :returns t_hosts.id, { hostdata }:
        """
        hostdata = {}
        if etree.iselement(host_properties):
            for tag in host_properties.findall('tag'):
                hostdata[tag.get('name')] = tag.text
            ipaddr = hostdata.get('host-ip')
        else:
            # with CSV each line has all the hostdata fields so we set them here for use later
            ipaddr = host_properties.get('IP Address')
            if not ipaddr:
                # Scanner CSV, use Host
                ipaddr = host_properties.get('Host')
            hostdata['mac-address'] = host_properties.get('MAC Address', '')
            hostdata['host-fqdn'] = host_properties.get('DNS Name', '')
            hostdata['netbios-name'] = host_properties.get('NetBIOS Name', '')

        if (ipaddr not in self.ip_include and self.ip_include) or (ipaddr in self.ip_exclude):
            log("Host in exclude or not in include list, skipping")
            self.stats['skipped'] += 1
            return None, {}

        # extra host data
        extradata = {
            'scan_start': host_properties.get('HOST_START', ''),
            'scan_end': host_properties.get('HOST_END', ''),
            'credentialed_scan': host_properties.get('Credentialed_Scan', ''),
            'policy': host_properties.get('policy-used', ''),
            'total_cves': host_properties.get('patch-summary-total-cves', 0),
            'system_type': host_properties.get('system-type', 'Unknown'),
        }

        host_id = get_host_record(ipaddr)
        if host_id and not self.update_hosts:
            return host_id, hostdata, extradata

        # new host found, pull what we need for t_hosts
        hostfields = {}
        hostfields['f_engineer'] = self.engineer
        hostfields['f_asset_group'] = self.asset_group
        hostfields['f_confirmed'] = False

        # check ipv4/ipv6 and set hostfields accordingly
        if IS_IPADDRESS()(ipaddr)[1] is None:
            hostfields['f_ipaddr'] = ipaddr
        else:
            log("Invalid IP Address in HostProperties: %s" % ipaddr, logging.ERROR)
            return None, {}, {}

        # pull out relevant hostfields
        for (k,v) in hostdata.iteritems():
            if k == 'mac-address':
                # multiple mac addrs may appear wildly, just pull the first
                hostfields['f_macaddr'] = v[:v.find('\n')]
            elif k == 'host-fqdn':
                hostfields['f_hostname'] = v
            elif k == 'netbios-name':
                hostfields['f_netbios_name'] = v

        if not self.update_hosts and not host_id:
            result = self.db.t_hosts.validate_and_insert(**hostfields)
            if not result.id:
                log("Error adding host to DB: %s" % result.errors, logging.ERROR)
                return None, {}, {}
            self.stats['added'] += 1
            host_id = result.id
            log(" [-] Adding host: %s" % ipaddr)
        elif self.update_hosts:
            if hostfields['f_ipaddr']:
                self.db(self.db.t_hosts.f_ipaddr == hostfields['f_ipaddr']).update(**hostfields)
                self.db.commit()
                host_id = get_host_record(hostfields['f_ipaddr'])
                if host_id:
                    host_id = host_id.id
                log(" [-] Updating IP: %s" % (hostfields['f_ipaddr']))
                self.stats['updated'] += 1

        return host_id, hostfields, extradata

