# encoding: utf-8

"""
##--------------------------------------#
## Kvasir
##
## Hping2 Utilities for Kvasir
##
## Author: Jan RUde
##--------------------------------------#
"""
from gluon import current
from skaldship.log import log
import logging

db = current.globalenv['db']
cache = current.globalenv['cache']
settings = current.globalenv['settings']
session = current.globalenv['session']

def process_file(
    filename=None,
    asset_group=None,
    engineer=None,
    ):
    # Upload and process hping Scan file
    import re
    import os
    from skaldship.hosts import get_host_record, do_host_status

    log(" [*] Processing hping2 scan file %s" % (filename))

    # parse the hosts, where all the goodies are
    #log(" [-] Parsing %d hosts" % (len(nmap_parsed.hosts)))
    hoststats = {}
    hoststats['added'] = 0
    hoststats['updated'] = 0
    hosts = []   # array of host_id fields

    nodefields = {}
    nodefields['f_engineer'] = engineer
    nodefields['f_asset_group'] = asset_group
    nodefields['f_confirmed'] = False

    svc_db = db.t_services
    query = db(db.t_hosts).select(db.t_hosts.f_ipv4, db.t_hosts.id)
    
    host_ip = ''
    ICMP_type = ''
    response = ''
    answer_ip = ''
    comment = ''

    with open(filename) as f:
        for line in f:
            if "IP: " in line:
                host_ip = line.split()[1]
                get_id = db(db.t_hosts.f_ipv4==host_ip).select(db.t_hosts.id).first()
                if get_id:
                    log(" [-] Updating Host %s" %(host_ip))
                    hoststats['updated'] += 1
                else:
                    log(" [-] Adding Host %s" %(host_ip))
                    db.t_hosts.insert(f_ipv4=host_ip, **nodefields)
                    db.commit()
                    hoststats['added'] += 1
            if "[*] " in line:
                ICMP_type = line.split()[1]
            if "ip=" in line:
                ip = line.split('=')[2]
                answer_ip = ip.split()[0]
            if "transmitted" in line:
                packets = line.split()
                if packets[0] == packets[3]:
                    if answer_ip != host_ip:
                        response = "Ja, von: %s" %(answer_ip)
                    else:
                        response = "Ja"
                else:
                    response = "Nein"
                get_id = db(db.t_hosts.f_ipv4==host_ip).select(db.t_hosts.id).first()
                svc_db.update_or_insert(f_hosts_id=get_id.id, f_proto='ICMP', f_number='0', f_status=response, f_name=ICMP_type)
                db.commit()
    f.close()
    log(" [*] Import complete: hosts: %s added, %s updated" % (hoststats['added'], hoststats['updated']))

##-------------------------------------------------------------------------