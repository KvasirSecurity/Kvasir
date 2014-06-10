# encoding: utf-8

"""
##--------------------------------------#
## Kvasir
##
## Hping Utilities for Kvasir
##
## Author: Jan Rude
##--------------------------------------#
"""
from gluon import current
from skaldship.log import log
import logging

db = current.globalenv['db']
cache = current.globalenv['cache']
settings = current.globalenv['settings']
session = current.globalenv['session']


##-------------------------------------------------------------------------
def process_file(filename=None, asset_group=None, engineer=None):

    # Upload and process hping Scan file
    from skaldship.hosts import get_host_record, do_host_status, add_or_update

    log(" [*] Processing hping scan file %s" % filename)

    hoststats = 0
    nodefields = {'f_engineer': engineer, 'f_asset_group': asset_group, 'f_confirmed': False}

    svc_db = db.t_services

    host_ip = None
    ICMP_type = ''
    answer_ip = ''

    with open(filename) as f:
        for line in f:
            if "IP: " in line:
                host_ip = line.split()[1]
                if IS_IPADDRESS()(host_ip)[1] == None:
                    nodefields['f_ipaddr'] = host_ip
                    host_rec = add_or_update(nodefields, update=True)
                    hoststats += 1
                else:
                    log(" [!] ERROR: Not a valid IP Address (%s)" % host_ip, logging.ERROR)
            if "[*] " in line:
                ICMP_type = line.split()[1]
            if "ip=" in line:
                ip = line.split('=')[2]
                answer_ip = ip.split()[0]
            if "transmitted" in line:
                packets = line.split()
                if packets[0] == packets[3]:
                    if answer_ip != host_ip:
                        response = T("No")
                    else:
                        response = T("Yes")
                else:
                    response = T("No")
                get_id = get_host_record(host_ip)
                svc_db.update_or_insert(
                    f_hosts_id=get_id.id, f_proto='ICMP', f_number='0', f_status=response, f_name=ICMP_type
                )
                db.commit()
    f.close()
    do_host_status(asset_group=asset_group)
    log(" [*] Import complete, %s hosts added/updated" % hoststats)

