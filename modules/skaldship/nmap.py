# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## nMap Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""
from gluon import current
from skaldship.log import log
import logging

db = current.globalenv['db']
cache = current.globalenv['cache']
auth = current.globalenv['auth']
settings = current.globalenv['settings']
session = current.globalenv['session']

##-------------------------------------------------------------------------


def script_metadata():
    """
    Load nmap script metadata into a dictionary
    """
    try:
        from zenmapCore_Kvasir.ScriptMetadata import get_script_entries
    except ImportError, e:
        return dict(error="Cannot load zenmap python library: %s" % (e))

    scr_mdata = get_script_entries(settings.nmap_scriptdir, settings.nmap_nselibdir)
    scripts = {}
    for scr in scr_mdata:
        scripts[scr.filename] = {
            'usage': scr.usage,
            'description': scr.description,
            'arguments': scr.arguments,
            'categories': scr.categories,
            'author': scr.author,
            'output': scr.output,
            'url': scr.url,
        }
    return scripts

##-------------------------------------------------------------------------


def process_xml(
    filename=None,
    addnoports=False,
    asset_group=None,
    engineer=None,
    msf_workspace=False,
    ip_ignore_list=None,
    ip_include_list=None,
    update_hosts=False,
    ):
    # Upload and process nMap XML Scan file
    import re
    import os
    from skaldship.general import get_host_record, do_host_status
    from skaldship.cpe import lookup_cpe
    from zenmapCore_Kvasir.NmapParser import NmapParser

    # output regexes
    RE_NETBIOS_NAME = re.compile('NetBIOS computer name: (?P<d>.*),')
    RE_NETBIOS_WORKGROUP = re.compile('Workgroup: (?P<d>.*),')
    RE_NETBIOS_MAC = re.compile('NetBIOS MAC: (?P<d>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))')

    # build the hosts only/exclude list
    ip_exclude = []
    if ip_ignore_list:
        ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    ip_only = []
    if ip_include_list:
        ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    log(" [*] Processing nMap scan file %s" % (filename))

    nmap_parsed = NmapParser()
    nmap_parsed.parse_file(filename)

    #existing_vulnids = db(db.t_vulndata()).select(db.t_vulndata.id, db.t_vulndata.f_vulnid).as_dict(key='f_vulnid')

    # parse the hosts, where all the goodies are
    log(" [-] Parsing %d hosts" % (len(nmap_parsed.hosts)))
    hoststats = {}
    hoststats['added'] = 0
    hoststats['skipped'] = 0
    hoststats['updated'] = 0
    hoststats['errored'] = 0
    hosts = []   # array of host_id fields

    svc_db = db.t_services
    for node in nmap_parsed.hosts:
        nodefields = {}

        if node.ipv6:
            ipaddr = node.ipv6
            nodefields['f_ipv4'] = ipaddr
        elif node.ip.get('type') == 'ipv4':
            ipaddr = node.ip.get('addr')
            nodefields['f_ipv4'] = ipaddr
        else:
            log(" [!] No IPv4/IPv6 address, skipping")
            continue

        try:
            nodefields['f_macaddr'] = node.mac['addr']
        except TypeError:
            nodefields['f_macaddr'] = None

        status = node.state

        log(" [-] Host %s status is: %s" % (ipaddr, status))
        if status != "up":
            hoststats['skipped'] += 1
            continue

        if ipaddr in ip_exclude:
            log(" [-] Host is in exclude list... skipping")
            hoststats['skipped'] += 1
            continue

        if len(ip_only) > 0 and ipaddr not in ip_only:
            log(" [-] Host is not in the only list... skipping")
            hoststats['skipped'] += 1
            continue

        if not node.ports and not addnoports:
            log(" [-] No ports open and not asked to add those kind... skipping")
            hoststats['skipped'] += 1
            continue

        # we'lll just take the last hostname in the names list since it'll usually be the full dns name
        for name in node.hostnames:
            nodefields['f_hostname'] = name['hostname']

        nodefields['f_engineer'] = engineer
        nodefields['f_asset_group'] = asset_group
        nodefields['f_confirmed'] = False

        # see if host exists, if so update. if not, insert!
        query = (db.t_hosts.f_ipv4 == ipaddr) | (db.t_hosts.f_ipv6 == ipaddr)
        host_rec = db(query).select().first()

        if host_rec is None:
            host_id = db.t_hosts.insert(**nodefields)
            db.commit()
            hoststats['added'] += 1
            log(" [-] Adding %s" % (ipaddr))
        elif host_rec is not None and update_hosts:
            db.commit()
            if 'f_ipv4' in nodefields:
                host_id = db(db.t_hosts.f_ipv4 == nodefields['f_ipv4']).update(**nodefields)
            else:
                host_id = db(db.t_hosts.f_ipv6 == nodefields['f_ipv6']).update(**nodefields)
            db.commit()
            host_id = get_host_record(ipaddr)
            host_id = host_id.id
            hoststats['updated'] += 1
            log(" [-] Updating %s" % (ipaddr))
        else:
            hoststats['skipped'] += 1
            db.commit()
            log(" [-] Skipped %s" % (ipaddr))
            continue
        hosts.append(host_id)

        # process non-port <hostscript> entries. Add to info/0:
        for hostscripts in node.hostscripts:
            query = (svc_db.f_proto == 'info') & (svc_db.f_number == 0) & (svc_db.f_hosts_id == host_id)
            svc_id = db.t_services.update_or_insert(query, f_proto='info', f_number=0, f_status='open', f_hosts_id=host_id)
            if not svc_id:
                svc_rec = db(query).select(cache=(cache.ram, 180)).first()
                if svc_rec:
                    svc_id = svc_rec.id
                else:
                    log(" [!] Service record wasn't created", logging.ERROR)
                    continue

            db.commit()
            for script in hostscripts:
                script_id = script.id
                output = script.output
                db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=script_id, f_text=output)
                db.commit()

                if script_id == 'nbstat':
                    # pull out NetBIOS info from nbstat output
                    result = RE_NETBIOS_MAC.search(output)
                    if 'd' in result.groupdict():
                        host_rec.update(f_macaddr=result.group('d'))
                        db.commit()
                    result = RE_NETBIOS_NAME.search(output)
                    if 'd' in result.groupdict():
                        host_rec.update(f_netbios_name=result.group('d'))
                        db.commit()
                    result = RE_NETBIOS_WORKGROUP.search(output)
                    if 'd' in result.groupdict():
                        db(db.t_netbios.update_or_insert(f_hosts_id=host_id, f_domain=result.group('d')))
                        db.commit()

        # add ports and resulting vulndata
        for port in node.ports:
            f_proto = port.get('protocol')
            f_number = port.get('portid')
            f_status = port.get('port_state')
            f_name = port.get('service_name')
            f_product = port.get('service_product')

            log(" [-] Adding port: %s/%s (%s)" % (f_proto, f_number, f_name))
            svc_id = db.t_services.update_or_insert(f_proto=f_proto, f_number=f_number, f_status=f_status, f_hosts_id=host_id, f_name=f_name)

            if f_product:
                version = port.get('service_version')
                if version:
                    f_product += " (%s)" % (version)
                db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=f_name, f_text=f_product)
                db.commit()

            # Process <script> service entries
            for script in port.get('scripts'):
                db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=script.get('id'), f_text=script.get('output'))
                db.commit()

            # Process <cpe> service entries
            port_cpe = port.get('service_cpe')
            if port_cpe:
                cpe_id = port_cpe.lstrip('cpe:/')

                if cpe_id.startswith('a'):
                    # process CPE Applications
                    #log(" [-] Found Application CPE data: %s" % (cpe_id))
                    db.t_service_info.update_or_insert(f_services_id=svc_id, f_name='cpe.app', f_text="cpe:/%s" % (cpe_id))
                    db.commit()

                elif cpe_id.startswith('o'):
                    # process CPE Operating System

                    os_id = lookup_cpe(cpe_id[2:])

                    if os_id is not None:
                        db.t_host_os_refs.insert(f_certainty='0.9',
                                                 f_family='Unknown',
                                                 f_class='Other',
                                                 f_hosts_id=host_id,
                                                 f_os_id=os_id)
                        db.commit()
                    else:
                        # So no CPE or existing OS data, lets split up the CPE data and make our own
                        log(" [!] No os_id found, this is odd !!!")

    if msf_workspace:
        try:
            # check to see if we have a Metasploit RPC instance configured and talking
            from MetasploitAPI import MetasploitAPI
            msf_api = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
        except:
            log(" [!] MSF Workspace sent but unable to authenticate to MSF API", logger.ERROR)
            msf_api = None

        try:
            scan_data = open(filename, "r+").readlines()
        except Exception, error:
            log(" [!] Error loading scan data to send to Metasploit: %s" % str(error), logger.ERROR)

        if scan_data and msf_api:
            task = msf_api.pro_import_data(
                msf_workspace,
                "".join(scan_data),
                {
                    #'preserve_hosts': form.vars.preserve_hosts,
                    'blacklist_hosts': "\n".join(ip_ignore_list)
                },
            )

            msf_workspace_num = session.msf_workspace_num or 'unknown'
            msfurl = os.path.join(auth.user.f_msf_pro_url, 'workspaces', msf_workspace_num, 'tasks', task['task_id'])
            print(" [*] Added file to MSF Pro: %s" % (msfurl))

    # any new nexpose vulns need to be checked against exploits table and connected
    log(" [*] Connecting exploits to vulns and performing do_host_status")
    do_host_status(asset_group=asset_group)

    log(" [*] Import complete: hosts: %s added, %s skipped" % (hoststats['added'],
                                                               hoststats['skipped'],
                                                              ))
