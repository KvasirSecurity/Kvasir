# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Nmap Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
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
    msf_settings={},
    ip_ignore_list=None,
    ip_include_list=None,
    update_hosts=False,
    ):
    # Upload and process Nmap XML Scan file
    import re
    import os
    from skaldship.hosts import get_host_record, do_host_status
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

    log(" [*] Processing Nmap scan file %s" % (filename))

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

        # process OS related info
        for os in node.osmatches:
            os_id = None
            host_id = None
            f_title = os['name'] #title
            for k in os['osclasses']:
                f_cpename= k['cpe'].lstrip('cpe:/o:')
                f_vendor = k['vendor']
                f_product = k['osfamily']
                f_version = k['osgen']
                f_class = k['type']
                f_family = k['osfamily']
                f_certainty= k['accuracy']

                cpe_res = db((db.t_os.f_cpename == f_cpename)&(db.t_os.f_title == f_title)).select().first()

                if cpe_res is not None:
                    os_id = cpe_res.id

                else:
                    try:
                        os_id = db.t_os.insert(
                        f_cpename = f_cpename,
                        f_title = f_title,
                        f_vendor = f_vendor,
                        f_product = f_product,
                        f_version = f_version,
                        )
                    except Exception, e:
                        logger.error("Error inserting OS: %s" % (e))

                    db.commit()

                if os_id and (f_class or f_family or f_certainty):
                    ipaddr = node.ip.get('addr')
                    host_id = get_host_record(ipaddr)
                    host_id = host_id.id
                    try:
                        db.t_host_os_refs.insert(f_certainty = f_certainty,
                                                 f_family = f_family,
                                                 f_class = f_class,
                                                 f_hosts_id = host_id,
                                                 f_os_id = os_id)
                    except Exception, e:
                        logger.error("Error inserting OS: %s" % (e))
                    db.commit()

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

            # if record exists, update returns None so look up the record:
            if svc_id is None:
                svc_id = db((db.t_services.f_hosts_id == host_id) &
                           (db.t_services.f_proto == f_proto) &
                           (db.t_services.f_number == f_number)).select('id').first()
                svc_id = svc_id.id

            if f_product:
                version = port.get('service_version')
                if version:
                    f_product += " (%s)" % (version)
                db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=f_name, f_text=f_product)
                db.commit()

            # Process <script> service entries
            for script in port.get('scripts'):
                try:
                    db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=script.get('id'), f_text=script.get('output'))
                except Exception, e:
                    logger.error("Error inserting Script: %s" % (e))
                db.commit()
                # check for banner id and update t_services banner field with the output
                if script.get('id') == "banner":
                    try:
                        db.t_services.update_or_insert((db.t_services.id == svc_id), f_banner = script.get('output'))
                    except Exception, e:
                        logger.error("Error inserting Banner: %s" % (e))
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

    if msf_settings.get('workspace'):
        try:
            # check to see if we have a Metasploit RPC instance configured and talking
            from MetasploitAPI import MetasploitAPI
            msf_api = MetasploitAPI(host=msf_settings.get('url'), apikey=msf_settings.get('key'))
            working_msf_api = msf_api.login()
        except Exception, error:
            log(" [!] Unable to authenticate to MSF API: %s" % str(error), logging.ERROR)
            working_msf_api = False

        try:
            scan_data = open(filename, "r+").readlines()
        except Exception, error:
            log(" [!] Error loading scan data to send to Metasploit: %s" % str(error), logging.ERROR)
            scan_data = None

        if scan_data and working_msf_api:
            task = msf_api.pro_import_data(
                msf_settings.get('workspace'),
                "".join(scan_data),
                {
                    #'preserve_hosts': form.vars.preserve_hosts,
                    'blacklist_hosts': "\n".join(ip_ignore_list)
                },
            )

            msf_workspace_num = session.msf_workspace_num or 'unknown'
            msfurl = os.path.join(msf_settings.get('url'), 'workspaces', msf_workspace_num, 'tasks', task['task_id'])
            log(" [*] Added file to MSF Pro: %s" % msfurl)

    # any new nexpose vulns need to be checked against exploits table and connected
    log(" [*] Connecting exploits to vulns and performing do_host_status")
    do_host_status(asset_group=asset_group)

    log(" [*] Import complete: hosts: %s added, %s skipped" % (hoststats['added'],
                                                               hoststats['skipped'],
                                                              ))

##-------------------------------------------------------------------------

def run_scan(
    blacklist=None,
    target_list=None,
    scan_options=None,
    ):
    '''
    Executes nmap scan
    '''
    from zenmapCore_Kvasir.NmapCommand import NmapCommand
    from zenmapCore_Kvasir.NmapOptions import NmapOptions
    from time import sleep

    if scan_options[0] is not 'nmap':
        if 'nmap' in settings:
            scan_options.insert(0, settings.nmap)
        else:
            scan_options.insert(0, 'nmap')

    if target_list:
        data = []
        for ip in target_list:
            data.append(ip.strip(' \t\n\r'))
        target_list = data

    if blacklist:
        data = []
        for ip in blacklist:
            data.append(ip.strip(' \t\n\r'))
        blacklist = [','.join(map(str, data))]
        blacklist.insert(0, "--exclude")

    ops = NmapOptions()
    try:
        ops.parse(scan_options + target_list + blacklist)
    except Exception as e:
        log("[!] %s" % e)

    cmd = NmapCommand(ops.render_string())

    log(" [*] Starting Nmap Scan: %s" % (cmd.command))
    cmd.run_scan()

    try:
        cmd.scan_state()
    except Exception as e:
        log("[!] %s" % e)

    full_output = ""
    while cmd.scan_state():
        sleep(5)
        result = cmd.get_output()
        start = len(full_output) - len(result)
        output = result[start:]
        full_output = "%s%s" % (full_output, output)
        log(output)


    log(" [*] Nmap Scan Complete")

    filename = cmd.get_xml_output_filename()
    return filename


