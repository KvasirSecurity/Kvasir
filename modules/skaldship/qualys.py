# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Qualys Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""
from gluon import current
import gluon.contrib.simplejson
import logging
logger = logging.getLogger("web2py.app.kvasir")

db = current.globalenv['db']
auth = current.globalenv['auth']

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
    # Upload and process Qualys XML Scan file
    import os, time, re, HTMLParser
    from StringIO import StringIO
    from MetasploitProAPI import MetasploitProAPI
    from skaldship.hosts import html_to_markmin, get_host_record, do_host_status
    from skaldship.cpe import lookup_cpe

    parser = HTMLParser.HTMLParser()

    # output regexes
    RE_NETBIOS_NAME = re.compile('NetBIOS name: (?P<d>.*),')
    RE_NETBIOS_MAC = re.compile('NetBIOS MAC: (?P<d>([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))')
    RE_IPV4 = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

    if msf_workspace:
        msf = MetasploitProAPI(host=user_id.f_msf_pro_url, apikey=user_id.f_msf_pro_key)
        if msf.login():
            logger.info(" [-] Authenticated to Metasploit PRO")
        else:
            logger.error(" [!] Unable to login to Metasploit PRO, check your API key")
            msf = None
    else:
        logger.warn(" [-] No Metasploit workspace provided!")
        msf = None

    try:
        from lxml import etree
    except ImportError:
        try:
            import xml.etree.cElementTree as etree
        except ImportError:
            try:
                import xml.etree.ElementTree as etree
            except:
                raise Exception("Unable to find valid ElementTree module.")

    # build the hosts only/exclude list
    ip_exclude = []
    if ip_ignore_list:
        ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    ip_only = []
    if ip_include_list:
        ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    print(" [*] Processing Qualys scan file %s" % (filename))

    try:
        nmap_xml = etree.parse(filename)
    except etree.ParseError, e:
        print(" [!] Invalid XML file (%s): %s " % (filename, e))
        return

    root = nmap_xml.getroot()

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    existing_vulnids = db(db.t_vulndata()).select(db.t_vulndata.id, db.t_vulndata.f_vulnid).as_dict(key='f_vulnid')
    #print(" [*] Found %d vulnerabilities in the database already." % (len(existing_vulnids)))

    # check for any CPE OS data
    if db(db.t_cpe_os).count() > 0:
        have_cpe = True
    else:
        have_cpe = False

    user_id = db.auth_user(engineer) or auth.user.id

    # parse the hosts, where all the goodies are
    nodes = root.findall('IP')
    print(" [-] Parsing %d hosts" % (len(nodes)))
    hoststats = {}
    hoststats['added'] = 0
    hoststats['skipped'] = 0
    hoststats['updated'] = 0
    hoststats['errored'] = 0
    hosts = []   # array of host_id fields
    vulns_added =0
    vulns_skipped = 0

    for node in nodes:
        nodefields = {}
        ipaddr = node.get('value')
        nodefields['f_ipaddr'] = ipaddr

        nodefields['f_hostname'] = node.get('hostname')
        nodefields['f_netbios_name'] = node.findtext('NETBIOS_HOSTNAME')
        # nodefields['f_macaddr'] = address.get('addr')

        """
        status = node.find('status').get('state')

        print(" [-] Host %s status is: %s" % (ipaddr, status))
        if status != "up":
            hoststats['skipped'] += 1
            continue
        """

        if ipaddr in ip_exclude:
            print(" [-] Host is in exclude list... skipping")
            hoststats['skipped'] += 1
            continue

        if len(ip_only) > 0 and ipaddr not in ip_only:
            print(" [-] Host is not in the only list... skipping")
            hoststats['skipped'] += 1
            continue

        ports = node.findall('INFOS')
        if len(ports) < 1 and not addnoports:
            print(" [-] No ports open and not asked to add those kind... skipping")
            hoststats['skipped'] += 1
            continue

        nodefields['f_engineer'] = user_id
        nodefields['f_asset_group'] = asset_group
        nodefields['f_confirmed'] = False

        # check to see if IPv4/IPv6 exists in DB already
        if nodefields.has_key('f_ipaddr'):
            host_rec = db(db.t_hosts.f_ipaddr == nodefields['f_ipaddr']).select().first()
        else:
            logging.warn("No IP Address found in record. Skipping")
            continue

        if host_rec is None:
            host_id = db.t_hosts.insert(**nodefields)
            db.commit()
            hoststats['added'] += 1
            print(" [-] Adding %s" % (ipaddr))
        elif host_rec is not None and update_hosts:
            db.commit()
            host_id = db(db.t_hosts.f_ipaddr == nodefields['f_ipaddr']).update(**nodefields)
            db.commit()
            host_id = get_host_record(ipaddr)
            host_id = host_id.id
            hoststats['updated'] += 1
            print(" [-] Updating %s" % (ipaddr))
        else:
            hoststats['skipped'] += 1
            db.commit()
            print(" [-] Skipped %s" % (ipaddr))
            continue
        hosts.append(host_id)

        # :
        for hostscripts in node.findall('hostscript/script'):
            svc_id = db.t_services.update_or_insert(f_proto='info', f_number=0, f_status='open', f_hosts_id=host_id)
            db.commit()
            for script in hostscripts:
                script_id = script.get('id')
                output = script.get('output')
                svc_info = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=script_id, f_text=output)
                db.commit()

        # add ports and resulting vulndata
        for port in node.findall("ports/port"):
            f_proto = port.get('protocol')
            f_number = port.get('portid')
            f_status = port.find('state').get('state')

            port_svc = port.find('service')
            if port_svc:
                f_name = port_svc.get('name')
                f_product = port_svc.get('product')
                svc_fp = port_svc.get('servicefp')
            else:
                f_name = None
                f_product = None
                svc_fp = None

            print(" [-] Adding port: %s/%s (%s)" % (f_proto, f_number, f_name))
            svc_id = db.t_services.update_or_insert(f_proto=f_proto, f_number=f_number, f_status=f_status, f_hosts_id=host_id, f_name=f_name)

            if f_product:
                version = port.find('service').get('version', None)
                if version:
                    f_product += " (%s)" % (version)
                svc_info = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=f_name, f_text=f_product)
                db.commit()

            if svc_fp:
                svc_info = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=svc_fp, f_text=svc_fp)
                db.commit()

            # Process <script> service entries
            for script in port.findall('service/script'):
                svc_info = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=script.get('id'), f_text=script.get('output'))
                db.commit()

            # Process <cpe> service entries
            for port_cpe in port.findall('service/cpe'):
                cpe_id = port_cpe.text.replace('cpe:/', '')

                if cpe_id[0] == "a":
                    # process CPE Applications

                    print(" [-] Found Application CPE data: %s" % (cpe_id))
                    svc_info = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name='CPE ID', f_text="cpe:/%s" % (cpe_id))
                    db.commit()

                elif cpe_id[0] == "o":
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
                        print(" [!] No os_id found, this is odd !!!")

                for config in port.findall("configuration/config"):
                    cfg_id = db.t_service_info.update_or_insert(f_services_id=svc_id, f_name=config.attrib['name'], f_text=config.text)
                    db.commit()
                    if re.match('\w+.banner$', config.attrib['name']):
                        db.t_services[svc_id] = dict(f_banner=config.text)
                        db.commit()
                    if config.attrib['name'] == 'mac-address':
                        # update the mac address of the host
                        db.t_hosts[host_id] = dict(f_macaddr = config.text)
                        db.commit()
                    if "advertised-name" in config.attrib['name']:
                        # netbios computer name
                        d = config.text.split(" ")[0]
                        if "Computer Name" in config.text:
                            data = {}
                            data['f_netbios_name'] = d
                            # if hostname isn't defined then lowercase netbios name and put it in
                            if db.t_hosts[host_id].f_hostname is None:
                                data['f_hostname'] = d.lower()
                            db(db.t_hosts.id == host_id).update(**data)
                        elif "Domain Name" in config.text:
                            db(db.t_netbios.f_hosts_id == host_id).update(f_domain=d) or db.t_netbios.insert(f_hosts_id=host_id, f_domain=d)
                        db.commit()

                for script in port.findall("script"):
                    # process <script> results. This data contains both info
                    # and vulnerability data. For now we'll take a list of
                    # known nmap vuln checks from private/nmap_vulns.csv and
                    # use that to separate between service_info and vulndata.
                    pass

    if msf is not None:
        # send the downloaded nexpose file to MSF for importing
        try:
            res = msf.pro_import_file(
                msf_workspace,
                filename,
                {
                    'DS_REMOVE_FILE': False,
                    'tag': asset_group,
                    },
            )
            print(" [*] Added file to MSF Pro: %s" % (res))
        except MSFAPIError, e:
            logging.error("MSFAPI Error: %s" % (e))
            pass

    # any new nexpose vulns need to be checked against exploits table and connected
    print(" [*] Connecting exploits to vulns and performing do_host_status")
    do_host_status(asset_group=asset_group)

    print(" [*] Import complete: hosts: %s added, %s skipped, %s errors - vulns: %s added, %s skipped" % (hoststats['added'],
                                                                                                          hoststats['skipped'],
                                                                                                          hoststats['errored'],
                                                                                                          vulns_added, vulns_skipped))
