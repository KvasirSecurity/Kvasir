# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## ShodanHQ Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from gluon import current
from skaldship.log import log
from skaldship.hosts import get_host_record, do_host_status

##-------------------------------------------------------------------------

class ShodanData():

    def __init__(self):
        self.stats = {}
        self.stats['hosts_added'] = 0
        self.stats['hosts_skipped'] = 0
        self.stats['hosts_updated'] = 0
        self.stats['services_added'] = 0
        self.stats['services_updated'] = 0
        self.ip_only = []
        self.ip_exclude = []
        self.engineer = None
        self.asset_group = 'ShodanHQ Import'
        self.hosts = []
        import re
        self.SMTP_FTP_220 = re.compile('^220.*')

    def parse_host(self, host):
        """
        Parse an XML host data from ShodanHQ results
        """
        from gluon.validators import IS_IPADDRESS
        db = current.globalenv['db']

        hostfields = {}
        ipaddr = host.get('ip')

        if self.ip_only and ipaddr not in self.ip_only:
            log(" [-] %s is not in the only list... skipping" % (ipaddr))
            #sys.stderr.write(msg)
            self.stats['hosts_skipped'] += 1
            return

        if ipaddr in self.ip_exclude:
            log(" [-] %s is in exclude list... skipping" % (ipaddr))

        if IS_IPADDRESS(is_ipv4=True)(ipaddr)[1] is None:
            # address is IPv4:
            hostfields['f_ipv4'] = ipaddr
        elif IS_IPADDRESS(is_ipv6=True)(ipaddr)[1] is None:
            hostfields['f_ipv6'] = ipaddr
        else:
            log(" [!] Invalid IP Address in report: %s" % (ipaddr))
            return

        hostname = host.findtext('hostnames')
        if hostname:
            hostfields['f_hostname'] = hostname

        # check to see if IP exists in DB already
        if 'f_ipv4' in hostfields:
            host_rec = db(db.t_hosts.f_ipv4 == hostfields['f_ipv4']).select().first()
        else:
            host_rec = db(db.t_hosts.f_ipv6 == hostfields['f_ipv6']).select().first()

        if host_rec is None:
            hostfields['f_asset_group'] = self.asset_group
            hostfields['f_engineer'] = self.engineer
            host_id = db.t_hosts.insert(**hostfields)
            db.commit()
            self.stats['hosts_added'] += 1
            log(" [-] Adding IP: %s" % (ipaddr))

        elif host_rec is not None:
            db.commit()
            if 'f_ipv4' in hostfields:
                host_id = db(db.t_hosts.f_ipv4 == hostfields['f_ipv4']).update(**hostfields)
                db.commit()
                host_id = get_host_record(hostfields['f_ipv4'])
                host_id = host_id.id
                self.stats['hosts_updated'] += 1
                log(" [-] Updating IP: %s" % (hostfields['f_ipv4']))
            else:
                host_id = db(db.t_hosts.f_ipv6 == hostfields['f_ipv6']).update(**hostfields)
                db.commit()
                host_id = get_host_record(hostfields['f_ipv6'])
                host_id = host_id.id
                self.stats['hosts_updated'] += 1
                log(" [-] Updating IP: %s" % (hostfields['f_ipv6']))

        else:
            self.stats['hosts_skipped'] += 1
            db.commit()
            log(" [-] Skipped IP: %s" % (ipaddr))
            return

        # process the service / data
        f_number = host.get('port')
        if f_number == '161':
            # only udp provided by shodanhq is snmp
            f_proto = 'udp'
        else:
            f_proto = 'tcp'

        f_status = 'open'
        f_name = ''
        addl_fields = {}

        # extract the data field for processing
        port_data = host.findtext('data')

        # for ssh, telnet and smtp throw data into the banner
        if f_number == '21':
            f_banner = "\n".join(self.SMTP_FTP_220.findall(port_data))
            f_name = 'FTP'
            addl_fields = {
                'ftp.banner': port_data,
            }
        elif f_number == '22':
            f_banner = port_data
            f_name = 'SSH'
            addl_fields = {
                'ssh.banner': port_data,
            }
        elif f_number == '23':
            f_banner = port_data
            f_name = 'Telnet'
        elif f_number == '25':
            f_banner = "\n".join(self.SMTP_FTP_220.findall(port_data))
            f_name = 'SMTP'
            addl_fields = {
                'smtp.banner': port_data,
            }
        elif f_number == '80':
            # TODO: parse HTTP headers.. ugly
            f_banner = port_data
            f_name = 'HTTP'
            addl_fields = {
                'http.banner': port_data,
            }
        elif f_number == '1900':
            f_banner = port_data
            f_name = 'UPNP'
            addl_fields = {
                'upnp.banner': port_data,
            }
        else:
            f_banner = port_data

        query = (db.t_services.f_proto == f_proto) & (db.t_services.f_number == f_number) & (db.t_services.f_hosts_id == host_id)
        svc_row = db(query).select().first()
        if svc_row:
            # we found a service record! Check for similar status, names and banners
            do_update = False
            if svc_row.f_status != f_status:
                svc_row.f_status = f_status
                do_update = True
            if svc_row.f_name != f_name:
                svc_row.f_name = f_name
                do_update = True
            if svc_row.f_banner != f_banner:
                svc_row.f_banner = f_banner
                do_update = True

            svc_id = svc_row.id
            if do_update:
                svc_row.update_record()
                db.commit()
                didwhat = "Updated"
                self.stats['services_updated'] += 1
            else:
                didwhat = "Unaltered"
        else:
            # we have a new service!
            svc_id = db.t_services.insert(
                f_proto=f_proto,
                f_number=f_number,
                f_status=f_status,
                f_name=f_name,
                f_banner=f_banner,
                f_hosts_id=host_id
            )
            db.commit()
            didwhat = "Added"
            self.stats['services_added'] += 1

        log(" [-] %s service: (%s) %s/%s" % (didwhat, ipaddr, f_proto, f_number))

        for k, v in addl_fields.iteritems():
            # add additional field entries as service_info records
            db.t_service_info.update_or_insert(
                f_services_id=svc_id,
                f_name=k,
                f_text=v,
            )
            db.commit()

##---------------------------------------------------------

def process_report(
    filename=None,
    host_list=[],
    query=None,
    ip_ignore_list=None,
    ip_include_list=None,
    engineer=1,
    asset_group="ShodanHQ Import",
):
    """
    Processes a ShodanHQ XML Report adding records to the db
    """

    settings = current.globalenv['settings']

    #try:
    #    from shodan import WebAPI
    #    from shodan.api import WebAPIError
    #    webapi = WebAPI(settings.shodanhq_apikey)
    #except ImportError:
    #    webapi = None

    sd = ShodanData()
    sd.engineer = engineer
    sd.asset_group = asset_group

    # build the hosts only/exclude list
    if ip_ignore_list:
        sd.ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    if ip_include_list:
        sd.ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    hosts = []
    if filename:
        log(" [*] Processing ShodanHQ report file: %s" % (filename))
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

        try:
            xml = etree.parse(filename)
        except etree.ParseError, e:
            raise Exception(" [!] Invalid XML file (%s): %s " % (filename, e))
            return

        root = xml.getroot()
        hosts = root.findall("host")

    """
    elif host_list and webapi:
        if not isinstance(host_list, list):
            host_list = [host_list]

        log(" [!] Searching for %s hosts from ShodanHQ" % (len(host_list)), level=logging.DEBUG)
        for h in host_list:
            try:
                host_result = webapi.host(h)
                if host_result.get('ip'):
                    hosts.append(host_result)
            except WebAPIError, e:
                log(" [!] (%s) ShodanHQ error response: %s" % (h, str(e)), level=logging.ERROR)
            except Exception, e:
                log(" [!] (%s) No response from ShodanHQ: %s" % (h, str(e)), level=logging.ERROR)

    elif query and webapi:
        log(" [!] Sending ShodanHQ WebAPI query: %s" % (str(query)), level=logging.DEBUG)
        try:
            query_result = webapi.search(query[0], limit=query[1])
            if query_result.get('total') > 0:
                hosts.append(query_result.get('matches'))
        except WebAPIError, e:
            log(" [!] (%s) ShodanHQ error response: %s" % (query, str(e)), level=logging.ERROR)
        except Exception, e:
            log(" [!] (%s) No response from ShodanHQ: %s" % (query, str(e)), level=logging.ERROR)
    """

    log(" [-] Parsing %d hosts" % (len(hosts)))
    for host in hosts:
        sd.parse_host(host)

    do_host_status()

    msg = " [*] Import complete: hosts: (%s/A, %s/U, %s/S) - services: (%s/A, %s/U)"\
        % (
            sd.stats['hosts_added'],
            sd.stats['hosts_updated'],
            sd.stats['hosts_skipped'],
            sd.stats['services_added'],
            sd.stats['services_updated'],
        )
    log(msg)
    return msg
