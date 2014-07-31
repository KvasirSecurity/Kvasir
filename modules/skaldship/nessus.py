# -*- coding: utf-8 -*-

__version__ = "1.1"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Nessus Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from gluon import current
import sys, os, time, re
from datetime import datetime
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from skaldship.hosts import get_host_record, do_host_status
from skaldship.exploits import connect_exploits
from skaldship.services import Services
from gluon.validators import IS_SLUG
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

def nessus_get_config(session={}):
    """
    Returns a dict of Nessus configuration settings based on yaml or session
    """

    nessus_config = current.globalenv['settings']['kvasir_config'].get('nessus') or {}
    config = {}
    config['ignored_plugins'] = nessus_config.get('ignored_plugins', [19506, 11219, 34277])
    config['servers'] = {}
    for server in nessus_config.get('servers'):
        for k,v in server.iteritems():
            config['servers'][k] = {
                'url': v.get('url', 'http://localhost:8834/'),
                'user': v.get('user', 'admin'),
                'password': v.get('password', 'password')
            }

    return config


##-------------------------------------------------------------------------

def vuln_time_convert(vtime=''):
    """
    Convert Nessus date (YYYY/MM/DD) into python datetime
    """
    if not vtime:
        tval = datetime(1970, 1, 1)
    else:
        if isinstance(vtime, str):
            (year, mon, day) = vtime.split('/')
            tval = time.strptime(vtime, "%Y/%m/%d")
    return datetime.fromtimestamp(time.mktime(tval))


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

        Args:
            host_properties: A <HostProperties> section from .nessus or a CSV line

        Returns:
            t_hosts.id, { hostdata }
        """
        from gluon.validators import IS_IPADDRESS
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

        host_id = get_host_record(ipaddr)
        if host_id and not self.update_hosts:
            return host_id, hostdata

        # new host found, pull what we need for t_hosts
        hostfields = {}
        hostfields['f_engineer'] = self.engineer
        hostfields['f_asset_group'] = self.asset_group
        hostfields['f_confirmed'] = False

        # check ipv4/ipv6 and set hostfields accordingly
        if IS_IPADDRESS(is_ipv4=True)(ipaddr)[1] is None:
            hostfields['f_ipv4'] = ipaddr
        elif IS_IPADDRESS(is_ipv6=True)(ipaddr)[1] is None:
            hostfields['f_ipv6'] = ipaddr
        else:
            log("Invalid IP Address in HostProperties: %s" % ipaddr, logging.ERROR)
            return None, {}

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
                return None, {}
            self.stats['added'] += 1
            host_id = result.id
            log(" [-] Adding host: %s" % ipaddr)
        elif self.update_hosts:
            if hostfields['f_ipv4']:             
                host_id = self.db(self.db.t_hosts.f_ipv4 == hostfields['f_ipv4']).update(**hostfields)
                self.db.commit()
                host_id = get_host_record(hostfields['f_ipv4'])
                if host_id:
                    host_id = host_id.id
                log(" [-] Updating IP: %s" % (hostfields['f_ipv4']))
            else:
                host_id = self.db(self.db.t_hosts.f_ipv6 == hostfields['f_ipv6']).update(**hostfields)
                self.db.commit()
                host_id = get_host_record(hostfields['f_ipv6'])
                host_id = host_id.id
                log(" [-] Updating IP: %s" % (hostfields['f_ipv6']))
            self.stats['updated'] += 1

        return host_id, hostfields


##-------------------------------------------------------------------------
class NessusVulns:
    """
    Since Nessus puts all vulnerability data into the ReportHost section
    we need to hold a mapping of db.t_vulndata.id to pluginID and also keep
    a link of fname to pluginID.
    """
    def __init__(self):
        self.vulns = {}         # { 'pluginID': [db.t_vulndata.id, vulndata] }
        self.db = current.globalenv['db']
        self.cache = current.globalenv['cache']
        self.stats = {
            'added': 0,
            'processed': 0
        }
        # list of references to add. these are fields in the xml vulndata
        self.ref_types = ['cve', 'osvdb', 'bid', 'urls', 'cpe', 'cert']
        # list of references that are single fields in the xml vulndata
        self.single_refs = ['msft']

    def db_vuln_refs(self, vuln_id=None, vulndata={}, extradata={}):
        """
        Add or update vulnerability references such as CPE, MSF Bulletins, OSVDB, Bugtraq, etc.

        Args:
            vuln_id: The db.t_vulndata reference id
            vulndadta: A dictionary of vulnerability data from t_vulndata
            extradata: A dictionary of extra vulndata

        Returns:
            None
        """
        if not vulndata:
            log(" [!] No vulndata sent!", logging.ERROR)
            return

        if not extradata:
            log(" [!] No extradata sent!", logging.ERROR)
            return

        if not vuln_id:
            log(" [!] No vulnerability record id sent!", logging.ERROR)
            return

        ref_types = self.ref_types
        ref_types.extend(self.single_refs)
        # ugh this needs to be more pythonic. it's 1:30am and I'm tired
        for refname in ref_types:
            if refname in extradata:
                for reftext in extradata[refname]:
                    if reftext:
                        # add the vuln_ref
                        ref_id = self.db.t_vuln_refs.update_or_insert(
                            f_text=reftext,
                            f_source=refname.upper(),
                        )
                        if not ref_id:
                            ref_id = self.db(self.db.t_vuln_refs.f_text == reftext).select(
                                cache=(self.cache.ram, 180)
                            ).first().id

                        # link vuln_ref to vulndata
                        self.db.t_vuln_references.update_or_insert(
                            f_vulndata_id=vuln_id,
                            f_vuln_ref_id=ref_id
                        )

        return

    def parse(self, rpt_item):
        """
        PluginID data is built as the report is processed however we want to
        also be certain to not duplicate existing t_vulndata so a lookup is
        performed with both the pluginID and fname. If none found the record is
        entered into the database and populates the local dict

        Args:
            rpt_item: A ReportItem field (etree._Element or CSV line)

        Returns:
            t_vulndata.id: integer field of db.t_vulndata[id]
            vulndata: A dictionary of fields for t_vulndata
            extradata: A dictionary of extra data fields such as references
        """
        # TODO: Check validity of XML or CSV
        # if not etree.iselement(rpt_item):
        #    log("Invalid plugin data received: %s" % type(rpt_item), logging.ERROR)
        #    return (None, {}, {})

        # extract specific parts of ReportItem
        extradata = {}

        SF_RE = re.compile('Source File: (\w+).nasl')
        if etree.iselement(rpt_item):
            # XML element, parse it as such
            is_xml = True
            extradata['proto'] = rpt_item.get('protocol', 'info')
            extradata['port'] = rpt_item.get('port', 0)
            extradata['status'] = rpt_item.get('port', 'open')
            extradata['svcname'] = rpt_item.get('svc_name', 0)
            extradata['plugin_output'] = rpt_item.findtext('plugin_output', '') 
            extradata['exploit_available'] = rpt_item.findtext('exploit_available', 'false')
            fname = rpt_item.findtext('fname', '')
            pluginID = rpt_item.get('pluginID')
            f_title = rpt_item.get('pluginName')
            f_riskscore = rpt_item.get('risk_factor', '')
            f_cvss_score = float(rpt_item.findtext('cvss_base_score', 0.0))
            f_cvss_i_score = float(rpt_item.findtext('cvss_temporal_score', 0.0))
            f_description = rpt_item.findtext('description')
            f_solution = rpt_item.findtext('solution')
            f_dt_published = rpt_item.findtext('plugin_publication_date')
            f_dt_added = rpt_item.findtext('plugin_publication_date')
            f_dt_modified = rpt_item.findtext('plugin_modification_date')
            severity = int(rpt_item.get('severity', 0))
            cvss_vectors = rpt_item.findtext('cvss_vector') # CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P
        else:
            # CSV data, parse it as such
            is_xml = False
            extradata['proto'] = rpt_item.get('Protocol', 'info')
            extradata['port'] = rpt_item.get('Port', 0)
            extradata['svcname'] = ''  # TODO: Look this up in etc/services
            extradata['plugin_output'] = rpt_item.get('Plugin Text', rpt_item.get('Plugin Output', ''))
            extradata['exploit_available'] = rpt_item.get('Exploit?', 'false')
            pluginID = rpt_item.get('Plugin', rpt_item.get('Plugin ID'))
            f_title = rpt_item.get('Plugin Name', rpt_item.get('Name', ''))
            f_riskscore = rpt_item.get('Risk Factor', '')
            f_cvss_score = rpt_item.get('CVSS Base Score', rpt_item.get('CVSS', 0.0))
            f_cvss_i_score = rpt_item.get('CVSS Temporal Score', 0.0)
            f_description = rpt_item.get('Description')
            f_solution = rpt_item.get('Solution')
            f_dt_published = rpt_item.get('Plugin Publication Date')
            f_dt_added = rpt_item.get('Plugin Publication Date')
            f_dt_modified = rpt_item.get('Plugin Modification Date')
            severity = rpt_item.get('Severity', 0)
            cvss_vectors = rpt_item.get('CVSS Vector') # AV:N/AC:L/Au:N/C:P/I:P/A:N
            sf_re = SF_RE.search(extradata['plugin_output'])
            if sf_re:
                fname = sf_re.groups()[0]
            else:
                fname = None

            # CSV DictReader sets fields to '' so force float/int if nothing set
            if not f_cvss_score:
                f_cvss_score = 0.0
            if not f_cvss_i_score:
                f_cvss_i_score = 0.0

            # Severity may be not set, set it to zero then
            if not severity:
                severity = 0
            # Severity may also be a word, lets map them to numbers
            severity_map = {
                'Critical': 4,
                'High': 3,
                'Medium': 2,
                'Low': 1,
                'Info': 0,
            }
            if isinstance(severity, str):
                severity = severity_map[severity]

            if not extradata['port']:
                extradata['port'] = 0

            # CSV puts N/A for date fields but we need them to be None or real datetimes...
            if f_dt_published == "N/A":
                f_dt_published = None
            if f_dt_added == "N/A":
                f_dt_added = None
            if f_dt_modified == "N/A":
                f_dt_modified = None

        # set t_vulndata.f_vulnid based on pluginID if no filename is found
        extradata['pluginID'] = pluginID
        if fname:
            fname = fname.rstrip('.nasl')
            f_vulnid = IS_SLUG()("%s-%s" % (fname, pluginID))[0]     # slugify it
        else:
            f_vulnid = pluginID

        # references with multiple values
        for refdata in self.ref_types:
            extradata[refdata] = []
            if is_xml:
                for i in rpt_item.findall(refdata):
                    extradata[refdata].append(i.text)
            else:
                if rpt_item.get(refdata):
                    extradata[refdata].append(rpt_item.get(refdata))

        # single value references
        for refdata in self.single_refs:
            if is_xml:
                extradata[refdata] = [rpt_item.findtext(refdata)]
            else:
                if rpt_item.get(refdata):
                    extradata[refdata] = rpt_item.get(refdata)

        # check local dict, else check t_vulndata
        if pluginID in self.vulns:
            return self.vulns[pluginID][0], self.vulns[pluginID][1], extradata
        else:
            vuln_row = self.db(self.db.t_vulndata.f_vulnid == f_vulnid).select(cache=(self.cache.ram, 180)).first()
            if vuln_row:
                # exists in t_vulndata, return it
                vuln_id = vuln_row.id
                vulndata = vuln_row.as_dict()
                return vuln_id, vulndata, extradata

        # vulnerability-specific data
        vulndata = {
            'f_vulnid': f_vulnid,
            'f_title': f_title,
            'f_riskscore': f_riskscore,
            'f_cvss_score': f_cvss_score,
            'f_cvss_i_score': f_cvss_i_score,
            'f_description': f_description,
            'f_solution': f_solution,
            'f_dt_published': f_dt_published,
            'f_dt_added': f_dt_added,
            'f_dt_modified': f_dt_modified,
            'f_source': 'Nessus',
        }

        # Nessus only has 5 severity levels: 0, 1, 2, 3 and 4 .. We go to 11. Assign 0:0, 1:3, 2:5, 3:8, 4:10
        sevmap = {'0': 0, '1': 3 , '2': 5, '3': 8, '4': 10}
        vulndata['f_severity'] = sevmap[str(severity)]

        if cvss_vectors:
            if cvss_vectors.startswith("CVSS2"):
                cvss_vectors = cvss_vectors[6:]
            vulndata['f_cvss_av'] = cvss_vectors[3]
            vulndata['f_cvss_ac'] = cvss_vectors[8]
            vulndata['f_cvss_au'] = cvss_vectors[13]
            vulndata['f_cvss_c'] = cvss_vectors[17]
            vulndata['f_cvss_i'] = cvss_vectors[21]
            vulndata['f_cvss_a'] = cvss_vectors[25]
        else:
            vulndata['f_cvss_av'] = ''
            vulndata['f_cvss_ac'] = ''
            vulndata['f_cvss_au'] = ''
            vulndata['f_cvss_c'] = ''
            vulndata['f_cvss_i'] = ''
            vulndata['f_cvss_a'] = ''
        vuln_id = self.db.t_vulndata.update_or_insert(**vulndata)
        if not vuln_id:
            vuln_id = self.db(self.db.t_vulndata.f_vulnid == f_vulnid).select(cache=(self.cache.ram, 180)).first().id

        if vuln_id:
            self.stats['processed'] += 1
            self.vulns[pluginID] = [vuln_id, vulndata]
            self.db.commit()
            log(" [-] Adding vulnerability to vuln database: %s" % f_vulnid)
            # add/update vulnerability references
            self.db_vuln_refs(vuln_id, vulndata, extradata)
        else:
            log(" [!] Error inserting/finding vulnerability in database: %s" % f_vulnid, logging.ERROR)

        return vuln_id, vulndata, extradata


##-------------------------------------------------------------------------
def process_scanfile(
    filename=None,
    asset_group=None,
    engineer=None,
    msf_settings={},
    ip_ignore_list=None,
    ip_include_list=None,
    update_hosts=False,
    ):
    """
    Process a Nessus XML or CSV Report file. There are two types of CSV output, the first
    is very basic and is generated by a single Nessus instance. The second comes from the
    centralized manager. I forget what it's called but it packs more data. If you have a
    standalone scanner, always export/save as .nessus.

    Args:
        filename: A local filename to process
        asset_group: Asset group to assign hosts to
        engineer: Engineer record number to assign hosts to
        msf_workspace: If set a Metasploit workspace to send the scanfile to via the API
        ip_ignore_list: List of IP addresses to ignore
        ip_include_list: List of IP addresses to ONLY import (skip all others)
        update_hosts: Boolean to update/append to hosts, otherwise hosts are skipped

    Returns:
        msg: A string status message
    """
    from skaldship.cpe import lookup_cpe
    nessus_config = nessus_get_config()

    db = current.globalenv['db']
    cache = current.globalenv['cache']
    settings = current.globalenv['settings']

    # build the hosts only/exclude list
    ip_exclude = []
    if ip_ignore_list:
        ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    ip_only = []
    if ip_include_list:
        ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    log(" [*] Processing Nessus scan file %s" % filename)

    fIN = open(filename, "rb")
    # check to see if file is a CSV file, if so set nessus_csv to True
    line = fIN.readline()
    fIN.seek(0)
    if line.startswith('Plugin'):
        import csv
        csv.field_size_limit(sys.maxsize)           # field size must be increased
        nessus_iterator = csv.DictReader(fIN)
        nessus_csv_type = 'Standalone'
        log(" [*] CSV file is from Standalone scanner")
    elif line.startswith('"Plugin"'):
        import csv
        csv.field_size_limit(sys.maxsize)           # field size must be increased
        nessus_iterator = csv.DictReader(fIN)
        nessus_csv_type = 'SecurityCenter'
        log(" [*] CSV file is from SecurityCenter")
    else:
        nessus_csv_type = False
        try:
            nessus_xml = etree.parse(filename)
            log(" [*] XML file identified")
        except etree.ParseError, e:
            msg = " [!] Invalid Nessus scan file (%s): %s " % (filename, e)
            log(msg, logging.ERROR)
            return msg

        root = nessus_xml.getroot()
        nessus_iterator = root.findall("Report/ReportHost")

    nessus_hosts = NessusHosts(engineer, asset_group, ip_include_list, ip_ignore_list, update_hosts)
    nessus_vulns = NessusVulns()
    services = Services()
    svcs = db.t_services

    for host in nessus_iterator:
        if not nessus_csv_type:
            (host_id, hostdata) = nessus_hosts.parse(host.find('HostProperties'))
        else:
            (host_id, hostdata) = nessus_hosts.parse(host)

        if not host_id:
            # no host_id returned, it was either skipped or errored out
            continue

        # Time to parse the plugin data. This is where CSV and XML diverge.
        def _plugin_parse(host_id, vuln_id, vulndata, extradata):
            port = extradata['port']
            proto = extradata['proto']
            svcname = extradata['svcname']
            plugin_output = extradata['plugin_output']
            pluginID = extradata['pluginID']

            svc_rec = services.get_record(
                create_or_update=True,
                **{'f_proto': proto, 'f_number': port, 'f_name': svcname, 'f_hosts_id': host_id}
            )

            # create t_service_vulns entry for this pluginID
            svc_vuln = {}
            svc_vuln['f_services_id'] = svc_rec.id
            svc_vuln['f_vulndata_id'] = vuln_id
            svc_vuln['f_proof'] = plugin_output

            # you may be a vulnerability if...
            if extradata['exploit_available'] == 'true':
                # if you have exploits available you may be an extra special vulnerability
                svc_vuln['f_status'] = 'vulnerable-exploited'
            elif svcname == 'general':
                # if general service then you may not be a vulnerability
                svc_vuln['f_status'] = 'general'
            elif vulndata['f_severity'] == 0:
                # if there is no severity then you may not be a vulnerability
                svc_vuln['f_status'] = 'general'
            else:
                # you're a vulnerability
                svc_vuln['f_status'] = 'vulnerable'
            db.t_service_vulns.update_or_insert(**svc_vuln)

            ######################################################################################################
            ## Let the parsing of Nessus Plugin Output commence!
            ##
            ## Many Plugins provide useful data in plugin_output. We'll go through the list here and extract
            ## out the good bits and add them to Kvasir's database. Some Plugins will not be added as vulnerabilities
            ## because they're truly informational. This list will change if somebody keeps it up to date.
            ##
            ## TODO: This should be moved into a separate function so we can also process csv data
            ## TODO: Add t_service_info key/value records (standardize on Nexpose-like keys?)
            ##
            ######################################################################################################
            d = {}

            if pluginID in nessus_config.get('ignored_plugins'):
                return

            nessus_vulns.stats['added'] += 1
            #### SNMP
            if pluginID == '10264':
                # snmp community strings
                for snmp in re.findall(' - (.*)', plugin_output):
                    res = db.t_snmp.update_or_insert(f_hosts_id=host_id, f_community=snmp)
                    db.commit()

            #elif pluginID == '':
            #    continue

            #### SMB/NetBIOS
            if pluginID == '10860':
                # SMB Use Host SID to Enumerate Local Users
                for user in re.findall(' - (.*)', plugin_output):
                    username = user[0:user.find('(')-1]
                    try:
                        gid = re.findall('\(id (\d+)', user)[0]
                    except:
                        gid = '0'

                    # Windows users, local groups, and global groups
                    d['f_username'] = username
                    d['f_gid'] = gid
                    d['f_services_id'] = svc_rec.id
                    d['f_source'] = '10860'
                    db.t_accounts.update_or_insert(**d)
                    db.commit()

            if pluginID == '17651':
                # Microsoft Windows SMB : Obtains the Password Policy
                d['f_hosts_id'] = host_id
                try:
                    d['f_lockout_duration'] = re.findall('Locked account time \(s\): (\d+)', plugin_output)[0]
                    d['f_lockout_limit'] = re.findall(
                        'Number of invalid logon before locked out \(s\): (\d+)', plugin_output
                    )[0]
                except IndexError:
                    d['f_lockout_duration'] = 1800
                    d['f_lockout_limit'] = 0
                db.t_netbios.update_or_insert(**d)
                db.commit()

            if pluginID == '10395':
                # Microsoft Windows SMB Shares Enumeration
                d['f_hosts_id'] = host_id
                d['f_shares'] = re.findall(' - (.*)', plugin_output)
                db.t_netbios.update_or_insert(**d)

            if pluginID == '10150':
                # Windows NetBIOS / SMB Remote Host Information Disclosure
                try:
                    d['f_hosts_id'] = host_id
                    d['f_domain'] = re.findall('(\w+).*= Workgroup / Domain name', plugin_output)[0]
                    db.t_netbios.update_or_insert(**d)
                except IndexError:
                    pass

            #### Banners
            if pluginID == '10092':
                # FTP Server Detection
                RE_10092 = re.compile('The remote FTP banner is :\n\n(.*)', re.DOTALL)
                try:
                    d['f_banner'] = RE_10092.findall(plugin_output)[0]
                    svc_rec.update(**d)
                    db.commit()
                except Exception, e:
                    log("Error parsing FTP banner: %s" % str(e), logging.ERROR)

            if pluginID == '10267':
                # SSH Server Type and Version Information
                try:
                    d['f_banner'] = re.findall('SSH version : (.*)', plugin_output)[0]
                    svcs[svc_id].update(**d)
                    db.commit()
                except Exception, e:
                    log("Error parsing SSH banner: %s" % str(e), logging.ERROR)

            ### Operating Systems and CPE
            if pluginID == '45590':
                # Common Platform Enumeration (CPE)
                for cpe_os in re.findall('(cpe:/o:.*? )', plugin_output):
                    os_id = lookup_cpe(cpe_os.replace('cpe:/o:', '').rstrip(' '))
                    if os_id:
                        db.t_host_os_refs.update_or_insert(
                            f_certainty='0.90',     # just a stab
                            f_family='Unknown',     # not given in Nessus
                            f_class=hostdata.get('system-type'),
                            f_hosts_id=host_id,
                            f_os_id=os_id
                        )
                        db.commit()

        if not nessus_csv_type:
            rpt_items = []

            # Parse the XML <ReportItem> sections where plugins, ports and output are all in
            for rpt_item in host.iterfind('ReportItem'):
                (vuln_id, vulndata, extradata) = nessus_vulns.parse(rpt_item)
                if not vuln_id:
                    # no vulnerability id
                    continue
                _plugin_parse(host_id, vuln_id, vulndata, extradata)
        else:
            (vuln_id, vulndata, extradata) = nessus_vulns.parse(host)
            _plugin_parse(host_id, vuln_id, vulndata, extradata)

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

    # any new Nessus vulns need to be checked against exploits table and connected
    log(" [*] Connecting exploits to vulns and performing do_host_status")
    connect_exploits()
    do_host_status(asset_group=asset_group)

    msg = (' [*] Import complete: hosts: %s added, %s updated, %s skipped '
           '- %s vulns processed, %s added' % (
            nessus_hosts.stats['added'],
            nessus_hosts.stats['updated'],
            nessus_hosts.stats['skipped'],
            nessus_vulns.stats['processed'],
            nessus_vulns.stats['added']
            ))
    log(msg)
    return msg


##-------------------------------------------------------------------------
def main():
    pass

if __name__ == '__main__':
    main()
