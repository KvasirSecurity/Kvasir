# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Nexpose Utilities for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from gluon import current
import time
import re
import HTMLParser
from datetime import datetime
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from skaldship.general import html_to_markmin
from skaldship.hosts import do_host_status
from skaldship.exploits import connect_exploits
import logging
from skaldship.log import log

# lxml is now a required library for processing nexpose xml files. This is
# due to the stdlib not supporting XSLT. Oh well! We'll let web2py handle
# the error.
from lxml import etree


##-------------------------------------------------------------------------

def nexpose_get_config():
    """
    Returns a dict of Nexpose configuration settings based on yaml or session
    """

    nexpose_config = current.globalenv['settings']['kvasir_config'].get('nexpose') or {}
    config = {}
    config['ignored_plugins'] = nexpose_config.get('ignored_plugins', [])
    config['host'] = nexpose_config.get('host', '127.0.0.1')
    config['port'] = nexpose_config.get('port', '3780')
    config['user'] = nexpose_config.get('user', 'nxadmin')
    config['password'] = nexpose_config.get('password', 'password')

    return config

##-------------------------------------------------------------------------

def nx_xml_to_html(vulnxml):
    """Transforms a Nexpose <ContainerBlockElement> to HTML using XSLT"""
    import os
    d = os.path.join(current.globalenv['request'].folder, "modules/skaldship/stylesheets/nexpose.xsl")
    vuln_xslt = etree.XML("".join(open(d, "r").readlines()))
    transform = etree.XSLT(vuln_xslt)

    if isinstance(vulnxml, (str, unicode)):
        # convert to stringio for etree parsing
        from StringIO import StringIO
        vulnxml = StringIO(vulnxml)

    vulnxml = etree.parse(vulnxml)
    result = transform(vulnxml)
    vulnhtml = etree.tostring(result, xml_declaration=False, encoding=unicode)

    return clean_html(vulnhtml)


##-------------------------------------------------------------------------

def clean_html(htmldata):
    """Cleans up the HTML using lxml.html clean_html for now."""
    import re
    try:
        from lxml.html.clean import clean_html
    except ImportError:
        log("You don't have lxml installed", logging.ERROR)
        return htmldata

    if htmldata is None:
        return htmldata
    newdata = clean_html(htmldata)
    newdata = newdata.replace('\n', ' ')
    newdata = newdata.replace('<div>', '')
    newdata = newdata.replace('</div>', '')
    newdata = newdata.replace('\t', '')         # tabs? not needed, no never
    newdata = re.sub(' +', ' ', newdata)

    return newdata


##-------------------------------------------------------------------------

def os_to_cpe(os_rec):
    """Takes a Nexpose XML OS field and finds CPE db id. If no CPE db id exists
then a new one is added."""

    if os_rec is None:
        return None

    result = {}
    result['f_vendor'] = None
    result['f_product'] = None
    result['f_version'] = None
    result['f_update'] = None
    result['f_edition'] = None
    result['f_language'] = None
    result['f_title'] = None

    if os_rec.attrib.has_key('title'):
        result['f_title'] = os_rec.attrib['title']
    else:
        # must build a title since one doesn't exist
        """
        title_data = []
        if os_rec.attrib.has_key('f_vendor'):
            title_data.append(os_key.attrib['f_vendor'])
        if os_rec.attrib.has_key('f_product'):
            title_data.append(os_key.attrib['f_product'])
        if os_rec.attrib.has_key('f_version'):
            title_data.append(os_key.attrib['f_version'])
        if os_rec.attrib.has_key('f_update'):
            title_data.append(os_key.attrib['f_update'])
        if os_rec.attrib.has_key('f_edition'):
            title_data.append(os_key.attrib['f_edition'])
        if os_rec.attrib.has_key('f_language'):
            title_data.append(os_key.attrib['f_language'])
        """
        os_keys = os_rec.keys()
        try:
            os_keys.remove('certainty')
        except:
            pass

        try:
            os_keys.remove('device-class')
        except:
            pass

        title_data = []
        for a in os_keys:
            title_data.append(os_rec.attrib[a])

        title_data = " ".join(title_data)
        out = []
        for word in title_data.split():
            if not word in out:
                out.append(word)
        result['f_title'] = " ".join(out)

    if os_rec.attrib.has_key('vendor'): result['f_vendor'] =os_rec.attrib['vendor'].lower()
    if os_rec.attrib.has_key('product'):
        result['f_product'] = os_rec.attrib['product'].lower()

        # this is annoying logic to handle cpe's variations of the product name
        # when nexpose starts putting cpe strings in their XML we can get rid of
        # a lot of this work and lookup the entries directly.
        if result['f_product'] == 'windows nt' or \
           result['f_product'] == 'windows ce' or \
           result['f_product'] == 'ms dos' or \
           result['f_product'] == 'windows 9x':
            result['f_product'] = result['f_product'].replace(" ", "-")
        else:
            result['f_product'] = result['f_product'].replace(" ", "_")
    if os_rec.attrib.has_key('arch'): result['f_edition'] = os_rec.attrib['arch'].lower()
    if os_rec.attrib.has_key('version'):
        result['f_update'] =os_rec.attrib['version'].lower()
        if result['f_vendor'] == "microsoft":
            try:
                result['f_version'], result['f_update']  = result['f_update'].split(" ")[0:1]
            except:
                pass
        if result['f_vendor'] == "cisco" or \
           result['f_vendor'] == "sun":
            result['f_update']  = result['f_version']
            result['f_version'] = ""

    return result


##-------------------------------------------------------------------------

def guess_cpe_os(os_rec):
    """
    A somewhat messy routine that tries to guess the operating system by
    looking through the official CPE dictionary. It's far from perfect
    but does an ok job... I think!
    """

    if os_rec is None:
        return None

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    osinfo = os_to_cpe(os_rec)

    # first look in the t_os table
    query = db.t_os.f_title == osinfo['f_title']
    os_row = db(query).select(cache=(cache.ram, 180)).first()

    if not os_row:
        query = db.t_os.f_vendor == osinfo['f_vendor']
        if osinfo['f_product'] is not '':
            query &= db.t_os.f_product == osinfo['f_product']
        if osinfo['f_version'] is not '':
            query &= db.t_os.f_version == osinfo['f_version']
        if osinfo['f_update'] is not '':
            query &= db.t_os.f_update  == osinfo['f_update']
        if osinfo['f_edition'] is not '':
            query &= db.t_os.f_edition == osinfo['f_edition']
        if osinfo['f_language'] is not '':
            query &= db.t_os.f_language == osinfo['f_language']
        os_row = db(query).select().first()

    if os_row:
        #msg = "Found (%d) OS IDs from customer tables. First one: %s" % (len(os_rows), os_rows[0].f_title)
        os_id = os_row.id

    else:
        # lookup in CPE OS database
        query = (db.t_cpe_os.f_vendor == osinfo['f_vendor'])
        if osinfo['f_product'] is not '':
            query &= (db.t_cpe_os.f_product == osinfo['f_product'])
        if osinfo['f_version'] is not '':
            query &= db.t_cpe_os.f_version == osinfo['f_version']
        if osinfo['f_update'] is not '':
            query &= db.t_cpe_os.f_update == osinfo['f_update']
        if osinfo['f_edition'] is not '':
            query &= db.t_cpe_os.f_edition == osinfo['f_edition']
        if osinfo['f_language'] is not '':
            query &= db.t_cpe_os.f_language == osinfo['f_language']

        os_row = db(query).select().first()

        if os_row:
            osinfo['f_isincpe'] = True
            osinfo['f_cpename'] = os_row.f_cpename
            os_id = db.t_os.insert(**osinfo)
            db.commit()
        else:
            osinfo['f_isincpe'] = False
            os_id = db.t_os.insert(**osinfo)
            db.commit()
    return os_id


##-------------------------------------------------------------------------

def vuln_time_convert(vtime=''):
    """Converts Nexpose timetsamp (YYYYMMDDTHHMMSSUUU) into python datetime"""
    if not vtime:
        tval = datetime(1970, 1, 1)
    else:
        if isinstance(vtime, str):
            if vtime[8] == "T":
                tstr = "%%Y%%m%%dT%%H%%M%%S%s" % vtime[15:]
                tval = time.strptime(vtime, tstr)
            else:
                log("Unknown datetime value: %s" % vtime, logging.ERROR)
        else:
            log("Invalid datetime value provided: %s" % vtime, logging.ERROR)
            tval = datetime(1970, 1, 1)
    return datetime.fromtimestamp(time.mktime(tval))


##-------------------------------------------------------------------------

def vuln_parse(vuln, fromapi=False):
    """Parses Nexpose vulnerability XML"""

    if vuln is None: return False, False

    vulnfields = {
        'f_vulnid': vuln.attrib['id'].lower(),
        'f_title': vuln.attrib['title'],
        'f_severity': vuln.attrib['severity'],
        'f_pci_sev': vuln.attrib['pciSeverity']
    }

    if 'published' in vuln.keys():
        vulnfields['f_dt_published'] = vuln_time_convert(vuln.attrib['published'])

    vulnfields['f_dt_added'] = vuln_time_convert(vuln.attrib['added'])
    vulnfields['f_dt_modified'] = vuln_time_convert(vuln.attrib['modified'])

    if 'cvssScore' in vuln.keys():
        vulnfields['f_cvss_score'] = vuln.attrib['cvssScore']

        cvss_vectors = vuln.attrib['cvssVector'] # cvssVector="(AV:N/AC:M/Au:N/C:P/I:P/A:P)"
        vulnfields['f_cvss_av'] = cvss_vectors[4]
        vulnfields['f_cvss_ac'] = cvss_vectors[9]
        vulnfields['f_cvss_au'] = cvss_vectors[14]
        vulnfields['f_cvss_c'] = cvss_vectors[18]
        vulnfields['f_cvss_i'] = cvss_vectors[22]
        vulnfields['f_cvss_a'] = cvss_vectors[26]

    # parse the first description field, since there can only be one
    d = vuln.find("description")
    if d is not None:
        if fromapi:
            result = etree.tostring(d)
            result = result.replace("<description>", "")
            result = result.replace("</description>", "")
            vulnfields['f_description'] = html_to_markmin(result)
        else:
            d = StringIO(etree.tostring(d))
            vulnfields['f_description'] = html_to_markmin(nx_xml_to_html(d))

    references = []
    for d in vuln.findall("references/reference"):
        references.append([d.attrib['source'], d.text])

    # right now we don't do anything with tags
    #tags = []
    #for d in vuln.findall("tags/tag"):
    #    tags.append(d.text)

    # parse the first solution field, since there can only be one
    d = vuln.find("solution")
    if d is not None:
        if fromapi:
            result = etree.tostring(d)
            result = result.replace("<solution>", "")
            result = result.replace("</solution>", "")
            vulnfields['f_solution'] = html_to_markmin(result)
        else:
            d = StringIO(etree.tostring(d))
            vulnfields['f_solution'] = html_to_markmin(nx_xml_to_html(d))

    vulnfields['f_source'] = 'Nexpose'
    return vulnfields, references


##-------------------------------------------------------------------------

def import_all_vulndata(overwrite=False, nexpose_server={}):
    """
    Uses the NexposeAPI and imports each and every vulnerability to Kvasir. Can take a looooong time.

    Args:
        overwrite: Whether or not to overwrite an existing t_vulndata record

    Returns:
        msg: A string message of status.
    """
    from NexposeAPI import VulnData
    db = current.globalenv['db']

    vuln_class = VulnData()
    vuln_class.host = nexpose_server.get('host', 'localhost')
    vuln_class.port = nexpose_server.get('port', '3780')
    if vuln_class.login(user_id=nexpose_server.get('user'), password=nexpose_server.get('pw')):
        log(" [*] Populating list of Nexpose vulnerability ID summaries")
        try:
            vuln_class.populate_summary()
        except Exception, e:
            log(" [!] Error populating summaries: %s" % str(e), logging.ERROR)
            return False

        try:
            vulnxml = etree.parse(StringIO(vuln_class.vulnxml))
        except Exception, e:
            log(" [!] Error parsing summary XML: %s" % str(e), logging.ERROR)
            return False

        vulns = vulnxml.findall('VulnerabilitySummary')
        log(" [*] %s vulnerabilities to parse" % len(vulns))

        if vuln_class.vulnerabilities > 0:
            existing_vulnids = []
            [existing_vulnids.extend([x['f_vulnid']]) for x in
             db(db.t_vulndata.f_source == "Nexpose").select(db.t_vulndata.f_vulnid).as_list()]

            log(" [*] Found %d vulnerabilities in the database already." % (len(existing_vulnids)))

            stats = {'added': 0, 'updated': 0, 'skipped': 0, 'errors': 0}
            for vuln in vulns:

                if vuln.attrib['id'] in existing_vulnids and not overwrite:
                    # skip over existing entries if we're not overwriting
                    stats['skipped'] += 1
                    continue

                try:
                    vulndetails = vuln_class.detail(vuln.attrib['id'])
                except Exception, e:
                    log(" [!] Error retrieving details for %s: %s" % (vuln.attrib['id'], str(e)), logging.ERROR)
                    stats['errors'] += 1
                    if stats['errors'] == 50:
                        log(" [!] Too many errors, aborting!", logging.ERROR)
                        return False
                    else:
                        continue

                if vulndetails is not None:
                    (vulnfields, references) = vuln_parse(vulndetails.find('Vulnerability'), fromapi=True)
                else:
                    log(" [!] Unable to find %s in Nexpose" % vuln.attrib['id'], logging.WARN)
                    continue

                # add the vulnerability to t_vulndata
                vulnid = db.t_vulndata.update_or_insert(**vulnfields)
                if not vulnid:
                    vulnid = db(db.t_vulndata.f_vulnid == vulnfields['f_vulnid']).select().first().id
                    stats['updated'] += 1
                    log(" [-] Updated %s" % vulnfields['f_vulnid'])
                else:
                    stats['added'] += 1
                    log(" [-] Added %s" % vulnfields['f_vulnid'])
                db.commit()

                # add the references
                if vulnid is not None and references:
                    for reference in references:
                        # check to see if reference exists first
                        query = (db.t_vuln_refs.f_source == reference[0]) & (db.t_vuln_refs.f_text == reference[1])
                        ref_id = db.t_vuln_refs.update_or_insert(query, f_source=reference[0], f_text=reference[1])
                        if not ref_id:
                            ref_id = db(query).select().first().id

                        # make many-to-many relationship with t_vuln_data
                        db.t_vuln_references.update_or_insert(f_vuln_ref_id=ref_id, f_vulndata_id=vulnid)
                        db.commit()

            from skaldship.exploits import connect_exploits
            connect_exploits()
            msg = "%s added, %s updated, %s skipped" % (stats['added'], stats['updated'], stats['skipped'])
            log(" [*] %s" % msg)
        else:
            msg = "No vulndata populated from Nexpose"
            log(" [!] Error: %s" % msg, logging.ERROR)

    else:
        msg = "Unable to communicate with Nexpose"
        log(" [!] Error: %s" % msg, logging.ERROR)

    return msg


##-------------------------------------------------------------------------

def process_exploits(filename=None):
    """
    Process Nexpose exploits.xml file into the database
    """

    log("Processing Nexpose exploits file: %s ..." % filename)

    try:
        exploits = etree.parse(filename)
    except etree.ParseError, e:
        raise Exception("Error processing file: %s" % e)
    except IOError, e:
        raise Exception("Error opening file: %s" % e)

    r = exploits.getroot()
    counter = 0
    from exploits import add_exploit, connect_exploits
    for exploit in r.findall('exploit'):
        #"adobe-unspec-bof-cve-2010-1297","13787","0day Exploit for Adobe Flash and Reader PoC (from the wild)","Description","1","Expert"
        f_name = exploit.findtext('name')
        f_title = exploit.findtext('id')
        f_description = unicode(exploit.findtext('description')).encode('iso-8859-1').decode('cp1252')
        f_description = f_description.replace("\\'", "'").replace('\\x', "0x")
        f_source = exploit.findtext('source')
        f_level = exploit.findtext('rank') or 'Unknown'         # exploiter experience level estimate
        f_rank = exploit.findtext('exploitrank') or 'Unknown'   # rank of the exploit

        # exploit records can have multiple Nexpose vulnerabilitiy identifiers
        f_vulnid = []
        for nex_id in exploit.findall("vulnerabilities/vulnerability"):
            f_vulnid.append(nex_id.get('id').lower())

        res = add_exploit(
            cve=None,
            vuln_ids=f_vulnid,
            f_name=f_name,
            f_title=f_title,
            f_description=f_description,
            f_source=f_source,
            f_level=f_level,
            f_rank=f_rank,
        )
        if res > 0:
            counter += 1
        else:
            log("Error importing exploit: %s" % f_name, logging.ERROR)

    connect_exploits()
    log("%d exploits added/updated" % counter)
    return True


##----------------------------------------------------------------------------

def process_xml(
    filename=None,
    asset_group=None,
    engineer=None,
    msf_settings={},
    ip_ignore_list=None,
    ip_include_list=None,
    update_hosts=False,
    ):
    # Upload and process Nexpose XML Scan file

    from skaldship.cpe import lookup_cpe
    from skaldship.hosts import get_host_record
    from gluon.validators import IS_IPADDRESS
    import os

    db = current.globalenv['db']
    session = current.globalenv['session']

    parser = HTMLParser.HTMLParser()
    user_id = db.auth_user(engineer)

    # build the hosts only/exclude list
    ip_exclude = []
    if ip_ignore_list:
        ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    ip_only = []
    if ip_include_list:
        ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    log(" [*] Processing Nexpose scan file %s" % filename)

    try:
        nexpose_xml = etree.parse(filename)
    except etree.ParseError, e:
        msg = " [!] Invalid Nexpose XML file (%s): %s " % (filename, e)
        log(msg, logging.ERROR)
        return msg

    root = nexpose_xml.getroot()

    existing_vulnids = db(db.t_vulndata()).select(db.t_vulndata.id, db.t_vulndata.f_vulnid).as_dict(key='f_vulnid')
    log(" [*] Found %d vulnerabilities in the database already." % len(existing_vulnids))

    # start with the vulnerability details
    vulns_added = 0
    vulns_skipped = 0
    vulns = root.findall("VulnerabilityDefinitions/vulnerability")
    log(" [*] Parsing %d vulnerabilities" % len(vulns))
    for vuln in vulns:

        # nexpose identifiers are always lower case in kvasir. UPPER CASE IS FOR SHOUTING!!!
        vulnid = vuln.attrib['id'].lower()
        if existing_vulnids.has_key(vulnid):
            #log(" [-] Skipping %s - It's in the db already" % vulnid)
            vulns_skipped += 1
        else:
            # add the vulnerability to t_vulndata - any duplicates are errored out
            (vulnfields, references) = vuln_parse(vuln, fromapi=False)
            try:
                vulnid = db.t_vulndata.update_or_insert(**vulnfields)
                if not vulnid:
                    vulnid = db(db.t_vulndata.f_vulnid == vulnfields['f_vulnid']).select().first().id
                vulns_added += 1
                db.commit()
            except Exception, e:
                log(" [!] Error inserting %s to vulndata: %s" % (vulnfields['f_vulnid'], e), logging.ERROR)
                vulnid = None
                db.commit()
                continue

            # add the references
            if vulnid is not None:
                for reference in references:
                    # check to see if reference exists first
                    ref_id = db(db.t_vuln_refs.f_text == reference[1])
                    if ref_id.count() == 0:
                        # add because it doesn't
                        ref_id = db.t_vuln_refs.insert(f_source=reference[0], f_text=reference[1])
                        db.commit()
                    else:
                        # pick the first reference as the ID
                        ref_id = ref_id.select()[0].id

                    # make many-to-many relationship with t_vuln_data
                    res = db.t_vuln_references.insert(f_vuln_ref_id=ref_id, f_vulndata_id=vulnid)
                    db.commit()

    log(" [*] %d Vulnerabilities added, %d skipped" % (vulns_added, vulns_skipped))

    # re-make the existing_vulnids dict() since we've updated the system
    existing_vulnids = db(db.t_vulndata()).select(db.t_vulndata.id, db.t_vulndata.f_vulnid).as_dict(key='f_vulnid')

    # parse the nodes now
    nodes = root.findall("nodes/node")
    log(" [-] Parsing %d nodes" % len(nodes))
    hoststats = {'added': 0, 'skipped': 0, 'updated': 0, 'errored': 0}
    hosts = []   # array of host_id fields
    for node in nodes:
        log(" [-] Node %s status is: %s" % (node.attrib['address'], node.attrib['status']))
        #sys.stderr.write(msg)
        if node.attrib['status'] != "alive":
            hoststats['skipped'] += 1
            continue

        if node.attrib['address'] in ip_exclude:
            log(" [-] Node is in exclude list... skipping")
            hoststats['skipped'] += 1
            continue

        nodefields = {}

        if len(ip_only) > 0 and node.attrib['address'] not in ip_only:
            log(" [-] Node is not in the only list... skipping")
            hoststats['skipped'] += 1
            continue

        # we'll just take the last hostname in the names list since it'll usually be the full dns name
        names = node.findall("names/name")
        for name in names:
            nodefields['f_hostname'] = name.text

        ip = node.attrib['address']

        if IS_IPADDRESS()(ip):
            nodefields['f_ipaddr'] = ip
        else:
            log(" [!] Invalid IP Address: %s" % ip, logging.ERROR)

        nodefields['f_engineer'] = user_id
        nodefields['f_asset_group'] = asset_group
        nodefields['f_confirmed'] = False

        if 'hardware-address' in node.attrib:
            nodefields['f_macaddr'] = node.attrib['hardware-address']
        if node.find('names/name') is not None:
            # XXX: for now just take the first hostname
            nodefields['f_hostname'] = node.find('names/name').text

        # check to see if IP exists in DB already
        query = (db.t_hosts.f_ipaddr == ip)
        host_rec = db(query).select().first()
        if host_rec is None:
            host_id = db.t_hosts.insert(**nodefields)
            db.commit()
            hoststats['added'] += 1
            log(" [-] Adding IP: %s" % ip)
        elif update_hosts:
            db.commit()
            db(db.t_hosts.f_ipaddr == nodefields['f_ipaddr']).update(**nodefields)
            db.commit()
            host_id = get_host_record(nodefields['f_ipaddr'])
            host_id = host_id.id
            hoststats['updated'] += 1
            log(" [-] Updating IP: %s" % ip)
        else:
            hoststats['skipped'] += 1
            db.commit()
            log(" [-] Skipped IP: %s" % ip)
            continue
        hosts.append(host_id)

        # tests that aren't specific to any port we wrap up into a meta service
        # called "INFO"
        tests = node.findall("tests/test")
        if len(tests) > 0:
            svc_id = db.t_services.update_or_insert(f_proto="info", f_number="0", f_status="info", f_hosts_id=host_id)
            db.commit()

        for test in tests:
            d = {}
            vulnid = test.get('id').lower()

            # we may have valid username.
            if "cifs-acct-" in vulnid:
                username = test.get('key')
                if username is not None:
                    d['f_services_id'] = svc_id
                    d['f_username'] = username
                    d['f_active'] = True
                    d['f_source'] = vulnid
                    query = (db.t_accounts.f_services_id == d['f_services_id']) &\
                            (db.t_accounts.f_username == d['f_username'])
                    db.t_accounts.update_or_insert(query, **d)
                    db.commit()

            if test.attrib['status'] == 'vulnerable-exploited' or \
               test.attrib['status'] == 'potential' or \
               test.attrib['status'] == 'exception-vulnerable-exploited' or \
               test.attrib['status'] == 'exception-vulnerable-version' or \
               test.attrib['status'] == 'exception-vulnerable-potential' or \
               test.attrib['status'] == 'vulnerable-version':
                if vulnid in existing_vulnids:
                    vuln_id = existing_vulnids[vulnid]['id']
                else:
                    continue

                if vulnid == 'cifs-nt-0001':
                    # Windows users, local groups, and global groups
                    infotext = nx_xml_to_html(StringIO(etree.tostring(test, xml_declaration=False)))
                    try:
                        unames = re.search("Found user\(s\): (?P<unames>.+?) </li>", infotext).group('unames')
                    except AttributeError, e:
                        # regex not found
                        continue
                    for uname in unames.split():
                        # add account
                        d['f_username'] = uname
                        d['f_services_id'] = svc_id
                        d['f_source'] = 'cifs-nt-0001'
                        db.t_accounts.update_or_insert(**d)
                        db.commit()

                test_str = etree.tostring(test, xml_declaration=False, encoding=unicode)
                test_str = test_str.encode('ascii', 'xmlcharrefreplace')
                proof = nx_xml_to_html(StringIO(test_str))
                proof = html_to_markmin(proof)

                if vulnid == 'cifs-insecure-acct-lockout-limit':
                    d['f_hosts_id'] = host_id
                    try:
                        d['f_lockout_limit'] = re.search("contains: (?P<l>\d+)", proof).group('l')
                    except AttributeError:
                        d['f_lockout_limit'] = 0
                    query = (db.t_netbios.f_hosts_id == host_id)
                    db.t_netbios.update_or_insert(query, **d)
                    db.commit()

                # Check for CIFS uid/pw
                if "cifs-" in vulnid:
                    try:
                        uid = re.search("uid\[(?P<u>.*?)\]", proof).group('u')
                        pw = re.search("pw\[(?P<p>.*?)\]", proof).group('p')
                        realm = re.search("realm\[(?P<r>.*?)\]", proof).group('r')
                        d = {
                            'f_services_id': svc_id,
                            'f_username': uid,
                            'f_password': pw,
                            'f_description': realm,
                            'f_active': True,
                            'f_compromised': True,
                            'f_source': vulnid
                        }
                        query = (db.t_accounts.f_services_id == svc_id) & (db.t_accounts.f_username == uid)
                        db.t_accounts.update_or_insert(query, **d)
                        db.commit()
                    except AttributeError:
                        db.commit()
                    except Exception, e:
                        log("Error inserting account (%s): %s" % (uid, e), logging.ERROR)
                    db.commit()

                # solaris-kcms-readfile shadow file
                if vulnid.lower() == "rpc-solaris-kcms-readfile":
                    # funky chicken stuff, if they mess with this output then we've got to
                    # change this around as well. thems the breaks, maynard!
                    shadow = parser.unescape(proof)
                    for line in shadow.split("<br />")[1:-1]:
                        user, pw, uid = line.split(':')[0:3]
                        d['f_services_id'] = svc_id
                        d['f_username'] = user
                        d['f_hash1'] = pw
                        d['f_hash1_type'] = "crypt"
                        d['f_uid'] = uid
                        d['f_source'] = "shadow"
                        d['f_active'] = True
                        d['f_source'] = "rpc-solaris-kcms-readfile"
                        query = (db.t_accounts.f_services_id == svc_id) & (db.t_accounts.f_username == user)
                        db.t_accounts.update_or_insert(query, **d)
                        db.commit()

                db.t_service_vulns.update_or_insert(
                    f_services_id=svc_id,
                    f_status=test.attrib['status'],
                    f_proof=proof,
                    f_vulndata_id=vuln_id
                )

                if "cisco-default-http-account" in vulnid.lower():
                    d['f_services_id'] = svc_id
                    d['f_username'] = vulnid.split('-')[4]
                    d['f_password'] = vulnid.split('-')[6]
                    d['f_source'] = "cisco-default-http-account"
                    query = (db.t_accounts.f_services_id == svc_id) & (db.t_accounts.f_username == d['f_username'])
                    db.t_accounts.update_or_insert(query, **d)
                    db.commit()

        # add services (ports) and resulting vulndata
        for endpoint in node.findall("endpoints/endpoint"):
            f_proto = endpoint.attrib['protocol']
            f_number = endpoint.attrib['port']
            f_status = endpoint.attrib['status']

            query = (db.t_services.f_hosts_id == host_id) \
                    & (db.t_services.f_proto == f_proto) \
                    & (db.t_services.f_number == f_number)
            svc_id = db.t_services.update_or_insert(
                query,
                f_proto=f_proto,
                f_number=f_number,
                f_status=f_status,
                f_hosts_id=host_id
            )
            if not svc_id:
                svc_id = db(query).select().first().id

            for service in endpoint.findall("services/service"):
                d = {}
                if 'name' in service.attrib:
                    db.t_services[svc_id] = dict(f_name=service.attrib['name'])

                for test in service.findall("tests/test"):
                    vulnid = test.get('id').lower()

                    if test.attrib['status'] == 'vulnerable-exploited' or \
                       test.attrib['status'] == 'potential' or \
                       test.attrib['status'] == 'exception-vulnerable-exploited' or \
                       test.attrib['status'] == 'exception-vulnerable-version' or \
                       test.attrib['status'] == 'exception-vulnerable-potential' or \
                       test.attrib['status'] == 'vulnerable-version':
                        if vulnid in existing_vulnids:
                            vuln_id = existing_vulnids[vulnid]['id']
                        else:
                            log(" [!] Unknown vulnid, Skipping! (id: %s)" % vulnid, logging.ERROR)
                            continue

                        test_str = etree.tostring(test, xml_declaration=False, encoding=unicode)
                        test_str = test_str.encode('ascii', 'xmlcharrefreplace')
                        proof = nx_xml_to_html(StringIO(test_str))
                        proof = html_to_markmin(proof)

                        # Check for SNMP strings
                        if "snmp-read-" in vulnid:
                            snmpstring = re.search("pw\[(?P<pw>.*?)\]", proof).group('pw')
                            db.t_snmp.update_or_insert(
                                f_hosts_id=host_id,
                                f_community=snmpstring,
                                f_access="READ",
                                f_version="v1"
                            )
                            db.commit()

                        if "snmp-write" in vulnid:
                            snmpstring = re.search("pw\[(?P<pw>.*?)\]", proof).group('pw')
                            db.t_snmp.update_or_insert(
                                f_hosts_id=host_id,
                                f_community=snmpstring,
                                f_access="WRITE",
                                f_version="v1"
                            )
                            db.commit()

                        # TODO: account names

                        # Dell DRAC root/calvin
                        if vulnid == "http-drac-default-login":
                            d['f_services_id'] = svc_id
                            d['f_username'] = 'root'
                            d['f_password'] = 'calvin'
                            d['f_active'] = True
                            d['f_compromised'] = True
                            d['f_source'] = vulnid
                            query = (db.t_accounts.f_services_id == svc_id) & (db.t_accounts.f_username == 'root')
                            db.t_accounts.update_or_insert(query, **d)
                            db.commit()

                        # Check for uid/pw
                        if "ftp-iis-" in vulnid or \
                           "telnet-" in vulnid or \
                           "cifs-" in vulnid or \
                           "tds-" in vulnid or \
                           "oracle-" in vulnid or \
                           "-default-" in vulnid or \
                           "ftp-generic-" in vulnid:
                            try:
                                uid = re.search("uid\[(?P<u>.*?)\]", proof).group('u')
                                pw = re.search("pw\[(?P<p>.*?)\]", proof).group('p')
                                realm = re.search("realm\[(?P<r>.*?)\]", proof).group('r')
                                d['f_services_id'] = svc_id
                                d['f_username'] = uid
                                d['f_password'] = pw
                                d['f_description'] = realm
                                d['f_active'] = True
                                d['f_compromised'] = True
                                d['f_source'] = vulnid
                                query = (db.t_accounts.f_services_id == svc_id) & (db.t_accounts.f_username == uid)
                                db.t_accounts.update_or_insert(query, **d)
                                db.commit()
                            except AttributeError:
                                db.commit()
                            except Exception, e:
                                log("Error inserting account (%s): %s" % (uid, e), logging.ERROR)
                            db.commit()

                        # cisco default http login accounts
                        if "cisco-default-http-account" in vulnid.lower():
                            d['f_services_id'] = svc_id
                            d['f_username'] = vulnid.split('-')[4]
                            d['f_password'] = vulnid.split('-')[6]
                            d['f_source'] = "cisco-default-http-account"
                            query = (db.t_accounts.f_services_id == svc_id) \
                                    & (db.t_accounts.f_username == d['f_username'])
                            db.t_accounts.update_or_insert(query, **d)
                            db.commit()

                        db.t_service_vulns.update_or_insert(
                            f_services_id=svc_id,
                            f_status=test.attrib['status'],
                            f_proof=proof,
                            f_vulndata_id=vuln_id
                        )
                        db.commit()

                for config in service.findall("configuration/config"):
                    db.t_service_info.update_or_insert(
                        f_services_id=svc_id,
                        f_name=config.attrib['name'],
                        f_text=config.text
                    )
                    db.commit()
                    if re.match('\w+.banner$', config.attrib['name']):
                        db.t_services[svc_id] = dict(f_banner=config.text)
                        db.commit()
                    if config.attrib['name'] == 'mac-address':
                        # update the mac address of the host
                        db.t_hosts[host_id] = dict(f_macaddr=config.text)
                        db.commit()
                    if "advertised-name" in config.attrib['name']:
                        # netbios computer name
                        d = config.text.split(" ")[0]
                        if "Computer Name" in config.text:
                            data = {'f_netbios_name': d}
                            # if hostname isn't defined then lowercase netbios name and put it in
                            if db.t_hosts[host_id].f_hostname is None:
                                data['f_hostname'] = d.lower()
                            db(db.t_hosts.id == host_id).update(**data)
                            db.commit()
                        elif "Domain Name" in config.text:
                            query = (db.t_netbios.f_hosts_id == host_id)
                            db.t_netbios.update_or_insert(query, f_hosts_id=host_id, f_domain=d)
                        db.commit()

        for os_rec in node.findall('fingerprints/os'):
            """
            <os  certainty="1.00" device-class="Workstation" vendor="Microsoft" family="Windows" product="Windows 2000 Professional" version="SP4" arch="x86"/>

            if using SCAP output the os line looks like:

            <os  certainty="0.66" device-class="General" vendor="Microsoft" family="Windows" product="Windows XP" arch="x86" cpe="cpe:/o:microsoft:windows_xp::sp3"/>
            """

            if os_rec.attrib.has_key('cpe'):
                # we have a cpe entry from xml! hooray!
                cpe_name = os_rec.attrib['cpe'].replace('cpe:/o:', '')
                os_id = lookup_cpe(cpe_name)
            else:
                # no cpe attribute in xml, go through our messy lookup
                os_id = guess_cpe_os(os_rec)

            if os_id is not None:
                db.t_host_os_refs.update_or_insert(
                    f_certainty=os_rec.attrib['certainty'],
                    f_family=os_rec.get('family', 'Unknown'),
                    f_class=os_rec.get('device-class', 'Other'),
                    f_hosts_id=host_id,
                    f_os_id=os_id
                )
                db.commit()
            else:
                log(" [!] os_rec could not be parsed: %s" % etree.tostring(os_rec), logging.ERROR)

        db.commit()

    if msf_settings.get('workspace'):
        try:
            # check to see if we have a Metasploit RPC instance configured and talking
            from MetasploitProAPI import MetasploitProAPI
            msf_api = MetasploitProAPI(host=msf_settings.get('url'), apikey=msf_settings.get('key'))
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
    connect_exploits()
    do_host_status(asset_group=asset_group)

    msg = " [*] Import complete: hosts: %s added, %s skipped, %s errors - vulns: %s added, %s skipped" % (
        hoststats['added'],
        hoststats['skipped'],
        hoststats['errored'],
        vulns_added, vulns_skipped
    )
    log(msg)
    return msg
