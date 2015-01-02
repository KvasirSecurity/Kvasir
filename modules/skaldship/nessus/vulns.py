# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2014 Kurt Grutzmacher
##
## Nessus Vulnerabilities for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from gluon import current
import re
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
        self.ref_types = ['cve', 'osvdb', 'bid', 'urls', 'cpe', 'cert', 'cwe']
        # list of references that are single fields in the xml vulndata
        self.single_refs = ['msft']

    def db_vuln_refs(self, vuln_id=None, vulndata={}, extradata={}):
        """
        Add or update vulnerability references such as CPE, MSF Bulletins, OSVDB, Bugtraq, etc.

        :param vuln_id: The db.t_vulndata reference id
        :param vulndata: A dictionary of vulnerability data from t_vulndata
        :param extradata: A dictionary of extra vulndata
        :returns None: Nothing.
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

        :param rpt_item: A ReportItem field (etree._Element or CSV line)
        :returns t_vulndata.id: integer field of db.t_vulndata[id]
        :returns vulndata: A dictionary of fields for t_vulndata
        :returns extradata: A dictionary of extra data fields such as references
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
            extradata['see_also'] = rpt_item.findtext('see_also', '').split('\n')
            extradata['script_version'] = rpt_item.findtext('script_version', '')
            extradata['plugin_type'] = rpt_item.findtext('plugin_type', '')
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
            fname = fname.replace('.nasl', '')
            fname = fname.replace('.nbin', '')
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
        self.db.commit()
        if not vuln_id:
            vuln_id = self.db(self.db.t_vulndata.f_vulnid == f_vulnid).select().first().id

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

