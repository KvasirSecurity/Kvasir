#!/usr/bin/env python
#coding:utf-8
# Author:  Kurt Grutzmacher -- <grutz@jingojango.net>
# Purpose: Nexpose API Interface
# Created: 01/28/10

__version__ = "1.1"
__author__ = "Kurt Grutzmacher <grutz@jingojango.net>"

import os, sys, random
import unittest
import urllib, urllib2
import logging
logger = logging.getLogger("web2py.app.kvasir")

try:
    from lxml import etree as etree
except ImportError:
    try:
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
            import xml.etree.ElementTree as etree
        except ImportError:
            raise Exception, "Unable to load any XML libraries for etree!"\
                  "Please install an xml library or Python 2.5 at least"

########################################################################
class NexposeAPIError(RuntimeError):
    pass

########################################################################
class NexposeAPI():
    """
    Nexpose API class for Python

    XXX: This does not perform server certificate verification!
    """

    #----------------------------------------------------------------------
    def __init__(self, host='127.0.0.1', port='3780'):
        self.log = logging.getLogger(self.__class__.__name__)
        self.opener = urllib2.build_opener()
        self.host = host
        self.port = port
        self.apiversion = "1.1"
        self.opener = urllib2.build_opener()
        self.sessionid = None
        self.syncid = random.randint(1, 65535)

    #----------------------------------------------------------------------
    def isLoggedIn(self):
        """
        Check to see if a session is logged in.
        """

        if self.sessionid:
            return True
        else:
            return False

    #----------------------------------------------------------------------
    def send_command(self, post_data=""):
        """
        Send XML request to Nexpose server and parse response.
        Performs a login if self.sessionid is None
        """

        url = "https://%s:%s/api/%s/xml" %(self.host, self.port, self.apiversion)
        if len(post_data) == 0:
            self.log.error("No XML text sent, can't do anthing.")
            return

        #post_data = urllib.urlencode(bodytext)
        req = urllib2.Request(url, data=post_data, headers={"Content-Type": "text/xml"})
        try:
            return self.opener.open(req)
        except:
            (exc_type, exc_value, exc_tb) = sys.exc_info()
            try:
                result = etree.parse(exc_value)
                self.log.warn("Caught a traceback: %r. etree result = %r", exc_value, result)
            except:
                mesg = exc_value
            raise NexposeAPIError(mesg)

    #----------------------------------------------------------------------
    def make_xml(self, name="", attributes={}, isroot=False, *args, **kwargs):
        """
        Generate an XML document and return the ascii text

        Requires an element name (name) and a dictionary of attributes that
        will be added to the element.
        """
        root = etree.Element(name)

        if isroot:
            root.set("sync-id", str(self.syncid))
            if self.sessionid:
                root.set('session-id', self.sessionid)

        for item in attributes.items():
            if item[1] == None:
                item[1] == ""
            root.set(item[0], item[1])

        if len(args) > 0:
            # We have multiple subelements, lets add them now
            for record in args:
                for element in record.keys():
                    child = etree.SubElement(root, element)
                    for item in record[element].items():
                        child.set(item[0], item[1])

        # don't need to add the standard xml header so we can create multiple xml elements
        # with this routine. It will always return a string.
        #return etree.tostring(root, xml_declaration=True, encoding='iso-8859-1')
        try:
            result = etree.tostring(root)
        except Exception, e:
            self.log.error("Error creating XML: %s" % (e))
            result = ""

        return result

    #----------------------------------------------------------------------
    def login(self, user_id="nxadmin", password="password"):
        """
        Process a login request and report success/failure
        """

        if self.sessionid:
            # remove any existing session ID
            self.sessionid = None

        attributes = {
            'user-id': user_id,
            'password': password,
        }

        loginxml = self.make_xml('LoginRequest', attributes, isroot=True)
        self.log.debug("Sending Login request:\n%s" % (loginxml))
        try:
            result = self.send_command(loginxml)
        except NexposeAPIError, e:
            self.log.error("Error connecting to Nexpose: %s" % (e))
            return False

        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            self.sessionid = data.attrib['session-id']
            self.log.debug("Session-id: %s" % (self.sessionid))
            return True
        else:
            self.log.warn("Failed to login!")

        return False

    #----------------------------------------------------------------------
    def logout(self):
        """
        Process a logout request and report success/failure
        """

        attributes = {
        }

        xml = self.make_xml('LogoutRequest', attributes, isroot=True)
        self.log.debug("Sending logout request:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            self.sessionid = None
            return True
        else:
            self.log.warn("Logout failed, clearing session anyways")
            self.sessionid = None

        return False

########################################################################
class Sites(NexposeAPI):
    """
    Nexpose Site configuration class
    """

    #----------------------------------------------------------------------
    def __init__(self, sessionid=None):
        NexposeAPI.__init__(self)
        if sessionid is not None:
            self.sessionid = sessionid
        self.log = logging.getLogger(self.__class__.__name__)
        self.site_id = "0"
        self.name = ""
        self.description = ""
        self.riskfactor = ""
        self.hosts = []
        self.credentials = {}
        self.alerts = {}

    #----------------------------------------------------------------------
    def save(self, siteid="-1", hosts=[], name="", description="", template="pentest-audit"):
        """
        Save changes to a new or existing site.

        XXX: Fix this.. it doesn't respond correctly!
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        if not name:
            self.log.warn("No site name set, generating random name")
            import random, string
            name = "".join([random.choice(string.digits + string.letters) for i in xrange(15)])

        hostxml=[]
        for host in hosts:
            hostxml.append("<Host>%s</Host>" % (host))

        # manually build the request
        xml = """
<SiteSaveRequest session-id="%s">
    <Site id="%s" name="%s" description="%s">
        <Hosts>%s</Hosts>
        <Credentials></Credentials>
        <Alerting></Alerting>
        <ScanConfig configID="%s" name="%s" templateID="%s"></ScanConfig>"
    </Site>
</SiteSaveRequest>""" % (self.sessionid, siteid, name, description, "".join(hostxml), siteid, name, template)

        #xml = self.make_xml('SiteSaveRequest', attributes, isroot=True)
        self.log.debug("Sending SiteSaveRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return True
        else:
            errormsg = data.xpath('//message')[0].text
            self.log.warn("Failed SiteSaveRequest: %s " % (errormsg))

        return False

    #----------------------------------------------------------------------
    def scan(self, siteid):
        """
        Starts a scan of a site. Requires the Site ID number
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        if siteid < 1:
            self.log.warn("No SiteID provided")
            return ""

        attributes = {
            'site-id': str(siteid),
        }

        xml = self.make_xml('SiteScanRequest', attributes, isroot=True)
        self.log.debug("Sending SiteScanRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        result = {}
        if data.attrib['success'] == '1':
            return "Scan Started"
        else:
            self.log.warn("SiteScanRequest failed")

        return ""

    #----------------------------------------------------------------------
    def listings(self):
        """
        Provide a list of all sites the user is authorized to view or manage.

        Returns a dict of sites keyed with site id.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('SiteListingRequest', attributes, isroot=True)
        self.log.debug("Sending SiteListing request:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        result = {}
        if data.attrib['success'] == '1':
            sites = data.findall('SiteSummary')
            for site in sites:
                result[site.attrib['id']] = {
                    'name': site.attrib['name'],
                    'description': site.attrib['description'],
                    'riskfactor': site.attrib['riskfactor'],
                    'riskscore': site.attrib['riskscore'],
                }
            return result
        else:
            self.log.warn("SiteListing failed")

        return {}

    #----------------------------------------------------------------------
    def config(self, siteid=None):
        """
        Provide the configuration of a site including its associated assets.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        if siteid < 1:
            self.log.warn("No SiteID provided")
            return ""

        attributes = {
            'site-id': str(siteid),
        }

        xml = self.make_xml('SiteConfigRequest', attributes, isroot=True)
        self.log.debug("Sending SiteConfigRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        result = {}
        if data.attrib['success'] == '1':

            # find all the ranges and put the resulting dict into an incremental
            # dict of ranges
            ranges = data.findall('Site/Hosts/range')
            result['ranges'] = {}
            if len(ranges) > 0:
                count = 0
                for r in ranges:
                    result['ranges'][count] = r.attrib
                    count += 1

            # place the scanconfig data into a dict
            scanconfig = data.find('Site/ScanConfig')
            if len(scanconfig) > 0:
                result['scanconfig'] = scanconfig.attrib
            else:
                result['scanconfig'] = {}

            return result
        else:
            self.log.warn("SiteListing failed")

        return ""

########################################################################
class AssetGroup(NexposeAPI):
    """
    TODO: AssetGroup!
    """

    #----------------------------------------------------------------------
    def __init__(self, sessionid=None):
        """Constructor"""
        NexposeAPI.__init__(self)
        if sessionid is not None:
            self.sessionid = sessionid
        self.log = logging.getLogger(self.__class__.__name__)


    #----------------------------------------------------------------------
    def listing(self):
        """
        Provide a list of all asset groups the user is authorized to view or manage.

        Returns a dict of asstegroups keyed with group id.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('AssetGroupListingRequest', attributes, isroot=True)
        self.log.debug("Sending AssetGroupListingRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        result = {}
        if data.attrib['success'] == '1':
            #sites = data.findall('SiteSummary')
            #for site in sites:
            #    result[site.attrib['id']] = {
            #        'name': site.attrib['name'],
            #        'description': site.attrib['description'],
            #        'riskfactor': site.attrib['riskfactor'],
            #        'riskscore': site.attrib['riskscore'],
            #    }
            return result
        else:
            self.log.warn("AssetGroupListing failed")

        return {}

########################################################################
class Scan(NexposeAPI):
    """"""

    #----------------------------------------------------------------------
    def __init__(self, sessionid=None):
        """Constructor"""
        NexposeAPI.__init__(self)
        if sessionid is not None:
            self.sessionid = sessionid
        self.log = logging.getLogger(self.__class__.__name__)

    #----------------------------------------------------------------------
    def scanactivity(self):
        """
        Provide a list of current scan activities across all scan engines managed by the security console.

        Returns a dict of scanactivity keyed with group id.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('ScanActivityRequest', attributes, isroot=True)
        self.log.debug("Sending ScanActivityRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        scans = tree.getroot()
        result = {}
        if scans.attrib['success'] == '1':
            #sites = data.findall('SiteSummary')
            #for site in sites:
            #    result[site.attrib['id']] = {
            #        'name': site.attrib['name'],
            #        'description': site.attrib['description'],
            #        'riskfactor': site.attrib['riskfactor'],
            #        'riskscore': site.attrib['riskscore'],
            #    }
            return result
        else:
            self.log.warn("ScanActivity failed")

        return {}

    #----------------------------------------------------------------------
    def scanaction(self, action="Pause", scanid="1"):
        """
        A multiple function that performs actions against Scans where ...

        action = Pause/Resume/Stop :: a running scan.
        action = Status :: return status of a scan
        action = Statistics :: return statistics of a scan

        Case is important with action.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'scan-id': scanid,
        }

        reqtype = "Scan%sRequest" % (action)
        xml = self.make_xml(reqtype, attributes, isroot=True)
        self.log.debug("Sending %s:\n%s" % (reqtype, xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if action in ['Pause', 'Resume', 'Stop']:
            if data.attrib['success'] == '1':
                self.log.warn("%s succeeded" % (reqtype))
                return True
            else:
                self.log.warn("%s failed: %s" % (reqtype, data.find('Failure/message').text))
                return False

        result = {}

        if action == "Status":
            result['engine-id'] = data.attrib['engine-id']
            result['scan-id'] = data.attrib['scan-id']
            result['status'] = data.attrib['status']
            return result

        if action == "Statistics":
            # TODO: This...
            return result

        return False

########################################################################
class VulnData(NexposeAPI):
    """
    The Nexpose vulnerability class. Supports vulnerabilities summary
    output and detailed vulnerability requests
    """

    def __init__(self, sessionid=None):
        """"""
        NexposeAPI.__init__(self)
        if sessionid is not None:
            self.sessionid = sessionid
        self.vulnerabilities = {}
        self.vulnxml = ""
        self.log = logging.getLogger(self.__class__.__name__)

    #----------------------------------------------------------------------
    def populate_summary(self):
        """
        Populates a summary list of vulnerabilities checked by Nexpose to a dict.

        Must provide a NexposeAPI instance to use.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('VulnerabilityListingRequest', attributes, isroot=True)
        self.log.debug("Sending VulnerabilityListingRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            vulns = data.findall('VulnerabilitySummary')
            self.vulnxml = etree.tostring(data)
            for vuln in vulns:
                self.vulnerabilities[vuln.attrib['id']] = vuln.attrib
                #del(self.vulnerabilities[vuln.attrib['id']]['id'])
        else:
            self.log.warn("VulnerabilityListing failed")
            return False

        self.log.debug("Loaded %s Vulnerabilities..." % (len(self.vulnerabilities)))
        return True

    #----------------------------------------------------------------------
    def csvout(self):
        """
        Retrn a string of vulnerability data in csv format
        """
        if (self.vulnerabilities) < 1:
            self.log.error("No vulnerabilities populated, returning empty")
            return ""

        import csv, StringIO

        csvout = StringIO.StringIO()
        writer = csv.DictWriter(csvout, fieldnames=('id', 'title', 'severity', 'pciSeverity', 'cvssScore', 'cvssVector', 'published', 'added', 'modified'))
        for vuln in self.vulnerabilities.keys():
            writer.writerow(self.vulnerabilities[vuln])

        return csvout.getvalue()

    #----------------------------------------------------------------------
    def detail(self, vulnid="1"):
        """
        Provide the full details of a vulnerability, including its description, cross-references, and solution.

        Returns a python dictionary result
        """

        attributes = {
            'vuln-id': vulnid,
        }

        xml = self.make_xml('VulnerabilityDetailsRequest', attributes, isroot=True)
        self.log.debug("Sending VulnerabilityDetailsRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            #result = {}
            #vuln = data.find('Vulnerability')
            #vulnid = vuln.attrib['id']
            #result[vulnid] = vuln.attrib
            #for child in vuln.getchildren():
            #    result[vulnid][child] = child.text
            return data
        else:
            self.log.warn("VulnerabilityDetailsRequest failed: %s" % (data.find('Failure/message').text))

        return None


########################################################################
class Report(NexposeAPI):
    """
    Nexpose Reporting Tempaltes and Configuration
    """

    #----------------------------------------------------------------------
    def __init__(self, sessionid=None):
        NexposeAPI.__init__(self)
        if sessionid is not None:
            self.sessionid = sessionid
        self.log = logging.getLogger(self.__class__.__name__)

    #----------------------------------------------------------------------
    def templates(self):
        """
        Provide a list of all report templates the user can access on the security console.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('ReportTemplateListingRequest', attributes, isroot=True)
        self.log.debug("Sending ReportTemplateListingRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            self.log.warn("ReportTemplateListingRequest failed: %s" % (data.find('Failure/message').text))

        return {}

    #----------------------------------------------------------------------
    def listing(self):
        """
        Provide a listing of all report definitions the user can access on the security console.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        xml = self.make_xml('ReportListingRequest', attributes, isroot=True)
        self.log.debug("Sending ReportListingRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            self.log.warn("ReportListingRequest failed: %s" % (data.find('Failure/message').text))

        return {}

    #----------------------------------------------------------------------
    def templateconfig(self, templateid=1):
        """
        Retrieve the configuration for a report template
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'template-id': str(templateid)
        }

        xml = self.make_xml('ReportTemplateConfigRequest', attributes, isroot=True)
        self.log.debug("Sending ReportTemplateConfigRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            self.log.warn("ReportTemplateConfigRequest failed: %s" % (data.find('Failure/message').text))

        return {}

    #----------------------------------------------------------------------
    def history(self, reportcfg=1):
        """
        Provide a history of all reports generated with the specified report definition.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'reportcfg-id': str(reportcfg)
        }

        xml = self.make_xml('ReportHistoryRequest', attributes, isroot=True)
        self.log.debug("Sending ReportHistoryRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            self.log.warn("ReportHistoryRequest failed: %s" % (data.find('Failure/message').text))

        return {}

    #----------------------------------------------------------------------
    def getconfig(self, reportcfg=1):
        """
        Retrieve the configuration for a report definition.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'reportcfg-id': str(reportcfg)
        }

        xml = self.make_xml('ReportConfigRequest', attributes, isroot=True)
        self.log.debug("Sending ReportConfigRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            self.log.warn("ReportConfigRequest failed: %s" % (data.find('Failure/message').text))

        return {}

    #----------------------------------------------------------------------
    def generate(self, reportid=1):
        """
        Generate a new report using the specified report definition.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'report-id': str(reportid)
        }

        xml = self.make_xml('ReportGenerateRequest', attributes, isroot=True)
        self.log.debug("Sending ReportGenerateRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            try:
                error = data.find('Failure/message').text
            except:
                error = data.find('Exception/message').text
            self.log.warn("ReportGenerateRequest failed: %s" % (error))

        return {}

    #----------------------------------------------------------------------
    def delete(self, reportcfgid=1, reportid=1):
        """
        Delete a previously generated report or report definition.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
            'reportcfg-id': str(reportcfgid),
            'report-id': str(reportid)
        }

        xml = self.make_xml('ReportDeleteRequest', attributes, isroot=True)
        self.log.debug("Sending ReportDeleteRequest:\n%s" % (xml))
        result = self.send_command(xml)
        tree = etree.parse(result)
        self.log.debug("Result: %s" % (etree.tostring(tree)))
        data = tree.getroot()
        if data.attrib['success'] == '1':
            return data
        else:
            try:
                error = data.find('Failure/message').text
            except:
                error = data.find('Exception/message').text
            self.log.warn("ReportDeleteRequest failed: %s" % (error))

        return {}

    #----------------------------------------------------------------------
    def adhoc_generate(self, templateid='full-audit', rptformat='scap-xml', filtertype='site', filterid='1', compareto=None):
        """
        Generate a report once using a simple configuration, and send it back in a multipart mime response.
        """

        if not self.isLoggedIn():
            self.log.warn("No Nexpose API instance provided...")
            return False

        attributes = {
        }

        # ghetto the xml generation here... oh well!

        xml = """
<ReportAdhocGenerateRequest session-id="%s" sync-id="%s">
  <AdhocReportConfig template-id="%s" format="%s"/>
  <Filters>
    <filter type="%s" id="%s"/>
  </Filters>
</ReportAdhocGenerateRequest>""" % (self.sessionid, self.syncid, templateid, rptformat, filtertype, filterid)

        if compareto:
            xml += """<Baseline compareTo="%(compareto)s"/>\n"""

        self.log.debug("Sending ReportAdhocGenerateRequest:\n%s" % (xml))
        result = self.send_command(xml)

        response = ''.join(result.readlines())
        if response.find('--AxB9sl3299asdjvbA') == -1:
            tree = etree.fromstring(response)
            try:
                error = tree.find('Failure/message').text
            except:
                error = tree.find('Exception/message').text
            self.log.warn("ReportAdhocGenerateRequest failed: %s" % (error))

            return ""

        resp_text = response.split('--AxB9sl3299asdjvbA')[1].split('response_xml')[1]
        tree = etree.fromstring(resp_text)
        self.log.debug("Response XML: %s" % (etree.tostring(tree)))

        if tree.get('success') == '1':
            # result is successful, return the report data
            import base64
            return base64.b64decode(response.split('--AxB9sl3299asdjvbA')[2].split('base64')[1])
        else:
            try:
                error = tree.find('Failure/message').text
            except:
                error = tree.find('Exception/message').text
            self.log.warn("ReportAdhocGenerateRequest failed: %s" % (error))

        return ""


########################################################################
class APIUnitTests(unittest.TestCase):
    """
    Nexpose API Unit Tests
    """

    def testLoginRequest(self):
        napi = NexposeAPI()
        napi.user_id = "test"
        napi.password = "password"
        validxml = "<?xml version='1.0' encoding='iso-8859-1'?>\n<LoginRequest><user-id>test</user-id><password>password</password></LoginRequest>"
        loginxml = napi.loginrequest()
        self.assertEqual(loginxml, validxml, "login:\n\texpecting: %s\n\treceived: %s" % (validxml, loginxml))

########################################################################

if __name__=='__main__':
    from optparse import OptionParser

    # set up commandline arguments
    Progname=os.path.basename(sys.argv[0])
    Usage="%prog usage: XXX:[command_line_args]\n" \
         "%prog usage: -h\n" \
         "%prog usage: -V"
    optparser = OptionParser(usage=Usage, version="%prog: $Id:$" )
    optparser.add_option("-d", "--debug", dest = "debug", action="store_true", help="log debugging messages")
    optparser.add_option("-t", "--tests", dest = "unittest", action="store_true", help="Perform unit tests")
    optparser.add_option("-u", "--userid", dest = "userid", action="store", default="nxadmin", help="Username")
    optparser.add_option("-p", "--passwd", dest = "password", action="store", default="password", help="Password")
    optparser.add_option("-v", "--verbose", dest = "verbose", action="store_true", help="be verbose")
    optparser.add_option("-s", "--server", dest = "server", action="store", default="localhost", help="Nexpose Server")
    optparser.add_option("-r", "--port", dest = "port", action="store", default="3780", help="Nexpose Port")
    optparser.add_option("-l", "--listvulns", dest = "listvulns", action="store", default=None, help="List vuln summary (xml|csv)")
    optparser.add_option("-i", "--interactive", dest = "interactive", action="store_true", help="Drop into an interactive prompt")
    optparser.add_option("-b", "--basictests", dest = "basictests", action="store_true", help="Run some basic tests")


    #optparser.add_option("-N", "--name", dest="var_n",
    #  action= "store" | "append" | "store_true" | "store_false"
    #  type = "int"
    #  default="foo", metavar="SOME_STRING", help="store a string")
    (options, params) = optparser.parse_args()

    root_log = logging.getLogger()
    if options.debug:
        root_log.setLevel(logging.DEBUG)
    elif options.verbose:
        root_log.setLevel(logging.INFO)
    else:
        root_log.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    logformat = "%(name)s: %(levelname)s: %(message)s"
    handler.setFormatter(logging.Formatter(logformat))
    root_log.addHandler(handler)
    log = logging.getLogger(Progname)

    if options.unittest:
        suite = unittest.TestLoader().loadTestsFromTestCase(APIUnitTests)
        unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(0)

    napi = NexposeAPI()
    napi.host = options.server
    napi.port = options.port
    napi.login(options.userid, options.password)

    if options.interactive:
        try:
            import IPython
        except ImportError:
            sys.exit("IPython not installed, won't continue...")

        argv = ['-pi1','In <\\#>:','-pi2','   .\\D.:','-po','Out<\\#>:']
        banner = '*** Starting Interactive Shell - Ctrl-D to exit...\n\nnapi is your NexposeAPI variable to play with\n'

        if IPython.__version__ >= "0.11":
            from IPython.config.loader import Config
            cfg = Config()
            cfg.InteractiveShellEmbed.prompt_in1="myprompt [\\#]> "
            cfg.InteractiveShellEmbed.prompt_out="myprompt [\\#]: "
            #cfg.InteractiveShellEmbed.profile=ipythonprofile
            # directly open the shell
            IPython.embed(config=cfg, banner2=banner)
        else:
            try:
                from IPython.Shell import IPShellEmbed
                argv = ['-pi1','In <\\#>:','-pi2','   .\\D.:','-po','Out<\\#>:']
                ipshell = IPShellEmbed(argv,banner='*** Starting Interactive Shell - Ctrl-D to exit...\n\nnapi is your NexposeAPI variable to play with\n')
                ipshell.set_exit_msg('Buh-bye!')
                ipshell()
            except ImportError, e:
                sys.exit("IPython not installed, won't continue...")

    if options.listvulns:
        vuln_class = VulnData(napi.sessionid)
        vuln_class.populate_summary()
        if (vuln_class.vulnerabilities) > 0:
            if options.listvulns.upper() == "CSV":
                print vuln_class.csvout()
            else:
                print vuln_class.vulnxml
        else:
            print "Error: No Vulnerabilities loaded, check your Nexpose server address or user/pass"

        sys.exit(0)

    if options.basictests:
        # do some basic testing here...
        sites = Sites(napi.sessionid)
        sites = sites.sitelisting()
        for site in sites:
            print "Site #%s: %s" % (site, sites[site]['name'])

        siteconfig = sites.siteconfig(napi, '2')

        print "\n\nSite configuration for SiteID 2\n"
        for count in siteconfig['ranges']:
            for a in siteconfig['ranges'][count]:
                print "%s => %s" % (a, siteconfig['ranges'][count][a])

        print "\nScanconfig for SiteID 2\n"
        for a in siteconfig['scanconfig']:
            print "%s => %s" % (a, siteconfig['scanconfig'][a])

        #napi.sitesave("2")

        assetgroup = AssetGroup(napi.sessionid)
        assetgroup.listing()

        scan_class = Scan(napi.sessionid)
        scan_class.scanactivity()
        scan_class.scanaction("Status", "1")
        scan_class.scanaction("Pause", "1")
        scan_class.scanaction("Resume", "1")
        scan_class.scanaction("Stop", "1")

    napi.logout()
