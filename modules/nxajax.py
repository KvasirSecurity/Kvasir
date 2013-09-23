#!/usr/bin/python
# Oh.. theres an easier way to grab the nexposeCCSessionID: from the HTML response! argh!

import urllib2, urllib, cookielib
import os, sys, logging
from lxml import etree
from StringIO import StringIO

class NexposeAJAXError(RuntimeError):
    pass

class SmartRedirHandler(urllib2.HTTPRedirectHandler):
    """
    Inserts the nexposeCCSessionID cookie back into headers from an HTTP '303 See Other' response.
    Might be a bug in urllib2.HTTPRedirectHandler
    """
    def http_error_303(self, req, fp, code, msg, hdrs):
        nsession = hdrs.headers
        result = urllib2.HTTPRedirectHandler.http_error_303(self, req, fp, code, msg, hdrs)
        result.headers = nsession
        return result

class NXAJAX():
    """
    Nexpose's JavaScript-free magical 'AJAX' class for Python
    at least until the Nexpose API is extended

    Use getsession to store the logged in session. Pass an externally stored getsession to NXAJAX(getsession) to resume it.
    """
    def __init__(self, session=None):
        self.log = logging.getLogger(self.__class__.__name__)
        if session == None:
            self.cj = cookielib.LWPCookieJar()
        else:
            self.cj = cookielib.LWPCookieJar()
            for index, value in session.iteritems():
                self.cj.set_cookie(value)
        self.opener = urllib2.build_opener(SmartRedirHandler, urllib2.HTTPCookieProcessor(self.cj), urllib2.HTTPSHandler(debuglevel=1))
        # because we do some cookie-jacking, a numeric host cookie domain will not match the jacked cookie's domain apparently.
        self.host = "localhost"
        self.port = "3780"
        self.user_id = "nxadmin"
        self.password = "password"
        self.session = session

    def login(self):
        """
        Logs into Nexpose's web interface with supplied credentials.

        Returns a urllib2 response object. Session cookies will be available in najax.cj._cookies
        """
        attributes = {
                'loginRedir':'/home.html',
                'nexposeccusername':self.user_id,
                'nexposeccpassword':self.password,
                'login':'Login'
        }
        login_data = urllib.urlencode(attributes)
        request = urllib2.Request("https://%s:%s/login.html" %(self.host, self.port), login_data)
        return self.opener.open(request)

    def logout(self):
        request = urllib2.Request("https://%s:%s/logout.html" %(self.host, self.port))
        return self.opener.open(request)

    def send_ajax(self, path="", xmldata=""):
        """
        Performs either a GET or POST action and returns a urllib2 response object.

        Nexpose requires an additional header for authentication: nexposeCCSessionID
        This session id is pulled from a cookie value that is set during login
        """
        if len(xmldata) == 0:
            self.log.debug("Empty POST data. Performing GET for " + path)
            request = urllib2.Request("https://%s:%s/%s" %(self.host, self.port, path))
            return self.opener.open(request)
        else:
            self.log.debug("Sending POST to " + path)
            request = urllib2.Request("https://%s:%s/%s" %(self.host, self.port, path), xmldata, headers={"Content-Type": "text/xml","nexposeCCSessionID":self.cj._cookies['localhost.local']['/']['nexposeCCSessionID'].value})
            return self.opener.open(request)

    def getsession(self):
        """
        Need to have a way to access the session login info so it can be passed in later
        """
        getsession = {}
        for index, value in enumerate(self.cj):
            getsession[index] = value
        return getsession

class ScanTemplates():

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)

    def listscantemps(self, xml=False, najax=None):
        """
        Will list all Scan Templates. By default the output is a /r delimited list.
        Invoke with xml=True to have output in pretty XML
        """
        # TODO: consolidate XML output handling into its own function
        # TODO: XML philosophy: attributes or elements?
        if not najax:
            self.log.warn("No instance provided")
            return False
        else:
            response = najax.send_ajax("ajax/scantemplate_synopsis.txml?printDocType=0&tableID=ScanTemplateSynopsis")
            parser = etree.HTMLParser()
            tree = etree.parse(StringIO(response.read()), parser)
            result_xml = etree.Element("ScanTemplates")
            if xml:
                for child in tree.iterfind("//tr"):
                    #sub = etree.SubElement(result_xml, "ScanTemplate", id = child[0].text)
                    sub = etree.SubElement(result_xml, "templateid")
                    sub.text = child[0].text
                return etree.tostring(result_xml, pretty_print=True)
            else:
                for child in tree.iterfind("//tr"):
                    print child[0].text

    def exporttemplate(self, template, najax=None):
        """
        Exports the specified ScanTemplate XML string.
        'template' is the 'ScanTemplate id=' attribute from Nexpose-generated XML.
        """
        if not najax:
            self.log.warn("No instance provided")
            return False
        else:
            response = najax.send_ajax("ajax/scantemplate_config.txml?templateid=" + template)
            tree = etree.parse(StringIO(response.read()))
            return etree.tostring(tree.getroot())

    def importtemplate(self, template, najax=None):
        """
        Imports the specified template, where 'template' is a valid XML document.
        *No error handling other than a traceback if its invalid.
        *No checks are made to ensure the ScanTemplate is a valid Nexpose format.
        """
        # TODO error handling of an invalid Nexpose scan template
        if not najax:
            self.log.warn("No instance provided")
            return False
        else:
            #parsed = etree.parse(StringIO(template), etree.XMLParser())
            #Nexpose rejects urlencoded POSTDATA
            post_data = template
            response = najax.send_ajax("ajax/save_scantemplate_config.txml", post_data)
            tree = etree.parse(StringIO(response.read()))
            return etree.tostring(tree.getroot())

    def deletetemplate(self, template, najax=None):
        """
        Deletes the specified ScanTemplate
        """
        # TODO error handling
        if not najax:
            self.log.warn("No instance provided")
            return False
        else:
            post_data = urllib.urlencode({'templateid':template})
            response = najax.send_ajax("admin/scan-template-delete.html", post_data)
            return response.read()


if __name__=='__main__':
    from optparse import OptionParser

    # set up commandline arguments
    Progname=os.path.basename(sys.argv[0])
    Usage="%prog usage: XXX:[command_line_args]\n" \
         "%prog usage: -h\n" \
         "%prog usage: -V"
    optparser = OptionParser(usage=Usage, version="%prog: $Id:$" )
    optparser.add_option("-u", "--userid", dest = "userid", action="store", default="nxadmin", help="Username")
    optparser.add_option("-p", "--passwd", dest = "password", action="store", default="password", help="Password")
    optparser.add_option("-v", "--verbose", dest = "verbose", action="store_true", help="be verbose")
    optparser.add_option("-s", "--server", dest = "server", action="store", default="localhost", help="Nexpose Server")
    optparser.add_option("-r", "--port", dest = "port", action="store", default="3780", help="Nexpose Port")
    optparser.add_option("-d", "--debug", dest = "debug", action="store_true", help="log debugging messages")
    optparser.add_option("-l", "--list", dest = "listscantemps", action="store_true", help="List scan templates")
    optparser.add_option("-e", "--export", dest = "Export", action="store", help="Export scan template id list to stdout")
    optparser.add_option("-i", "--import", dest = "Import", action="store", help="Import scan template id list from xml file")
    optparser.add_option("-k", "--delete", dest = "Delete", action="store", help="Delete scan template id")
    optparser.add_option("-x", "--xmlout", dest = "xmlout", action="store_true", help="Output in XML")

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

    najax = NXAJAX()
    najax.user_id = options.userid
    najax.password = options.password
    najax.host = options.server
    najax.port = options.port
    najax.login()

    if options.listscantemps:
        scantemps = ScanTemplates()
        if options.xmlout:
            print scantemps.listscantemps(options.xmlout, najax)
        else:
            scantemps.listscantemps(options.xmlout, najax)
        sys.exit(0)

    if options.Export:
        scantemps = ScanTemplates()
        print scantemps.exporttemplate(options.Export, najax)
        sys.exit(0)

    if options.Import:
        scantemps = ScanTemplates()
        template = open(options.Import, 'r')
        template = template.read()
        print scantemps.importtemplate(template, najax)
        sys.exit(0)

    if options.Delete:
        scantemps = ScanTemplates()
        print scantemps.deletetemplate(options.Delete, najax)
        sys.exit(0)
