# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Immunity CANVAS Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from gluon import current
import gluon.contrib.simplejson
import sys, os, time, re, HTMLParser
from StringIO import StringIO
from skaldship.general import html_to_markmin, get_host_record, do_host_status
import logging
logger = logging.getLogger("web2py.app.kvasir")

try:
    from lxml import etree as etree
except ImportError:
    try:
        from xml.etree import cElementTree as etree
    except ImportError:
        try:
            import cElementTree as etree
        except ImportError:
            try:
                from xml.etree import ElementTree as etree
            except ImportError:
                try:
                    from elementtree import ElementTree as etree
                except ImportError:
                    raise("Unable to load any XML libraries for ElementTree!"\
                          "Please install an xml library or Python 2.5 at least")

##----------------------------------------------------------------------------

def process_exploits(filename=None):
    """
    Process Canvas Exploits.xml file into the database
    """

    localdb = current.globalenv['db']

    if filename is None:
        expurl = 'http://exploitlist.immunityinc.com/home/serve/live'
        from gluon.tools import fetch
        import sys
        try:
            print("Downloading CANVAS Exploits XML file... Please wait...")
            xmldata = fetch(expurl)
            print("Download complete. %s bytes received" % (sys.getsizeof(xmldata)))
        except Exception, e:
            raise Exception("Error downloading CPE XML file: %s" % (e))

    logging.info("Processing %s ..." % (filename))

    try:
        if filename is None:
            from StringIO import StringIO
            exploits = etree.parse(StringIO(xmldata))
        else:
            exploits = etree.parse(filename)
    except etree.ParseError, e:
        print("Error processing file: ", e)
        logging.error("Error processing file: %s" % (e))
        return e
    except IOError, e:
        print("Error opening file: ", e)
        logging.error("Error opening file: %s" % (e))
        return e

    r = exploits.getroot()

    # CANVAS uses CVE identifiers to link their exploits
    from exploits import add_exploit, connect_exploits
    counter = 0
    exploits_added = []
    for exploit in r.xpath('//Exploit'):
        #<Exploit cve="CVE-2008-4250" desc="Windows Server Service Underflow (MS08-067)" name="ms08_067"/>
        cve = exploit.get('cve')
        # sometimes they forget to put CVE- in front of the CVE ID
        if not cve.startswith('CVE-'):
            cve = "CVE-%s" % (cve)
        f_name = exploit.get('desc')
        f_title = exploit.get('name')  # seems backwards but not
        f_description = f_title
        f_source = 'canvas'
        f_rank = 'average'              # rank is not defined in xml, default to average
        f_level = 'Intermediate'        # level is not defined in xml, default to Intermediate

        res = add_exploit(
            cve=cve,
            f_name=f_name,
            f_title=f_title,
            f_description=f_description,
            f_source=f_source,
            f_rank=f_rank,
            f_level=f_level,
        )
        if res > 0:
            counter += 1
        else:
            logger.error("Error importing exploit: %s" % (f_name))

    connect_exploits()
    logging.info("%d exploits added/updated" % (counter))
    return True

##----------------------------------------------------------------------------
