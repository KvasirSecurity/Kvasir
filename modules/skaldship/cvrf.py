# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Common Vulnerability Reference File module for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from gluon import current
import gluon.contrib.simplejson
import sys, os, time, re, HTMLParser
from StringIO import StringIO
import logging
logger = logging.getLogger("web2py.app.kvasir")

##------------------------------------------------------------------------

process_xml(filename=None):
    """
    Processes a single CVRF XML file into t_vulndata structure.
    CVRF info can be found at http://www.icasi.org/cvrf
    """

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


    logger.info("Processing CVRF XML file [%s]" % (filename))

    db = current.globalenv['db']
    cache = current.globalenv['cache']

