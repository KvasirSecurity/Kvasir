# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## CPE Utilities for Kvasir
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

from gluon import current
import gluon.contrib.simplejson
import sys, os, time, re, HTMLParser, string
from StringIO import StringIO
import logging
logger = logging.getLogger("web2py.app.kvasir")

##------------------------------------------------------------------------

def split_cpe(cpe=None):
    """
    Splits a CPE record entry into a dictionary using an ugly try/except
    block.

    >>> split_cpe('cpe:/o:freebsd:freebsd:5.2')
    {'product': 'freebsd', 'vendor': 'freebsd', 'version': '5.2', 'language': None, 'update': None, 'edition': None, 'part': 'o'}
    >>> split_cpe('cpe:/a:openbsd:openssh:3.6')
    {'product': 'openssh', 'vendor': 'openbsd', 'version': '3.6', 'language': None, 'update': None, 'edition': None, 'part': 'a'}
    """
    # title, part, vendor,     product,             version, update, edition,    language
    # cpe:/  o:    microsoft:  windows_server_2008: -:       gold:   datacenter: english
    part = None
    vendor = ""
    product = ""
    version = ""
    update = None
    edition = None
    language = None

    if cpe.startswith('cpe:/'):
        cpe = cpe.split('/')[1]

    try:
        part, vendor, product, version, update, edition, language = cpe.split(':')
    except ValueError:
        try:
            part, vendor, product, version, update, edition = cpe.split(':')
        except ValueError:
            try:
                part, vendor, product, version, update = cpe.split(':')
            except ValueError:
                try:
                    part, vendor, product, version = cpe.split(':')
                except ValueError:
                    try:
                        part, vendor, product, version = cpe.split(':')
                    except ValueError:
                        # if it gets this far then the file is bad
                        try:
                            part, vendor, product = cpe.split(':')
                        except ValueError, e:
                            logger.error("Uh, I have no idea what CPE data this is. Error: %s\n%s" % (e, cpe))

    return {
        'part': part,
        'vendor': vendor,
        'product': product,
        'version': version,
        'update': update,
        'edition': edition,
        'language': language
    }

##------------------------------------------------------------------------

def normalize_cpe(cpe_string):
    """
    Normalize CPE data given known formats or capitalize.

    >>> normalize_cpe('freebsd freebsd 5.2')
    'FreeBSD FreeBSD 5.2'
    >>> normalize_cpe('Microsoft Windows xp')
    'Microsoft Windows XP'
    >>> normalize_cpe('microsoft windows 2008 datacenter')
    'Microsoft Windows 2008 Datacenter'
    >>> normalize_cpe('apple iphone')
    'Apple iPhone'
    """

    exchange_table = {
        'hp': 'HP',
        'freebsd': 'FreeBSD',
        'openbsd': 'OpenBSD',
        'netbsd': 'NetBSD',
        'openssh': 'OpenSSH',
        'hpux': 'HP/UX',
        'cisco ios': 'Cisco IOS',
        'apple ios': 'Apple iOS',
        'ios': 'IOS',
        'iphone': 'iPhone',
        'windows_xp': 'Windows XP',
        'windows_nt': 'Windows NT',
        'windows_2000_server': 'Windows 2000 Server',
        'windows_2003_server': 'Windows 2003 Server',
        'windows_2008_server': 'Windows 2008 Server',
        'xp': 'XP',
        'nt': 'NT',
    }

    new_cpe = []
    for cpe in cpe_string.split(' '):
        new_cpe.append(exchange_table.get(cpe, cpe.title()))

    return " ".join(new_cpe)

##------------------------------------------------------------------------

def make_cpe_title(cpe=None):
    """
    Create a CPE title based on cpe string value using string.capwords()

    Ex: cpe:/o:microsoft:windows:xp == Microsoft Windows Xp

    Only care about vendor, product and version

    >>> make_cpe_title('cpe:/o:microsoft:windows:xp')
    'Microsoft Windows XP'
    >>> make_cpe_title('cpe:/o:freebsd:freebsd:5.2')
    'FreeBSD FreeBSD 5.2'
    >>> make_cpe_title('cpe:/o:cisco:ios:12.4')
    'Cisco IOS 12.4'
    """
    if cpe is None:
        return ""

    if not isinstance(cpe, dict):
        cpe_dict = split_cpe(cpe)

    parts = ['vendor', 'product', 'version']

    return normalize_cpe(" ".join([cpe_dict[part] for part in parts]))

##------------------------------------------------------------------------

def lookup_cpe(cpe_name=None):
    """
    Look up a CPE OS record:
      1. Look up the cpe name in t_os database
      2. If not found lookup values in t_cpe_os database
      3. If not found add to t_os database by splitting up the cpe name
    Returns os_id record
    """
    if not cpe_name:
        return None

    # cpe:/o: is stripped in the database
    cpe_name = cpe_name.replace('cpe:/o:', '')

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    os_id = None

    # lookup the CPE entry in t_os first
    cpe_res = db(db.t_os.f_cpename == cpe_name).select().first()
    if cpe_res is not None:
        # found CPE entry in local t_os database, assign cpe_res.id to os_id
        logger.info(" [-] Found CPE OS ID from t_os table: %s" % (cpe_res.f_title))
        os_id = cpe_res.id
    else:
        # CPE not found in t_os, search master CPE db and copy if found
        cpe_res = db(db.t_cpe_os.f_cpename == cpe_name).select().first()
        if cpe_res:
            # we have found a valid master CPE entry, copy it to t_os
            logger.info(" [-] Found CPE OS ID from t_cpe_os master table: %s" % (cpe_res.f_title))
            # first search to see if the f_title is already in the t_os table.
            title_recs = db(db.t_os.f_title == cpe_res.f_title).select().first()
            if not title_recs:
                logger.info(" [-] Adding CPE OS to t_os")
                os_id = db.t_os.insert(f_cpename = cpe_res.f_cpename,
                                       f_title = cpe_res.f_title,
                                       f_vendor = cpe_res.f_vendor,
                                       f_product = cpe_res.f_product,
                                       f_version = cpe_res.f_version,
                                       f_update = cpe_res.f_update,
                                       f_edition = cpe_res.f_edition,
                                       f_language = cpe_res.f_language,
                                       f_isincpe = True)
                db.commit()
            else:
                logger.info(" [-] Found CPE title already in t_os")
                os_id = title_recs.id
                #db.t_os(title_recs.id).update(f_cpename = cpe_res.f_cpename,
                #                              f_title = cpe_res.f_title,
                #                              f_vendor = cpe_res.f_vendor,
                #                              f_product = cpe_res.f_product,
                #                              f_version = cpe_res.f_version,
                #                              f_update = cpe_res.f_update,
                #                              f_edition = cpe_res.f_edition,
                #                              f_language = cpe_res.f_language,
                #                              f_isincpe = True)

    if not os_id:
        # no CPE or OS record found, insert a new t_os record
        cpe_dict = split_cpe("o:" + cpe_name)
        title = make_cpe_title("o:" + cpe_name)
        logger.info(" [!] No os_id found, inserting new record: %s" % (cpe_name))

        try:
            os_id = db.t_os.insert(
                f_cpename = cpe_name,
                f_title = title,
                f_vendor = cpe_dict['vendor'],
                f_product = cpe_dict['product'],
                f_version = cpe_dict['version'],
                f_update = cpe_dict['update'],
                f_edition = cpe_dict['edition'],
                f_language = cpe_dict['language']
            )
        except Exception, e:
            logger.error("Error inserting OS: %s" % (e))
        db.commit()

    return os_id

##------------------------------------------------------------------------

def process_xml(filename=None, download=False, wipe=False):
    """
    Process the CPE data through an uploaded file or have it download directly
    from the MITRE webserver
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

    if download:
        # grab cpe data from http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml
        from gluon.tools import fetch
        import sys
        try:
            logger.info("Downloading http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz... Please wait...")
            gz_cpedata = fetch('http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz')
            logger.info("Download complete. %s bytes received" % (sys.getsizeof(gz_cpedata)))
        except Exception, e:
            raise Exception("Error downloading CPE XML file: %s" % (e))

    logger.info("Processing CPE XML file...")

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    try:
        if download:
            import gzip
            from cStringIO import StringIO
            gz_cpedata = StringIO(gz_cpedata)
            infile = gzip.GzipFile(fileobj=gz_cpedata).read()
            cpe_xml = etree.parse(StringIO(infile))
        else:
            cpe_xml = etree.parse(filename)
    except etree.ParseError, e:
        raise Exception("Error loading CPE XML file: %s " % (e))

    root = cpe_xml.getroot()

    # from the t_errata table, a few key/value pairs:
    #
    #   cpe_last_upload = date/time of last upload
    #   cpe_timestamp   = timestamp from official dictionary
    #   cpe_schema_ver  = CPE schema version
    #   cpe_product_ver = CPE product version

    cpe_info = root.find('generator')
    curr_errata = {}
    curr_errata['timestamp'] = db(db.t_errata.f_key == 'cpe_timestamp').select().first()
    curr_errata['pversion'] = db(db.t_errata.f_key == 'cpe_product_ver').select().first()
    curr_errata['schemaver'] = db(db.t_errata.f_key == 'cpe_schema_ver').select().first()

    if cpe_info:
        pver = cpe_info.get('product_version')
        schemaver = cpe_info.get('schema_version')
        timestamp = cpe_info.get('timestamp')

        if pver:
            curr_errata['pversion'].update_record(
                f_key = 'cpe_product_ver',
                f_value = pver,
            )

        if timestamp:
            curr_errata['timestamp'].update_record(
                f_key = 'cpe_timestamp',
                f_value = timestamp,
            )

        if schemaver:
            curr_erata['schemaver'].update_record(
                f_key = 'cpe_schema_ver',
                f_value = cpe_schemaver,
            )
        db.commit()

    os_added = 0
    apps_added = 0
    hardware_added = 0
    if wipe:
        db.t_cpe_os.truncate(mode="CASCADE")
        db.t_cpe_hardware.truncate(mode="CASCADE")
        db.t_cpe_apps.truncate(mode="CASCADE")
        db.commit()

    for cpeitem in root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
        name = cpeitem.get('name')
        title = cpeitem.findtext('{http://cpe.mitre.org/dictionary/2.0}title')
        cpe_dict = split_cpe(name)
        name = name[7:]

        try:
            if cpe_dict['part'] == "o":
                resid = db.t_cpe_os.update_or_insert(
                    f_cpename = name,
                    f_title = title,
                    f_vendor = cpe_dict['vendor'],
                    f_product = cpe_dict['product'],
                    f_version = cpe_dict['version'],
                    f_update = cpe_dict['update'],
                    f_edition = cpe_dict['edition'],
                    f_language = cpe_dict['language']
                )
                os_added += 1
            """
            elif cpe_dict['part'] == "a":
                resid = db.t_cpe_apps.update_or_insert(
                    f_cpename = name,
                    f_title = title,
                    f_vendor = cpe_dict['vendor'],
                    f_product = cpe_dict['product'],
                    f_version = cpe_dict['version'],
                    f_update = cpe_dict['update'],
                    f_edition = cpe_dict['edition'],
                    f_language = cpe_dict['language']
                )
                apps_added += 1
            elif cpe_dict['part'] == "h":
                resid = db.t_cpe_hardware.update_or_insert(
                    f_cpename = name,
                    f_title = title,
                    f_vendor = cpe_dict['vendor'],
                    f_product = cpe_dict['product'],
                    f_version = cpe_dict['version'],
                    f_update = cpe_dict['update'],
                    f_edition = cpe_dict['edition'],
                    f_language = cpe_dict['language']
                )
                hardware_added += 1
            """
        except Exception, e:
            logger.warn("Exception adding CPE data: %s" % (e))
            pass

        db.commit()

    msg = 'CPE items added/updated (%d/O, %d/A, %d/H)' % (os_added, apps_added, hardware_added)
    logger.info(msg)
    return msg

##------------------------------------------------------------------------

def _doctest():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _doctest()
