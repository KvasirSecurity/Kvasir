# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2011 Cisco Systems, Inc.
##
## Looks at the screenshots directory and uploads any that are not
## in the database. Tries to be smart about those that are still
## open by checking the MD5 sum.
##
## Execute by:
##
##    /opt/SPA/web2py/web2py.py -S <appname> -M -R applications/<appname>/private/update_evidence -d applications/<appname>/data/files/screenshots -t S
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

import sys, os, glob
import hashlib, re
from optparse import OptionParser, OptionGroup
from skaldship.hosts import get_host_record
from gluon.validators import IS_IPADDRESS

IPV4_REGEX = re.compile("^(?P<ipv4>((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))")

##--------------------------------------------------------------------

def md5_file(filename):
    if not filename:
        return

    md5 = hashlib.md5()
    try:
        with open(filename,'rb') as f:
            for chunk in iter(lambda: f.read(128*md5.block_size), ''):
                md5.update(chunk)
            return md5.hexdigest()
    except Exception, e:
        print "Error obtaining md5sum of %s: %s" % (filename, e)

    return

##--------------------------------------------------------------------

def md5_content(content):
    if not content:
        return

    md5 = hashlib.md5()
    md5.update(content)
    return md5.hexdigest()

##--------------------------------------------------------------------

def update_db(f_type=None, record=None, data=None, filename=None, ipaddr=None):
    """Adds or updates an existing record id"""

    if record is None:
        # inserting a new record into the database
        if ipaddr is None:
            print "ERROR: No IPv4 address provided"
            return False

        host_id = get_host_record(ipaddr)
        if not host_id:
            print "ERROR: %s is not a host in the database" % (ipaddr)
            return False

        try:
            db.t_evidence.insert(
                f_hosts_id = host_id.id,
                f_filename = filename,
                f_data = data,
                f_type = f_type
            )
        except Exception, e:
            print "ERROR inserting record:", e
            db.commit()
            return False

    else:
        # updating an existing record's data
        try:
            db.t_evidence[record].update(f_data = data)
        except Exception, e:
            print "ERROR updating record:", e
            db.commit()
            return False

    db.commit()
    return True

##--------------------------------------------------------------------

def get_ipaddr(filename):
    ipv4_addr = IPV4_REGEX.match(filename)
    if ipv4_addr:
        return ipv4_addr.group('ipv4')
    else:
        return

##--------------------------------------------------------------------


def Run(directory=None, filename=None, f_type=None, ipaddr=None):

    print "======================================================================="
    print "\nAdding %s files to the Evidence database\n" % (f_type)

    default_locations = {
        'Session Log': 'session-logs/',
        'Screenshot': 'screenshots/',
    }

    if directory is not None and filename is None:
        currpath = os.path.abspath(os.path.curdir)
        directory = os.path.join(currpath, request.folder, default_locations[f_type])

        if f_type == "Session Logs":
            dir_glob = os.path.join(directory, '*.log')
        else:
            dir_glob = os.path.join(directory, '*')

        # build a list of database entires based on filename, md5 and record identifier
        db_entries = {}
        for row in db(db.t_evidence.f_type == f_type).select(db.t_evidence.f_filename, db.t_evidence.id, db.t_evidence.f_data):
            md5_data = md5_content(row.f_data)
            filename = row.f_filename
            db_entries[filename] = { 'md5': md5_data, 'id': row.id }

        for glob_result in glob.glob(dir_glob):
            (file_path, filename) = os.path.split(glob_result)

            ipaddr = get_ipaddr(filename)
            if ipaddr is None:
                print "No IP address provided or found in the filename: %s" % (filename)
                print "For files the IP address must be the first part of the name."
                print "Example: 192.168.1.0-description.png"
                continue

            full_path_filename = os.path.join(file_path, filename)
            md5_filesum = md5_file(full_path_filename)
            try:
                data = ''.join(open(full_path_filename, 'r').readlines())
            except Exception, e:
                print "ERROR opening %s: %s" % (full_path_filename, e)
                continue

            if db_entries.has_key(filename):
                if db_entries[filename]['md5'] != md5_filesum:
                    print "%s: md5 sums do not match, updating database..." % (filename)
                    res = update_db(f_type, db_entries[filename]['id'], data)
                else:
                    continue
            else:
                print "%s is NOT in database, adding it..." % (filename)
                res = update_db(f_type, None, data, filename, ipvaddr)

    elif filename is not None:
        (dir_path, filename) = os.path.split(filename)

        if ipaddr is None:
            ipaddr = get_ipaddr(filename)
            if ipaddr is None:
                print "No IP address provided or found in the filename: %s" % (filename)
                print "For files the IP address must be the first part of the name."
                print "Example: 192.168.1.0-description.png"
                return

        try:
            data = ''.join(open(os.path.join(dir_path, filename), 'r').readlines())
        except Exception, e:
            print "ERROR opening %s: %s" % (filename, e)
            return

        db_row = db(db.t_evidence.f_filename == filename).select(db.t_evidence.f_filename, db.t_evidence.id, db.t_evidence.f_data).first()
        if db_row is None:
            print "%s is NOT in database, adding it..." % (filename)
            res = update_db(f_type, None, data, filename, ipaddr)
        else:
            print "%s is in the database, updating database..." % (filename)
            res = update_db(f_type, db_row.id, data, filename, ipaddr)

    return

##--------------------------------------------------------------------

# set up commandline arguments
optparser = OptionParser(version=__version__)

optparser.add_option("-t", "--type", dest="f_type",
    action="store", default=None, help="Evidence type ([S]creenshot, Session[L]og)")

file_group = OptionGroup(optparser, "File-based Options")
file_group.add_option("-i", "--ip", dest="ipaddr",
    action="store", default=None, help="IP Address (if only a filename)")
file_group.add_option("-f", "--file", dest="filename",
    action="store", default=None, help="Filename to insert/update")
optparser.add_option_group(file_group)

directory_group = OptionGroup(optparser, "Directory-based Options")
directory_group.add_option("-d", "--dir", dest="directory",
    action="store", default=None, help="Directory location")
optparser.add_option_group(directory_group)

(options, params) = optparser.parse_args()

if options.f_type is None:
    sys.exit("\nMust provide an evidence type\n")

f_type = options.f_type.lower()

if f_type in ["SessionLog", "l", "L"]:
    f_type = "Session Log"
elif f_type in ["Screenshot", "s", "S"]:
    f_type = "Screenshot"
else:
    sys.exit("\nMust provide an evidence type")

Run(options.directory, options.filename, f_type, options.ipaddr)
