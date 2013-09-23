#!/usr/bin/env python
# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Sends the password file(s) via Kvasir API
##
##--------------------------------------#
"""

from optparse import OptionParser, OptionGroup, OptionValueError
import sys, os, glob, re
sys.path.append('/opt/SPA/tools/lib/python')
from AutoSPAngAPI import Accounts, Services

# this is a mess... should use ipaddr library instead
IPV4_REGEX = re.compile("^(?P<ipv4>((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))")
IPV6_REGEX = re.compile("^(?P<ipv6>\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?)")

# grab the ASPANG_URI if defined
ASPANG_URI = os.environ.get('ASPANG_URI', "http://localhost:8000/kvasir/api/call/jsonrpc")
PW_TYPES = ('PWDUMP', 'MSCa$h Dump', 'UNIX Passwd', 'UNIX Shadow', 'Medusa', 'Hydra', 'Username:Password', 'Usernames')

##--------------------------------------------------------------------

def process_pwfiles(options):
    """Processes each options.pw_file_infos record"""
    for pw_file_info in options.pw_file_infos:

        print("----------------------------------------------------------------")
        print(" [*] Processing password file: %s" % (pw_file_info['full_path']))
        try:
            pw_data = open(pw_file_info['full_path'], "r").readlines()
        except Exception, e:
            print " [!] Unable to load file: %s" % (e)
            return False

        acct_api = Accounts(options.aspanguri)
        svc_rec = get_svc_rec(options, pw_file_info['ipaddr'])
        if type(svc_rec) == type(int()):
            res = acct_api.upload_file(
                filename=pw_file_info['filename'],
                pw_data=pw_data,
                service_rec=svc_rec,
                add_to_evidence=options.add_to_evidence,
                f_type=options.f_type,
            )
            for line in res[1].split("\n"):
                if len(line) > 0:
                    print(" [-] %s" % (line))
        else:
            print(" [!] No service record found and none added for %s %s/%s" % (
                pw_file_info['ipaddr'], options.proto, options.port
            ))

##--------------------------------------------------------------------

def get_address(options, filename):
    if options.ipaddr is None:
        address = get_ipv4(filename)
        if address is None:
            address = get_ipv6(filename)
            if address is None:
                print " [!] No IPv4/IPv6 address provided or found in the filename: %s" % (filename)
            else:
                address = ipv6_addr
    else:
        address = options.ipaddr

    return address

##--------------------------------------------------------------------

def get_svc_rec(options, address):
    """Calls the Services.info() API to find the service record id"""
    svc_api = Services(options.aspanguri)
    svc = svc_api.info_or_add(ipaddr=address, proto=options.proto, port=options.port)
    if svc:
        return svc[0][0]
    else:
        # No service record found, lets try to add it if desired
        if options.add_to_services:
            retval = svc_api.add(ipaddr=address, proto=options.proto, port=options.port)
            if not retval[0]:
                print(retval[1])
                return None
            else:
                return retval[1]

##--------------------------------------------------------------------

def get_ipv4(filename):
    ipv4_addr = IPV4_REGEX.match(filename)
    if ipv4_addr:
        return ipv4_addr.group('ipv4')
    else:
        return

##--------------------------------------------------------------------

def get_ipv6(filename):
    ipv6_addr = IPV6_REGEX.match(filename)
    if ipv6_addr:
        return ipv6_addr.group('ipv6')
    else:
        return

##--------------------------------------------------------------------

def Run(options):

    options.pw_file_infos = []
    if options.directory is not None and options.filename is None:

        print " [*] Processing directory: %s" % (options.directory)
        for file_path, dirs, filenames in os.walk(options.directory):
            for filename in filenames:
                address = get_address(options, filename)
                if address:
                    full_path_filename = os.path.join(file_path, filename)
                    options.pw_file_infos.append({
                        'ipaddr': address,
                        'full_path': full_path_filename,
                        'filename': filename
                    })

    elif options.filename is not None:
        (file_path, options.filename) = os.path.split(options.filename)
        if not file_path:
            file_path = os.getcwd()
        full_path_filename = os.path.join(file_path, options.filename)

        address = get_address(options, options.filename)
        options.pw_file_infos.append({
            'ipaddr': address,
            'full_path': full_path_filename,
            'filename': options.filename
        })

    process_pwfiles(options)

    return

##--------------------------------------------------------------------

def check_pwtypes(options, opt_str, value, parser):
    if value in PW_TYPES:
        parser.values.f_type = value
    else:
        raise OptionValueError(" [!] Invalid password file type: %s\nValid entries are:\n\n%s" % (value, ', '.join(PW_TYPES)))

##--------------------------------------------------------------------
if __name__=='__main__':
    # set up commandline arguments
    optparser = OptionParser(version=__version__)

    optparser.add_option("-p", "--port", dest="port",
        action="store", default=None, help="Protocol/Port (info/0, tcp/445) for all files")
    optparser.add_option("-e", "--add_evidence", dest="add_to_evidence",
        action="store_true", help="Add to evidence table")
    optparser.add_option("-a", "--add_service", dest="add_to_services",
        action="store_true", help="Add to services DB if not found")
    optparser.add_option('-u', '--uri', dest='aspanguri',
        action="store", default=ASPANG_URI, help="Kvasir API URI (eg: %s)" % (ASPANG_URI))

    file_group = OptionGroup(optparser, "File-based Options")
    file_group.add_option("-i", "--ip", dest="ipaddr",
        action="store", default=None, help="IPv4/IPv6 Address (if non-std filename)")
    file_group.add_option("-f", "--file", dest="filename",
        action="store", default=None, help="Filename to insert/update")
    file_group.add_option('-t', '--type', dest='f_type', type='string',
        action='callback', callback=check_pwtypes, help='Password file type: %s' % (', '.join(PW_TYPES)))
    optparser.add_option_group(file_group)

    directory_group = OptionGroup(optparser, "Directory-based Options")
    directory_group.add_option("-d", "--dir", dest="directory",
        action="store", default=None, help="Directory location, all files should be named <ipdadr>-value")
    optparser.add_option_group(directory_group)

    (options, params) = optparser.parse_args()

    print " ----------------------------------------------------------"
    print " -- Password file upload, Kvasir master pwner edition --"
    print " ----------------------------------------------------------\n"

    if options.f_type is None:
        raise OptionValueError("\n [!] Must provide a password file type\nValid entries are:\n\n%s" % (', '.join(PW_TYPES)))

    if options.filename is None and options.directory is None:
        raise OptionValueError("\n [!] Must provide a filename or directory of files to upload.\n")

    try:
        (options.proto, options.port) = options.port.split('/')
    except Exception:
        raise OptionValueError("\n [!] Invalid port provided. Must be something like info/0 or tcp/22\n")

    Run(options)
