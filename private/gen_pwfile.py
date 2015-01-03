#!/usr/bin/env python
# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Generates a password file format for input into
## tools like john the ripper
##
## Run from a shell using web2py:
##
##   ./web2py.py -R applications/kvasir_public/private/gen_pwfile.py -S $appname -M -A -o pwdump -H ntlm
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

import sys, os, csv
from optparse import OptionParser, OptionGroup
from skaldship.hosts import get_host_record

########################################################################
class HostQuery:
    """Represents the host_query for services"""

    #----------------------------------------------------------------------
    def __init__(self):
        self.host_query = None

    #----------------------------------------------------------------------
    def show(self):
        return self.host_query

    #----------------------------------------------------------------------
    def add_host(self, address=None, ports=None):
        """Looks up the host and adds the result to the query"""
        host_rec = get_host_record(address)
        if host_rec is None:
            sys.stderr.write("%s invalid address!\n" % (address))
        else:
            q = (db.t_services.f_hosts_id == host_rec.id)
            for port in ports:
                q &= (db.t_services.f_proto == port[0])
                q &= (db.t_services.f_number == port[1])
            if self.host_query is None:
                self.host_query = q
            else:
                self.host_query |= q

        return

##--------------------------------------------------------------------

pwtypes = [
    ("pwdump", "Windows PWDUMP"),
    ("unix", "UNIX Passwd/shadow"),
    ("userpass", "Usernamne:Password"),
    ("csv", "ipv4,hostname,username,cleartext,hash_1,hash1_type,hash2,hash2_type"),
]

optparser = OptionParser(version=__version__)

optparser.add_option("-o", "--otype", dest="output_type",
    action="store", default=None, help="Output file type")
optparser.add_option("-L", "--list-types", dest="list_types",
    action="store_true", help="List all password file types")

select_group = OptionGroup(optparser, "Selection Criteria")
select_group.add_option("-p", "--port", dest="port",
    action="append", default=[], help="Port (tcp/445) or leave blank for all")
select_group.add_option("-H", "--hash", dest="hash_type",
    action="store", default=None, help="Hash type (LM, NT, MD5, crypt, etc)")
select_group.add_option("-e", "--empty", dest="empty",
    action="store_true", default=False, help="Include records without hashes")
optparser.add_option_group(select_group)

input_group = OptionGroup(optparser, "Source Input Options")
input_group.add_option("-4", "--ip", dest="ipaddr",
    action="append", default=[], help="IP Address or leave blank for all")
input_group.add_option("-l", "--list", dest="filelist",
    action="store", default=None, help="File of IP addresses, one per line")

optparser.add_option_group(input_group)
(options, params) = optparser.parse_args()

if options.list_types:
    sys.stdout.write("\nPassword file types for output\n")
    sys.stdout.write("------------------------------\n\n")
    for a in pwtypes:
        sys.stdout.write("\t%10s .................. %s\n" % (a[0], a[1]))
    sys.stdout.write("\n")
    sys.exit(0)

if options.output_type is None:
    sys.exit("\nMust provide a password file type\n")

ports = []
for port in options.port:
    try:
        (proto, number) = port.split("/")
        ports.append((proto.lower(), number))
    except:
        sys.stderr.write("Invalid port specified: %s" % options.port)

# the large, all accounts query
query = (db.t_accounts.id > 0)

# build a host_query if ipv4 and/or ipv6 addresses are supplied
host_query = HostQuery()
for ip in options.ipaddr:
    host_query.add_host(ip, ports)
if options.filelist:
    for ip in open(options.filelist, "r").readlines():
        host_query.add_host(ip, ports)

if host_query.show() is not None:
    query = (db.t_accounts.active == True) & host_query.show()

# build the port query but only if we haven't specified any ipv4
# or ipv6 addresses.
port_q = (db.t_services.id > 0)
if options.port and host_query.show() is None:
    for p,n in ports:
        port_q &= (db.t_services.f_proto == p)
        port_q &= (db.t_services.f_number == n)
    query &= port_q

"""
if host_query.show() is not None:
    q = (db.t_services)
    q &= host_query.show()
    q &= port_q
    print q.__str__()
    host_rows = db(q).select()
    print host_rows.as_list()
"""

#print "Query =", query.__str__()
output_type = options.output_type.lower()
query &= (db.t_accounts.f_services_id == db.t_services.id)
if options.hash_type:
    query &= (db.t_accounts.f_hash1_type.like(options.hash_type)) | (db.t_accounts.f_hash2_type.like(options.hash_type))
query &= (db.t_services.f_hosts_id == db.t_hosts.id)
#print db(query).select().as_list()

if output_type == "csv":
    output = csv.writer(sys.stdout, quoting=csv.QUOTE_MINIMAL)
    output.writerow(["IP Address", "Hostname", "Account", "Full Name", "Password", "Hash 1 type", "Hash 1", "Hash Type", "Hash 2"])
else:
    output = ""

for row in db(query).select():
    acct = row.t_accounts
    host = row.t_hosts
    # Windows PWDUMP format:
    if not options.empty and (not acct.f_hash1 and not acct.f_hash2):
        continue
    if output_type == "pwdump":
        output += ":".join((acct.f_username, acct.f_uid or "1000", acct.f_hash1 or "", acct.f_hash2 or "", "", "", "", ""))
        output += "\n"
        #print acct
    # UNIX Shadow format:
    elif output_type == "unix":
        output += ":".join((acct.f_username, acct.f_hash1 or "", acct.f_uid or "0", acct.f_gid or "0", acct.f_fullname or "", "/", "/"))
        output += "\n"
    elif output_type == "userpass":
        output += ":".join((acct.f_username, acct.f_password or ""))
        output += "\n"
    elif output_type == "csv":
        output.writerow([host.f_ipaddr, host.f_hostname,
                         acct.f_username, acct.f_fullname, acct.f_password,
                         acct.f_hash1_type, acct.f_hash1, acct.f_hash2_type, acct.f_hash2])

if type(output) == str:
    print output


