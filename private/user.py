#!/usr/bin/env python
# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Create/Change password users for Kvasir
##
## Run from a shell using web2py:
##
##   ./web2py.py -R applications/$appname/private/user.py -S $appname -M -A -u username -p password
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

import sys
import getpass
from optparse import OptionParser, OptionGroup

##--------------------------------------------------------------------

optparser = OptionParser(version=__version__)

optparser.add_option("-u", "--user", dest="user",
    action="store", default=None, help="Username")
optparser.add_option("-p", "--password", dest="password",
    action="store", default=None, help="Password")
optparser.add_option("-P", "--prompt", dest="prompt",
    action="store_true", default=False, help="Prompt for password")
optparser.add_option("-n", "--nochange", dest="nochange",
    action="store_true", default=False, help="Do not change the user information")
optparser.add_option("-f", "--force", dest="forcechange",
    action="store_true", default=False, help="Force the change of user information without prompt")

(options, params) = optparser.parse_args()

print "\n\nKvasir User Add/Modify Management\n"
if not options.user:
    user = raw_input("Username: ")
else:
    user = options.user

if not user:
    sys.exit("No username provided\n")

# see if the user exists first
user_row = db(db.auth_user.username == user).select().first()
if user_row:
    # user exists, update password
    if nochange:
        sys.exit("Not changing user...\n")
    ask_update = raw_input("User exists, update password? [y/N]: ")
    if ask_update not in ['Y', 'y'] :
        sys.exit("Ok, leaving user as-is...\n")

if not options.password or options.prompt:
    password = getpass.getpass("Password: ")
else:
    password = options.password

if not password or password == '':
    sys.exit("Password cannot be blank\n")

if user_row:
    # user exists, update password
    print "Updating password for %s..." % (user)
    user_row.update(password=password)
    db.commit()

else:
    # new user
    print "Adding %s to Kvasir user database..." % (user)
    db.auth_user.validate_and_insert(
        username=user,
        password=password
    )
    db.commit()
