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
## De-dupify some tables
##
## Run from a shell using web2py:
##
##   ./web2py.py -R applications/$appname/private/dedupe.py -S $appname -M -A -t <table> --dry-run
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#
"""

import sys
import argparse

##--------------------------------------------------------------------

parser = argparse.ArgumentParser(description='Kvasir De-Dupe Table Entries')

parser.add_argument('-f', '--fields', action='append', help="Fields to validate")
parser.add_argument('-d', '--dry-run', action='store_true', default=False, help="Dry run")
parser.add_argument('table', help="Table name to de-dupe")

args = parser.parse_args()

sys.stdout.write("\nKvasir De-Dupe Table Entries\n============================\n\n")

if not args.table:
    parser.print_help()
    sys.exit("[!] Requires a table name\n")
else:
    table = db[args.table]

if args.table not in db.tables:
    sys.stderr.write("[!] %s is not a valid table name.\n\nValid table names are:\n\n" % args.table)
    for tn in db.tables:
        sys.stderr.write("\t%s\n" % tn)
    sys.exit("\n")
else:
    sys.stdout.write(" [*] Database %s valid\n" % args.table)

invalid = False
for field in args.fields:
    sys.stdout.write(' [*] Validating field: %s -- ' % field)
    if field not in table.fields:
        invalid = True
        sys.stdout.write("NOT a valid fieldname\n")
    else:
        sys.stdout.write("OK\n")

if invalid:
    sys.stdout.write(" [-] Valid fields:\n\n")
    for field in table.fields:
        sys.stdout.write("\t%s\n" % field)
    sys.exit("\n")


sql_cmd = """
DELETE FROM %s
WHERE id IN (SELECT id
    FROM (SELECT id,
        row_number() over (partition BY %s ORDER BY id) AS rnum
            FROM %s) t
    WHERE t.rnum > 1);
""" % (args.table, ", ".join(args.fields), args.table)

pre_count = db(table).count()

sys.stdout.write(" [-] %s records currently in the database\n" % pre_count)

if args.dry_run:
    sys.stdout.write(" [*] Dry run selected, would have executed:\n")
    for ln in sql_cmd.split("\n"):
        sys.stdout.write("\t%s\n" % ln)
else:
    sys.stdout.write(" [*] Executing de-dupe query, go grab a tasty beverage!\n")
    res = db.executesql(sql_cmd)
    db.commit()
    post_count = db(table).count()
    sys.stdout.write(" [-] %s records after de-duplication\n" % post_count)
