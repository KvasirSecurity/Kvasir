#!/usr/bin/env python

import re
import fileinput

#LEADER = "    "
LEADER = "\t"

def matchit(match):
	if match is None:
		return None
	return match.group('d')

table_re = re.compile("define_table\('(?P<d>\w+)'")
field_re = re.compile("Field\('(?P<d>\w+)'")
field_dbref = re.compile("db\.(?P<d>\w+),")

print "Kvasir Models"

for line in fileinput.input():
	table = matchit(table_re.search(line))
	if table:
		print LEADER, table

	field = matchit(field_re.search(line))
	#if field == "id":
	#	print "%s%s_%s" % (LEADER, field, table)
	if field:
		print LEADER, LEADER, field

	#field = matchit(field_re.search(line))
	#if field is not None:
	#	print "%sid_%s" % (LEADER, field)

