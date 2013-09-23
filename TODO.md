Kvasir TODO
=========

The following list of items are things that need some attention in Kvasir.
These should generally map to Github issues but some may not.

Urgents
--------------

* hosts/edit 'id' field is not hidden in form view!

* clear cache.ram after add/delete/modifies

* Form errors should pop out better (in web2py.js)

* Document server-side filtering for accounts and services in html

* Nessus file parsing and API needs completion

* Host filter should have some help attached to it

* Send a host to be re-scanned and update/replace information

* vulninfo-by-vulnid updates for adding exploit/references

* Better Scheduler task management and integrate MSF Pro task viewing
  Right now we just redirect to the MSF Pro workspace task detail but
  the API code is there and functioning. Just not Kvasir UI.

* Long output results should go into an alert div and not response.flash

Needs
--------------

* shodanhq WebAPI calls

* Filter based on IP subnet range needs to be implemented

* Error in AJAX submissions of forms should handle errors... sorta
  handled by web2py javascript.

* Enumerate additional host information using SNMP / SAMBA / banners
  using valkyries

* Kick off aux/exploits to Metasploit / CANVAS using their API

* Kick off nmap scans and import results through scheduler

* QualysGuard file parsing and API needs attention. Can use existing
  internal python library to parse XML report. API will require some
  coordination for access to dev/test.

Wants
--------------

* netbios/list is still SQLFORM.grid() .. Usable but not uniform

* Datetime picker needs to be bootstrap-y and not the jQuery one
  Maybe http://tarruda.github.io/bootstrap-datetimepicker/ ?

* Integrate CPE Application database with xml imports and services list

* Like the PowerTables plugin, create a function that will turn a Row()
  or list/dict into JSON output for dataTables or perhaps an SQLTABLE()
  into JSON?

* IP Subnet / Address assignment tables and status. Fields:
  "ip address", "engineer assigned", "scanned/not-scanned", "date/time scanned"

* From IP Subnet / Address table submit to vuln scanner

* Investigage using 'list:reference tablename' instead of reference tables
  for many-to-many relationships. May be easier.

* Quake console integration with JSONRPC API

