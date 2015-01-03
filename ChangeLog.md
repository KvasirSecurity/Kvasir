Kvasir Log of Notable Changes
=============================

01/02/15 : 1.1.0
----------------

https://github.com/KvasirSecurity/Kvasir/releases/tag/v1.1.0
https://github.com/KvasirSecurity/Kvasir/issues?q=is%3Aissue+milestone%3A1.1.0+is%3Aclosed

1.1.0 brings us a few steps further in the quest to not have more bugs.
101 commits, 6 contributors and over 90 files modified. Whew!

Sometimes I feel like Markowski in Wreck It Ralph. "Code the app, find bugs.
Fix bugs! Make more bugs!" I'm hoping 1.2.0 will have working tests so this
at least the old things won't break anymore. There are always old bugs to
find so if you come across them, submit an issue!

Notable enhancements and fixes:

* Skaldship module refactoring for Metasploit, Nessus and Passwords
* YAML-based configuration file, no more modifying db.py!
* Vulnerability references can be added or removed from the UI
* f_ipv4/f_ipv6 merged into f_ipaddr for t_hosts table
* Added redirect page for external links, configurable in YAML file
* Use select2 json to load large data like from t_vulndata
* Old bugs fixed, new bugs added, hidden bugs still hidden


04/21/14 : 1.0.1
----------------

https://github.com/KvasirSecurity/Kvasir/releases/tag/v1.0.1
https://github.com/KvasirSecurity/Kvasir/issues?q=is%3Aissue+milestone%3A1.0.1+is%3Aclosed

1.0.1 added quite a few new features and bug fixes with 156 commits, 666 file
changes from 10 contributors! Most notable:

* Nessus CSV and XML (.nessus) file parsing
* Stronger NMAP parsing
* Scan hosts via NMAP using web2py scheduler
* Moved to a YAML configuration file, no more editing db.py!
* Use CVSS or Severity for charts/stats
* Add VNC screenshot Valkyrie
* Exploit-db and PwnWiki support added


09/23/13 : 1.0.0
----------------

* 1.0.0 Released!
