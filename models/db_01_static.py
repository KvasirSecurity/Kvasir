#coding:utf-8

#--------------------------------------#
# Kvasir Static Table Definitions
#
# Vulnerabilities, Operating Systems
# Row entries are generally static in these tables,
# filled from master database and/or XML import scripts
#
# (c) 2010-2013 Cisco Systems, Inc.
#
# Author: Kurt Grutzmacher <kgrutzma@cisco.com>
#--------------------------------------#

########################################
auth.settings.extra_fields['auth_user']= [
    Field('f_host_detail', 'string', label=T('Host Detail Page'), default='detail'),
    Field('f_launch_cmd', 'string', label=T('Launch Command'),
          default="xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e script _LOGFILE_"),
          #default="gnome-terminal --profile=spa -t 'manual hacking: _IP_' -e script _LOGFILE_"),
    Field('f_show_size', 'string', label=T('Table Show Start'), default='50', requires=IS_IN_SET(('10', '50', '100', '200', '500', 'All'), multiple=False)),
    Field('f_host_detail_tab', 'string', label=T('First Tab on Host Detail'), default='Services', requires=IS_IN_SET(('Services', 'Vulnerabilities', 'Notes', 'Evidence', 'OS', 'Accounts', 'SNMP'), multiple=False)),
    Field('f_tabletools', 'boolean', label=T('Enable TableTools'), default=True),
    Field('f_scheduler_tasks', 'boolean', label=T('Default Background Tasks'), default=True),
    Field('f_msf_pro_key', 'string', label=T('Metasploit Pro API Key')),
    Field('f_msf_pro_url', 'string', default='https://localhost:3790/', label=T('Metasploit Pro URL')),
    Field('f_nexpose_host', 'string', default='localhost', label=T('Nexpose Host')),
    Field('f_nexpose_port', 'string', default='3780', label=T('Nexpose Port')),
    Field('f_nexpose_user', 'string', default='nxadmin', label=T('Nexpose Username')),
    Field('f_nexpose_pw', 'password', default='password', label=T('Nexpose Password')),
    Field('f_nessus_host', 'string', default='localhost:8834', label=T('Nessus Host')),
    Field('f_nessus_user', 'string', default='admin', label=T('Nessus Username')),
    Field('f_nessus_pw', 'password', default='password', label=T('Nessus Password')),
]
auth.define_tables(username=True, fake_migrate=settings.fake_migrate, migrate=settings.migrate)   # creates all needed tables

auth.settings.actions_disabled.append('register')
auth.settings.actions_disabled.append('retrieve_username')
auth.settings.actions_disabled.append('request_reset_password')
auth.settings.registration_requires_verification = False
auth.settings.registration_requires_approval = False

########################################
## Vulnerabilities
db.define_table('t_vulndata',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('vulns','vulndata_edit',args=id)))),
    Field('f_vulnid', type='string', length=255, unique=True, label=T('Vulnerability ID'), requires=IS_NOT_EMPTY(),
          represent=lambda id,row:SPAN(A(id,_href=URL('vulns','vulninfo_by_vulnid', args=id)))),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_severity', type='integer', label=T('Severity'), requires=IS_IN_SET([x for x in range(1, 11)])),
    Field('f_pci_sev', type='integer', label=T('PCI Severity'), requires=IS_IN_SET([x for x in range(1, 6)])),
    Field('f_riskscore', type='string', label=T('Risk score')),
    Field('f_dt_published', type='datetime', label=T('Date Published')),
    Field('f_dt_added', type='datetime', label=T('Date Added')),
    Field('f_dt_modified', type='datetime', label=T('Date Modified')),
    Field('f_cvss_score', type='string', label=T('CVSS Score'), requires=IS_FLOAT_IN_RANGE(0, 11)),
    Field('f_cvss_i_score', type='string', label=T('CVSS Temporal Score')),
    Field('f_cvss_e_score', type='string', label=T('CVSS Enviromental Score')),
    Field('f_cvss_av', type='string', label=T('CVSS Access Vector'), requires=IS_IN_SET([('L', 'Local Access'), ('A', 'Adjacent Network'), ('N', 'Network')], multiple=False)),
    Field('f_cvss_ac', type='string', label=T('CVSS Access Complexity'), requires=IS_IN_SET([('H', 'High'), ('M', 'Medium'), ('L', 'Low')], multiple=False)),
    Field('f_cvss_au', type='string', label=T('CVSS Authentication'), requires=IS_IN_SET([('N', 'None required'), ('S', 'Single instance'), ('M', 'Multiple instances')], multiple=False)),
    Field('f_cvss_c', type='string', label=T('CVSS Confidentiality Impact'), requires=IS_IN_SET([('N', 'None'), ('P', 'Partial'), ('C', 'Complete')], multiple=False)),
    Field('f_cvss_i', type='string', label=T('CVSS Integrity Impact'), requires=IS_IN_SET([('N', 'None'), ('P', 'Partial'), ('C', 'Complete')], multiple=False)),
    Field('f_cvss_a', type='string', label=T('CVSS Availablity Impact'), requires=IS_IN_SET([('N', 'None'), ('P', 'Partial'), ('C', 'Complete')], multiple=False)),
    Field('f_description', type='text', length=65535, represent=lambda x, row: MARKMIN(x), label=T('Description')),
    Field('f_solution', type='text', length=65535, represent=lambda x, row: MARKMIN(x), label=T('Solution')),
    Field('f_source', type='string', length=255, widget=autocomplete_bootstrap, label=T('Source')),
    auth.signature,
    format='%(f_vulnid)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

#db.t_vulndata.f_vulnid.represent=lambda i:SPAN(A(i,_id="vuln_details_%s" % (i),_href=URL('vulns', 'vulninfo_by_vulnid',args=i)))

def ref_id_represent(f_source, f_text):
    """
    Return a string representing f_text with a ulink based upon the source

    NOTE: This is hardly complete, a full map is available from CVE at
    http://cve.mitre.org/data/refs/index.html but for now these will do.
    """

    ulinks = { 'CVE': lambda x: A(x, _target="reference", _href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % (x)),
               'URL': lambda x: A(x, _target="reference", _href=x),
               'BID': lambda x: A(x, _target="reference", _href="http://www.securityfocus.com/bid/%s" %(x)),
               'XF':  lambda x: A(x, _target="reference", _href="http://xforce.iss.net/xforce/xfdb/%s" % (x)),
               'ISS':  lambda x: A(x, _target="reference", _href="http://xforce.iss.net/xforce/xfdb/%s" % (x)),
               'MSKB': lambda x: A(x, _target="reference", _href="http://support.microsoft.com/kb/%s" %(x)),
               'OSVDB': lambda x: A(x, _target="reference", _href="http://osvdb.org/show/osvdb/%s" % (x)),
               'SECUNIA': lambda x: A(x, _target="reference", _href="https://secunia.com/advisories/%s" % (x)),
               'MANDRAKE': lambda x: A(x, _target="reference", _href='http://lwn.net/Alerts/Mandrake/'),
               'MANDRIVA': lambda x: A(x, _target="reference", _href='http://www.mandriva.com/security/advisories'),
               'REDHAT': lambda x: A(x,_target="reference",  _href='http://www.redhat.com/support/errata/index.html'),
               'CERT': lambda x: A(x, _target="reference", _href='http://www.cert.org/advisories'),
               'CERT-VN': lambda x: A(x, _target="reference", _href="https://www.kb.cert.org/vuls/id/%s" % (x)),
               'SECTRACK': lambda x: A(x, _target="reference", _href='http://www.securitytracker.com/'),
               'OVAL': lambda x: A(x, _target="reference", _href='https://oval.mitre.org/repository/data/SearchDefinitionAdv?id=%s&advsearch=Search' % (x.replace('OVAL', ''))),
               'MS': lambda x: A(x, _target="reference", _href='http://www.microsoft.com/technet/security/current.aspx'),
               'GENTOO': lambda x: A(x, _target="reference", _href='http://www.gentoo.org/security/en/glsa/'),
               'SANS-06': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'SANS-07': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'SANS-08': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'SANS-09': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'SANS-10': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'SANS-11': lambda x: A(x, _target="reference", _href='http://isc.sans.org'),
               'AIXAPAR': lambda x: A(x, _target="reference", _href='http://www-01.ibm.com/support/search.wss?rs=0&apar=only'),
               'APPLE': lambda x: A(x, _target="reference", _href='http://lists.apple.com/archives/security-announce'),
               'CISCO': lambda x: A(x, _target="reference", _href='http://www.cisco.com/en/US/products/products_security_advisories_listing.html'),
               'AUSCERT': lambda x: A(x, _target="reference", _href='http://www.auscert.org.au/Information/advisories.html'),
               'BEA': lambda x: A(x, _target="reference", _href='http://dev2dev.bea.com/advisoriesnotifications/index.csp'),
               'CALDERA': lambda x: A(x, _target="reference", _href='http://www.calderasystems.com/support/security/'),
               'CHECKPOINT': lambda x: A(x, _target="reference", _href='http://www.checkpoint.com/defense/advisories/public/summary.html'),
               'CIAC': lambda x: A(x, _target="reference", _href='http://ciac.llnl.gov/cgi-bin/index/bulletins'),
               'COMPAQ': lambda x: A(x, _target="reference", _href='http://ftp.support.compaq.com/patches/.new/security.html'),
               'CONECTIVA': lambda x: A(x, _target="reference", _href='http://lwn.net/Alerts/Conectiva/'),
               'DEBIAN': lambda x: A(x, _target="reference", _href='http://www.debian.org/security/'),
               'EEYE': lambda x: A(x, _target="reference", _href='http://research.eeye.com/html/advisories/index.html'),
               'ENGARDE': lambda x: A(x, _target="reference", _href='http://lwn.net/Alerts/EnGarde/'),
               'EXPLOIT-DB': lambda x: A(x, _target="reference", _href='http://www.exploit-db.com/exploits/%s' % (x)),
               'FEDORA': lambda x: A(x, _target="reference", _href='http://www.redhat.com/archives/fedora-announce-list/'),
               'FREEBSD': lambda x: A(x, _target="reference", _href='http://www.freebsd.org/security/'),
               'FRSIRT': lambda x: A(x, _target="reference", _href='http://www.vupen.com/english/'),
               'FULLDISC': lambda x: A(x, _target="reference", _href='http://lists.grok.org.uk/pipermail/full-disclosure/'),
               'FarmerVenema': lambda x: A(x, _target="reference", _href='http://www.alw.nih.gov/Security/Docs/admin-guide-to-cracking.101.html'),
               'HP': lambda x: A(x, _target="reference", _href='http://www.itrc.hp.com/service/cki/secBullArchive.do'),
               'IDEFENSE': lambda x: A(x, _target="reference", _href='http://labs.idefense.com/intelligence/vulnerabilities/'),
               'NETBSD': lambda x: A(x, _target="reference", _href='http://www.netbsd.org/Security/advisory.html'),
               'OPENBSD': lambda x: A(x, _target="reference", _href='http://www.openbsd.org/security.html'),
               'SUN': lambda x: A(x, _target="reference", _href='http://search.sun.com/main/index.jsp?col=main-support-sunalerts&oneof=security&nh=100&rf=1&type=advanced&optstat=true'),
               'SUNALERT': lambda x: A(x, _target="reference", _href='http://search.sun.com/main/index.jsp?col=main-support-sunalerts&oneof=security&nh=100&rf=1&type=advanced&optstat=true'),
               'SUSE': lambda x: A(x, _target="reference", _href='http://www.novell.com/linux/security/advisories.html'),
               'UBUNTU': lambda x: A(x, _target="reference", _href='http://www.ubuntu.com/usn/'),
             }

    if ulinks.has_key(f_source):
        return(ulinks[f_source](f_text))
    else:
        return f_text

########################################
## Vulnerability references
db.define_table('t_vuln_refs',
    Field('id', 'id', represent=lambda id,row:SPAN(A(id,_href=URL('vuln_refs_edit',args=id)))),
    Field('f_source', type='text', label=T('Source'), requires=IS_NOT_EMPTY()),
    Field('f_text', type='text', label=T('Text'), requires=IS_NOT_EMPTY(), represent=lambda id,row: ref_id_represent(row.f_source, row.f_text)),
    auth.signature,
    format=lambda r:ref_id_represent(r.f_source, r.f_text),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Many-to-Many table for vulns and references
## Creates a new set, s_vulnerabilities
db.define_table('t_vuln_references',
    Field('id', 'id', represent=lambda id,row:SPAN(A(id,_href=URL('vulns', 'vuln_references_edit',args=id)))),
    Field('f_vulndata_id', 'reference t_vulndata', label=T('Vulnerability'), represent=lambda id,row:A(db.t_vulndata[id].f_vulnid, _href=URL('vulndata_edit', args=id))),
    Field('f_vuln_ref_id', 'reference t_vuln_refs', label=T('Reference'), represent=lambda id,row: " :: ".join([db.t_vuln_refs[id].f_source, db.t_vuln_refs[id].f_text])),
    auth.signature,
    format=lambda r:XML(ref_id_represent(db.t_vuln_refs[r.f_vuln_ref_id].f_source, db.t_vuln_refs[r.f_vuln_ref_id].f_source)),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
s_vulnerabilities = db(db.t_vuln_refs.id == db.t_vuln_references.f_vuln_ref_id)

########################################
## Exploits
db.define_table('t_exploits',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('exploits', 'edit', args=id)))),
    Field('f_name', type='string', label=T('Name'), requires=IS_NOT_EMPTY()),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_description', type='text', label=T('Description'), requires=IS_NOT_EMPTY()),
    Field('f_source', type='string', label=T('Source'), default='other',
        requires=IS_IN_SET(('exploitdb', 'metasploit', 'metasploit2', 'canvas', 'core', 'other'), multiple=False)),
    Field('f_rank', type='string', label=T('Exploit quality ranking'), default='Unknown',
        requires=IS_IN_SET(('Unknown', 'Novice', 'Intermediate', 'Expoert'))),
    Field('f_level', type='string', label=T('Exploit knowledge level'), default='unknown',
        requires=IS_IN_SET(('unknown', 'manual', 'low', 'average', 'good', 'normal', 'great', 'excellent'), multiple=False)),
    Field('f_vulnid', type='list:string', label=T('Vulnerability List')),
    Field('f_cve', type='list:string', label=T('CVE List')),
    auth.signature,
    format='%(f_source)s :: %(f_name)s :: %(f_title)s :: %(f_rank)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Many-to-Many table for exploits and references
## Creates a new set, s_exploit_info
db.define_table('t_exploit_references',
    Field('f_exploit_id', 'reference t_exploits', label=T('Exploit')),
    Field('f_vulndata_id', 'reference t_vulndata'),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
s_exploit_info = db((db.t_exploits.id==db.t_exploit_references.f_exploit_id) | (db.t_vuln_refs.id==db.t_vuln_references.f_vuln_ref_id))

########################################
## CPE pre-defined operating systems
db.define_table('t_cpe_os',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('cpe', 'os_edit',args=id)))),
    Field('f_cpename', type='string', label=T('CPE Name'), requires=IS_NOT_EMPTY()),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_vendor', type='string', label=T('Vendor')),
    Field('f_product', type='string', label=T('Product')),
    Field('f_version', type='string', label=T('Version')),
    Field('f_update', type='string', label=T('Update')),
    Field('f_edition', type='string', label=T('Edition')),
    Field('f_language', type='string', label=T('Language')),
    auth.signature,
    format='%(f_cpename)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## CPE pre-defined applications
db.define_table('t_cpe_apps',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('cpe', 'apps_edit',args=id)))),
    Field('f_cpename', type='string', label=T('CPE Name'), requires=IS_NOT_EMPTY()),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_vendor', type='string', label=T('Vendor')),
    Field('f_product', type='string', label=T('Product')),
    Field('f_version', type='string', label=T('Version')),
    Field('f_update', type='string', label=T('Update')),
    Field('f_edition', type='string', label=T('Edition')),
    Field('f_language', type='string', label=T('Language')),
    auth.signature,
    format='%(f_vendor)s %(f_product)s %(f_version)',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## CPE pre-defined hardware
db.define_table('t_cpe_hardware',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('cpe', 'hardware_edit',args=id)))),
    Field('f_cpename', type='string', label=T('CPE Name'), requires=IS_NOT_EMPTY()),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_vendor', type='string', label=T('Vendor')),
    Field('f_product', type='string', label=T('Product')),
    Field('f_version', type='string', label=T('Version')),
    Field('f_update', type='string', label=T('Update')),
    Field('f_edition', type='string', label=T('Edition')),
    Field('f_language', type='string', label=T('Language')),
    auth.signature,
    format='%(f_vendor)s %(f_product)s %(f_version)',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
