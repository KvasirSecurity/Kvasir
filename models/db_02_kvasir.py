# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir Dynamic Table Definitions
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Dynamic tables that create Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.hosts import host_title_maker


########################################
## Hosts table
########################################
db.define_table('t_hosts',
    Field('id','id', represent=lambda i, row:SPAN(A(i,_id="host_detail_%s" % (i),_href=URL('hosts', 'detail',args=i)))),
    Field('f_ipv4', type='string', length=15, unique=True, requires=IS_EMPTY_OR(IS_IPV4()), label=T('IPv4 Address')),
    Field('f_ipv6', type='string', label=T('IPv6 Address'), requires=IS_EMPTY_OR(IS_IPV6())),
    Field('f_macaddr', type='string', label=T('MAC Address')),
    Field('f_hostname', type='string', label=T('Hostname')),
    Field('f_netbios_name', type='string', label=T('NetBIOS Name')),
    Field('f_confirmed', type='boolean', default=False, label=T('Confirmed')),
    Field('f_accessed', type='boolean', default=False, label=T('Accessed'), comment=T('Host has been accessed by an Engineer')),
    Field('f_followup', type='boolean', label=T('Follow Up')),
    Field('f_engineer', type='reference auth_user', label=T('Engineer')),
    Field('f_asset_group', type='string', label=T('Asset Group'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_service_count', type='integer', default=0, label=T('Service Count')),
    Field('f_vuln_count', type='integer', default=0, label=T('Vuln Count')),
    Field('f_vuln_graph', type='string', default='0,0,0,0,0,0,0,0,0,0', label=T('Vuln Graph')),
    Field('f_exploit_count', type='integer', default=0, label=T('Exploit Count')),
    format=lambda r: host_title_maker(r),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Customer operating system records
## These SHOULD be copied from CPE but
## if not they'll be flagged as such.
db.define_table('t_os',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('os', 'os_edit',args=id)))),
    Field('f_cpename', length=255, type='string', label=T('CPE Name'), unique=True),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_vendor', type='string', label=T('Vendor'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_product', type='string', label=T('Product'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_version', type='string', label=T('Version')),
    Field('f_update', type='string', label=T('Update')),
    Field('f_edition', type='string', label=T('Edition')),
    Field('f_language', type='string', label=T('Language')),
    Field('f_isincpe', type='boolean', default=False, label=T('Sourced from CPE')),
    format='%(f_cpename)s :: %(f_title)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Many-to-Many table for hosts and os
## Creates a new set result, s_host_os
db.define_table('t_host_os_refs',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('os', 'os_ref_edit',args=id)))),
    Field('f_certainty', 'double', label=T('Certainty'), requires=IS_FLOAT_IN_RANGE(0, 1), comment=T('Must be a float in range of 0 to 1.0')),
    Field('f_class', 'string', label=T('Device Class'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_family', 'string', label=T('Family'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), represent=lambda id,row:XML(host_title_maker(db.t_hosts[id]))),
    Field('f_os_id', 'reference t_os', label=T('OS'), represent=lambda id,row:db.t_os[id].f_title),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate,
    )
s_host_os = db((db.t_hosts.id==db.t_host_os_refs.f_hosts_id) | (db.t_os.id==db.t_host_os_refs.f_os_id))

########################################
## Services (ports, essentially)
db.define_table('t_services',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('services', 'edit',args=id)))),
    Field('f_proto', type='string', notnull=True, label=T('Protocol'), default="tcp", requires=IS_IN_SET(('tcp', 'udp', 'info', 'other'))),
    Field('f_number', type='string', notnull=True, label=T('Number'), requires=IS_INT_IN_RANGE(0, 65536)),
    Field('f_status', type='string', label=T('Status'), default="open", requires=IS_IN_SET(('open', 'closed', 'info'))),
    Field('f_name', type='string', label=T('Service Name'), widget=autocomplete_bootstrap),
    Field('f_banner', type='text', label=T('Banner')),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), represent=lambda id,row:XML(host_title_maker(db.t_hosts[id]))),
    format=lambda r:XML("%s :: %s/%s" % (db.t_hosts[r.f_hosts_id.id].f_ipv4, r.f_proto, r.f_number)),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Customer applications, like t_os
## these should be copies from t_cpe_apps
db.define_table('t_apps',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('apps', 'apps_edit',args=id)))),
    Field('f_cpename', type='string', label=T('CPE Name'), requires=IS_NOT_EMPTY()),
    Field('f_title', type='string', label=T('Title'), requires=IS_NOT_EMPTY()),
    Field('f_vendor', type='string', label=T('Vendor'), widget=autocomplete_bootstrap),
    Field('f_product', type='string', label=T('Product'), widget=autocomplete_bootstrap),
    Field('f_version', type='string', label=T('Version')),
    Field('f_update', type='string', label=T('Update')),
    Field('f_edition', type='string', label=T('Edition')),
    Field('f_language', type='string', label=T('Language')),
    Field('f_isincpe', type='boolean', default=False, label=T('Sourced from CPE')),
    format='%(f_vendor)s %(f_product)s %(f_version)',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Many-to-Many table for services and apps
## Creates a new set, s_app_fingerprints
db.define_table('t_services_apps_refs',
    Field('f_certainty', 'double', label=T('Certainty')),
    Field('f_services_id', 'reference t_services'),
    Field('f_apps_id', 'reference t_apps'),
    format='%(f_services_id.f_number)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate,
    )
s_app_fingerprints = db((db.t_services.id==db.t_services_apps_refs.f_services_id) | (db.t_apps.id==db.t_services_apps_refs.f_apps_id))

vuln_status_set = [
    'exploited',
    'vulnerable',
    'vulnerable-exploited',
    'vulnerable-version',
    'general',
    'potential',
    'exception-vulnerable-exploited',
    'exception-vulnerable-version',
    'exception-vulnerable-potential',
]

########################################
## Service vulnerabilities
## Vulns are associated to services, this links t_vulndata to t_services
## and adds status and proof fields
db.define_table('t_service_vulns',
    Field('id','id',represent=lambda id,row:SPAN(A(id,_href=URL('vulns' 'service_vulns_edit',args=id)))),
    Field('f_services_id', 'reference t_services', label=T('Service')),
    Field('f_vulndata_id', 'reference t_vulndata', label=T('Vulnerability')),
    Field('f_status', type='string', label=T('Status'),
        requires=IS_IN_SET(vuln_status_set)),
    Field('f_proof', type='text', length=65535, label=T('Proof'), represent=lambda x, row: MARKMIN(x)),
    Field('f_exploited', 'boolean', default=False, label=T('Exploited')),
    format='%(f_service.f_proto)s/%(f_service.f_number)s :: %(f_status)s :: %(f_vulnid)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

s_service_vuln_data = db(db.t_service_vulns.f_vulndata_id==db.t_vulndata.id)

########################################
## Service info
## Additional service info such as netbios names
db.define_table('t_service_info',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('services', 'info_edit',args=id)))),
    Field('f_services_id', 'reference t_services', label=T('Service'),
        represent=lambda id,row:XML("%s :: %s/%s" % (host_title_maker([db.t_services[id].f_hosts_id]), db.t_services[id].f_proto, db.t_services[id].f_number))),
    Field('f_name', type='text', label=T('Key'), requires=IS_NOT_EMPTY(), widget=autocomplete_bootstrap),
    Field('f_text', type='text', length=2048, label=T('Value'), requires=IS_NOT_EMPTY(), widget=autocomplete_bootstrap),
    format='%(f_service.f_proto)s/%(f_service.f_number)s :: %(f_name) :: %(f_text)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Accounts
## Linked to t_services

## list of password file types supported by the upload process
settings.password_file_types = (
    'PWDUMP',
    'MSCa$h Dump',
    'UNIX Passwd',
    'UNIX Shadow',
    'Medusa',
    'Hydra',
    'Metasploit Creds CSV',
    'Username:Password',
    'Usernames',
    'AccountDB',
)

db.define_table('t_accounts',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('edit',args=id)))),
    Field('f_services_id', 'reference t_services', label=T('Service'),
        represent=lambda id,row:XML("%s :: %s/%s" % (host_title_maker(db.t_hosts[db.t_services[id].f_hosts_id]), db.t_services[id].f_proto, db.t_services[id].f_number))),
    Field('f_username', type='string', label=T('Username'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_fullname', type='string', label=T('Fullname'), widget=autocomplete_bootstrap),
    Field('f_password', type='string', label=T('Password'), widget=autocomplete_bootstrap),
    Field('f_compromised', type='boolean', label=T('Compromised')),
    Field('f_hash1', type='string', label=T('Hash1')),
    Field('f_hash1_type', type='string', label=T('Hash1 Type'), widget=autocomplete_bootstrap),
    Field('f_hash2', type='string', label=T('Hash2')),
    Field('f_hash2_type', type='string', label=T('Hash2 Type'), widget=autocomplete_bootstrap),
    Field('f_source', type='string', label=T('Source'), widget=autocomplete_bootstrap),
    Field('f_uid', type='string', label=T('UID')),
    Field('f_gid', type='string', label=T('GID')),
    Field('f_level', type='string', label=T('Level'), requires=IS_IN_SET(('ADMIN', 'USER', 'SERVICE'), multiple=False), default="ADMIN"),
    Field('f_domain', type='string', label=T('Domain'), widget=autocomplete_bootstrap),
    Field('f_message', type='string', label=T('Message')),
    Field('f_lockout', type='boolean', label=T('Lockoutable'), default=False),
    Field('f_duration', type='integer', label=T('Lockout Duration')),
    Field('f_active', type='boolean', label=T('Active')),
    Field('f_description', type='string', label=T('Description')),
    format='%(f_username)s :: %(f_password)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

#s_service_accts = db( (db.t_accounts.f_services_id==db.t_services.id) & (db.t_hosts.id == db.t_services.f_hosts_id) )

########################################
## User Groups
#db.define_table('t_groups',
#    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('accounts', 'group_edit',args=id)))),
#    Field('f_services_id', db.t_services, label=T('Service')),
#    Field('f_name', type='string', label=T('Name')),
#    Field('f_password', type='string', label=T('Password')),
#    Field('f_groupid', type='string', label=T('GroupID')),
#    Field('f_sid', type='string', label=T('Windows SID')),
#    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Accounts -> Group References and Set()
## TODO: Nested Group references
#db.define_table('t_group_account_refs',
#    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('acct_groups_edit',args=id)))),
#    Field('f_accounts_id', db.t_accounts, label=T('Account')),
#    Field('f_groups_id', db.t_groups, label=T('Group')),
#    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
#s_account_groups = db((db.t_accounts.id==db.t_group_account_refs.f_accounts_id) | (db.t_groups.id==db.t_group_account_refs.f_groups_id))

########################################
## Host-specific notes (not seen by customer)
db.define_table('t_host_notes',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('notes', 'edit',args=id)))),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), represent=lambda id,row:XML(host_title_maker(db.t_hosts[id]))),
    Field('f_note', type='text', represent=lambda x, row: MARKMIN(x), label=T('Note'), requires=IS_NOT_EMPTY()),
    format='%(f_note)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Evidence files
db.define_table('t_evidence',
    Field('id', 'id', represent=lambda id, row: SPAN(A(id, _href=URL('evidence', 'edit', args=id)))),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), represent=lambda id, row: XML(host_title_maker(db.t_hosts[id]))),
    Field('f_type', type='list:string', label=T('Type'), requires=IS_IN_SET(
        ('Log file', 'Screenshot', 'Password file', 'Router/Switch Config', 'Database Data', 'Session Log', 'Other'))),
    Field('f_other_type', type='string', label=T('Other Type')),
    Field('f_text', type='text', label=T('Text')),
    Field('f_filename', type='string', label=T('Filename')),
    # Files are stored in the database, to change this uncomment the next line and comment the one after it
    #Field('f_evidence', 'upload', uploadfolder=os.path.join(request.folder, 'data', 'evidence'), label=T('File'), autodelete=False),
    Field('f_evidence', 'upload', label=T('File'), uploadfield='f_data'),
    Field('f_data', 'blob'),
    format='%(f_note_type)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## SNMP Info
db.define_table('t_snmp',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('snmp', 'edit', args=id)))),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), represent=lambda id,row:XML(host_title_maker(db.t_hosts[id]))),
    Field('f_community', type='string', label=T('Community String'), widget=autocomplete_bootstrap, requires=IS_NOT_EMPTY()),
    Field('f_version', type='string', label=T('SNMP Version'), default="v1", requires=IS_IN_SET(('v1', 'v2c', 'v3'), multiple=False)),
    Field('f_access', type='string', label=T('Access Type'), default="READ", requires=IS_IN_SET(('READ', 'WRITE'), multiple=False)),
    format='%(f_note_type)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## NetBIOS Info
db.define_table('t_netbios',
    Field('id','id', represent=lambda id,row:SPAN(A(id,_href=URL('netbios', 'edit',args=id)))),
    Field('f_hosts_id', type='reference t_hosts', label=T('Host'), unique=True, represent=lambda id,row:XML(host_title_maker(db.t_hosts[id]))),
    Field('f_type', type='string', label=T('Server Type'), default="Workstation", requires=IS_IN_SET(('Server', 'Workstation', 'PDC', 'BDC', 'Other'))),
    Field('f_advertised_names', type='list:string', label=T('Advertised Names')),
    Field('f_domain', type='string', label=T('Domain Name'), widget=autocomplete_bootstrap),
    Field('f_lockout_limit', type='integer', label=T('Lockout Limit'), default=0),
    Field('f_lockout_duration', type='integer', label=T('Lockout Duration'), default=1440),
    Field('f_shares', type='list:string', label=T('Shares')),
    format='%(f_note_type)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
