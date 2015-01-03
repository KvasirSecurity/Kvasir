# -*- coding: utf-8 -*-

##--------------------------------------#
## Metasploit Table Definitions
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

# Note that this makes direct queries to the Metasploit database. Kvasir
# will have full read/write privileges to all Workspaces.
#
# At this time only read-access is required as we do not do any writes
# to the db as our purpose here is to retrieve data from Metasploit
# that the API doesn't do. Any actions requested by Kvasir to Metasploit
# are performed through the API.

if settings.msfdb_uri:
    msfdb = DAL(settings.msfdb_uri, pool_size=10)

    migrate = False

    msfdb.define_table('cred_files',
        Field('id', type='id'),
        Field('workspace_id', type='integer', default=1),
        Field('path', type='string', length=1024),
        Field('ftype', type='string', length=16),
        Field('created_by', type='string', length=255),
        Field('name', type='string', length=512),
        Field('desc', type='string', length=1024),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    """
    XXX: creds must use a executesql query since it uses a python
         keyword as the field name ('pass')
    msfdb.define_table('creds',
        Field('id', type='id'),
        Field('service_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('user', type='string', length=2048),
        Field('pass', type='string', length=4096),
        Field('active', type='boolean', default=True),
        Field('proof', type='string', length=4096),
        Field('ptype', type='string', length=256),
        Field('source_id', type='integer'),
        Field('source_type', type='string', length=255),
        migrate=migrate)
    """

    msfdb.define_table('exploit_attempts',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('service_id', type='integer'),
        Field('vuln_id', type='integer'),
        Field('attempted_at', type='datetime'),
        Field('exploited', type='boolean'),
        Field('fail_reason', type='string', length=255),
        Field('username', type='string', length=255),
        Field('module', type='text'),
        Field('session_id', type='integer'),
        Field('loot_id', type='integer'),
        Field('port', type='integer'),
        Field('proto', type='string', length=255),
        Field('fail_detail', type='text'),
        migrate=migrate)

    msfdb.define_table('exploited_hosts',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('service_id', type='integer'),
        Field('session_uuid', type='string', length=8),
        Field('name', type='string', length=2048),
        Field('payload', type='string', length=2048),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('host_details',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('nx_console_id', type='integer'),
        Field('nx_device_id', type='integer'),
        Field('src', type='string', length=255),
        Field('nx_site_name', type='string', length=255),
        Field('nx_site_importance', type='string', length=255),
        Field('nx_scan_template', type='string', length=255),
        Field('nx_risk_score', type='double'),
        migrate=migrate)

    msfdb.define_table('hosts',
        Field('id', type='id'),
        Field('created_at', type='datetime'),
        Field('address', type='string'),
        Field('mac', type='string', length=255),
        Field('comm', type='string', length=255),
        Field('name', type='string', length=255),
        Field('state', type='string', length=255),
        Field('os_name', type='string', length=255),
        Field('os_flavor', type='string', length=255),
        Field('os_sp', type='string', length=255),
        Field('os_lang', type='string', length=255),
        Field('arch', type='string', length=255),
        Field('workspace_id', type='integer'),
        Field('updated_at', type='datetime'),
        Field('purpose', type='text'),
        Field('info', type='string', length=65536),
        Field('comments', type='text'),
        Field('scope', type='text'),
        Field('virtual_host', type='text'),
        Field('note_count', type='integer', default=0),
        Field('vuln_count', type='integer', default=0),
        Field('service_count', type='integer', default=0),
        Field('host_detail_count', type='integer', default=0),
        Field('exploit_attempt_count', type='integer', default=0),
        migrate=migrate)

    msfdb.define_table('hosts_tags',
        Field('host_id', type='integer'),
        Field('tag_id', type='integer'),
        migrate=migrate)

    """
    XXX: imported_creds must use a executesql query since it uses a python
         keyword as the field name ('pass')
    msfdb.define_table('imported_creds',
        Field('id', type='id'),
        Field('workspace_id', type='integer', default=1),
        Field('user', type='string', length=512),
        Field('pass', type='string', length=512),
        Field('ptype', type='string', length=16),
        migrate=migrate)
    """

    msfdb.define_table('loots',
        Field('id', type='id'),
        Field('workspace_id', type='integer', default=1),
        Field('host_id', type='integer'),
        Field('service_id', type='integer'),
        Field('ltype', type='string', length=512),
        Field('path', type='string', length=1024),
        Field('data', type='text'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('content_type', type='string', length=255),
        Field('name', type='text'),
        Field('info', type='text'),
        migrate=migrate)

    msfdb.define_table('notes',
        Field('id', type='id'),
        Field('created_at', type='datetime'),
        Field('ntype', type='string', length=512),
        Field('workspace_id', type='integer', default=1),
        Field('service_id', type='integer'),
        Field('host_id', type='integer'),
        Field('updated_at', type='datetime'),
        Field('critical', type='boolean'),
        Field('seen', type='boolean'),
        Field('data', type='text'),
        migrate=migrate)

    msfdb.define_table('refs',
        Field('id', type='id'),
        Field('ref_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('name', type='string', length=512),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('services',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('port', type='integer'),
        Field('proto', type='string', length=16),
        Field('state', type='string', length=255),
        Field('name', type='string', length=255),
        Field('updated_at', type='datetime'),
        Field('info', type='text'),
        migrate=migrate)

    msfdb.define_table('session_events',
        Field('id', type='id'),
        Field('session_id', type='integer'),
        Field('etype', type='string', length=255),
        Field('command', type='blob'),
        Field('output', type='blob'),
        Field('remote_path', type='string', length=255),
        Field('local_path', type='string', length=255),
        Field('created_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('sessions',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('stype', type='string', length=255),
        Field('via_exploit', type='string', length=255),
        Field('via_payload', type='string', length=255),
        Field('desc', type='string', length=255),
        Field('port', type='integer'),
        Field('platform', type='string', length=255),
        Field('datastore', type='text'),
        Field('opened_at', type='datetime'),
        Field('closed_at', type='datetime'),
        Field('close_reason', type='string', length=255),
        Field('local_id', type='integer'),
        Field('last_seen', type='datetime'),
        migrate=migrate)

    msfdb.define_table('tags',
        Field('id', type='id'),
        Field('user_id', type='integer'),
        Field('name', type='string', length=1024),
        Field('desc', type='text'),
        Field('report_summary', type='boolean', default=False),
        Field('report_detail', type='boolean', default=False),
        Field('critical', type='boolean', default=False),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('tasks',
        Field('id', type='id'),
        Field('workspace_id', type='integer', default=1),
        Field('created_by', type='string', length=255),
        Field('module', type='string', length=255),
        Field('completed_at', type='datetime'),
        Field('path', type='string', length=1024),
        Field('info', type='string', length=255),
        Field('description', type='string', length=255),
        Field('progress', type='integer'),
        Field('options', type='text'),
        Field('error', type='text'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('result', type='text'),
        Field('module_uuid', type='string', length=8),
        Field('settings', type='blob'),
        migrate=migrate)

    msfdb.define_table('vuln_attempts',
        Field('id', type='id'),
        Field('vuln_id', type='integer'),
        Field('attempted_at', type='datetime'),
        Field('exploited', type='boolean'),
        Field('fail_reason', type='string', length=255),
        Field('username', type='string', length=255),
        Field('module', type='text'),
        Field('session_id', type='integer'),
        Field('loot_id', type='integer'),
        Field('fail_detail', type='text'),
        migrate=migrate)

    msfdb.define_table('vuln_details',
        Field('id', type='id'),
        Field('vuln_id', type='integer'),
        Field('cvss_score', type='double'),
        Field('cvss_vector', type='string', length=255),
        Field('title', type='string', length=255),
        Field('description', type='text'),
        Field('solution', type='text'),
        Field('proof', type='blob'),
        Field('nx_console_id', type='integer'),
        Field('nx_device_id', type='integer'),
        Field('nx_vuln_id', type='string', length=255),
        Field('nx_severity', type='double'),
        Field('nx_pci_severity', type='double'),
        Field('nx_published', type='datetime'),
        Field('nx_added', type='datetime'),
        Field('nx_modified', type='datetime'),
        Field('nx_tags', type='text'),
        Field('nx_vuln_status', type='text'),
        Field('nx_proof_key', type='text'),
        Field('src', type='string', length=255),
        Field('nx_scan_id', type='integer'),
        Field('nx_vulnerable_since', type='datetime'),
        Field('nx_pci_compliance_status', type='string', length=255),
        migrate=migrate)

    msfdb.define_table('vulns',
        Field('id', type='id'),
        Field('host_id', type='integer'),
        Field('service_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('name', type='string', length=255),
        Field('updated_at', type='datetime'),
        Field('info', type='string', length=65536),
        Field('exploited_at', type='datetime'),
        Field('vuln_detail_count', type='integer', default=0),
        Field('vuln_attempt_count', type='integer', default=0),
        migrate=migrate)

    msfdb.define_table('vulns_refs',
        Field('ref_id', type='integer'),
        Field('vuln_id', type='integer'),
        migrate=migrate)

    msfdb.define_table('web_forms',
        Field('id', type='id'),
        Field('web_site_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('path', type='text'),
        Field('method', type='string', length=1024),
        Field('params', type='text'),
        Field('query', type='text'),
        migrate=migrate)

    msfdb.define_table('web_pages',
        Field('id', type='id'),
        Field('web_site_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('path', type='text'),
        Field('query', type='text'),
        Field('code', type='integer'),
        Field('cookie', type='text'),
        Field('auth', type='text'),
        Field('ctype', type='text'),
        Field('mtime', type='datetime'),
        Field('location', type='text'),
        Field('headers', type='text'),
        Field('body', type='blob'),
        Field('request', type='blob'),
        migrate=migrate)

    msfdb.define_table('web_sites',
        Field('id', type='id'),
        Field('service_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('vhost', type='string', length=2048),
        Field('comments', type='text'),
        Field('options', type='text'),
        migrate=migrate)

    msfdb.define_table('web_templates',
        Field('id', type='id'),
        Field('name', type='string', length=512),
        Field('title', type='string', length=512),
        Field('body', type='string', length=524288),
        Field('campaign_id', type='integer'),
        Field('prefs', type='text'),
        migrate=migrate)

    msfdb.define_table('web_vulns',
        Field('id', type='id'),
        Field('web_site_id', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('path', type='text'),
        Field('method', type='string', length=1024),
        Field('params', type='text'),
        Field('pname', type='text'),
        Field('risk', type='integer'),
        Field('name', type='string', length=1024),
        Field('query', type='text'),
        Field('category', type='text'),
        Field('confidence', type='text'),
        Field('description', type='text'),
        Field('blame', type='text'),
        Field('request', type='blob'),
        Field('proof', type='blob'),
        Field('owner', type='string', length=255),
        Field('payload', type='text'),
        migrate=migrate)

    msfdb.define_table('wmap_requests',
        Field('id', type='id'),
        Field('host', type='string', length=255),
        Field('address', type='string'),
        Field('port', type='integer'),
        Field('ssl', type='integer'),
        Field('meth', type='string', length=32),
        Field('path', type='text'),
        Field('headers', type='text'),
        Field('query', type='text'),
        Field('body', type='text'),
        Field('respcode', type='string', length=16),
        Field('resphead', type='text'),
        Field('response', type='text'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('wmap_targets',
        Field('id', type='id'),
        Field('host', type='string', length=255),
        Field('address', type='string'),
        Field('port', type='integer'),
        Field('ssl', type='integer'),
        Field('selected', type='integer'),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        migrate=migrate)

    msfdb.define_table('workspaces',
        Field('id', type='id'),
        Field('name', type='string', length=255),
        Field('created_at', type='datetime'),
        Field('updated_at', type='datetime'),
        Field('boundary', type='string', length=4096),
        Field('description', type='string', length=4096),
        Field('owner_id', type='integer'),
        Field('limit_to_network', type='boolean', default=False),
        migrate=migrate)
