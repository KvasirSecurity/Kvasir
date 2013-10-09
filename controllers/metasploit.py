# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Metasploit controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import host_title_maker
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def api_settings():
    """Settings Metasploit API"""
    msf_key = session.msf_key or auth.user.f_msf_pro_key
    msf_url = session.msf_host or auth.user.f_msf_pro_url
    msf_ws_num = session.msf_workspace_num or 1
    msf_user = session.msf_user or None
    response.title = "%s :: Metasploit API Settings" % (settings.title)

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, form=None)

    error=None
    alert=False
    msf = MetasploitAPI(host=msf_url, apikey=msf_key)
    try:
        workspaces = [w for w in msf.pro_workspaces().keys()]
        users = [u for u in msf.pro_users().get('users').keys()]
    except MSFAPIError, e:
        error = str(e)
        alert = True
        workspaces = []
        users = []

    form=SQLFORM.factory(
        Field('workspace', 'string', default=session.msf_workspace, label=T('Workspace Name'), requires=IS_IN_SET(workspaces)),
        Field('workspace_num', 'string', default=msf_ws_num, label=T('Workspace Number')),
        Field('user', 'string', default=msf_user, label=T('MSF User'), requires=IS_IN_SET(users)),
        Field('url', 'string', default=msf_url, label=T('MSF URL')),
        Field('msf_key', 'string', default=msf_key, label=T('API Key')),
    )
    # NOTE: workspace_num must be manually entered since there's no way for us
    # to learn it from the API. We're just guessing otherwise - 1 is the default
    # workspace so it's more likely to exist
    if form.accepts(request, session):
        session.msf_workspace = form.vars.workspace
        session.msf_workspace_num = form.vars.workspace_num
        session.msf_key = form.vars.msf_key
        session.msf_user = form.vars.user
        auth.user.f_msf_pro_key = form.vars.msf_key
        auth.user.f_msf_pro_url = form.vars.url
        response.flash = "MSF Settings updated"
    elif form.errors:
        response.flash = "Errors in your form!"
    return dict(form=form, error=str(error), alert=False)

##-------------------------------------------------------------------------
## mass bruteforce / exploit
##-------------------------------------------------------------------------

@auth.requires_login()
def bruteforce():
    """
    Launches a Metasploit Pro Bruteforce based upon a list of host records
    """
    workspace = session.msf_workspace
    response.title = "%s :: Metasploit Pro Bruteforce" % (settings.title)

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(alert=True, error=str(error), form=None)

    host_records = request.vars.host_records
    if host_records:
        def host_to_ip(host_rec):
            if isinstance(host_rec, (int, str)):
                host_rec = get_host_record(host_rec)
            if not host_rec:
                return None
            return host_rec.get('f_ipv4') or host_rec.get('f_ipv6')
        target_ips = '\n'.join([host_to_ip(x) for x in host_records.split('|')])
    else:
        target_ips = ''

    loot_list = []    # list of loot IDs and IPs
    alert = False
    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(alert=True, error=str(error), form=None)

    form = SQLFORM.factory(
        Field('targets', 'text', default=target_ips, label=T('Targets'), requires=IS_NOT_EMPTY(),
            comment=T('Targets to scan can be IP Addresses, ranged lists or subnets. One per line.'),
        ),
        Field('blacklist', 'text', label=T('Blacklisted hosts'),
            comment=T('Targets to blacklist can be IP Addresses, ranged lists or subnets. One per line.')
        ),
        Field('stop_on_success', 'boolean', default=True, label=T('Stop on success'),
            comment=T('Stop scanning a host after first user login success')
        ),
        Field('verbose', 'boolean', default=False, label=T('Verbose')),
        Field('include_known', 'boolean', default=True, label=T('Include known'),
            comment=T('Include known credentials from the Workspace')
        ),
        Field('dry_run', 'boolean', default=False, label=T('Dry run'),
            comment=T('Prepare for execution but do nothing')
        ),
        Field('scope', 'string', default='normal', label=T('Scope'),
            requires=IS_IN_SET(['quick', 'defaults', 'normal', 'deep', 'known', 'imported', '50k']),
        ),
        Field('speed', 'string', default=3, label=T('Speed'),
            requires=IS_IN_SET([
                [ 0, 'Glacial'], [1, 'Slow'], [2, 'Stealthy'], [3, 'Normal'], [4, 'Fast'], [5, 'Turbo']
            ])
        ),
        Field('services', 'list:string', label=T('Services'),
            requires=IS_EMPTY_OR(IS_IN_SET(
                ['Telnet', 'SSH', 'SMB', 'VNC', 'SNMP', 'Postgres', 'MySQL', 'MSSQL', 'Oracle',
                 'DB2', 'FTP', 'HTTP', 'HTTPS', 'EXEC', 'LOGIN', 'SHELL', ], multiple=(1,17))
            ),
            comment=T('List of services to bruteforce, multiples permitted')
        ),
        Field('addl_creds', 'text', label=T('Additional credentals'),
            comment=T('List additional credentials to test. One per line with space between username and password.')
        ),
        Field('getsession', 'boolean', default=True, label=T('Execute session'),
            comment=T('On successful access pop a shell or meterpreter session')
        ),
        Field('payload', 'string', default='auto', label=T('Payload method'),
            requires=IS_IN_SET(['auto', 'reverse', 'bind'])
        ),
        Field('payload_type', 'string', default='meterpreter', label=T('Paylod type'),
            requires=IS_IN_SET(['meterpreter', 'shell'])
        ),
        Field('payload_ports', 'string', default='4000-5000', label=T('Payload ports'),
            requires=IS_NOT_EMPTY(),
            comment=T('Port range for reverse/connect payloads'),
        ),
        Field('smb_domains', 'string', label=T('SMB Domains'),
            comment=T('List of SMB domains, separated by spaces, to use')
        ),
        Field('preverse_domains', 'boolean', default=True, label=T('Preserve Domains'),
            comment=T('Use previously identified SMB Domains with usernames')
        ),
        Field('mssql_windows_auth', 'boolean', default=False, label=T('MSSQL Windows Auth'),
            comment=T('MSSQL attempts should use NTLM instead of Standard mode')
        ),
        Field('skip_blank_pw', 'boolean', default=False, label=T('Blanks')),
        Field('skip_machine_names', 'boolean', default=False, label=T('Machine names')),
        Field('skip_builtin_windows', 'boolean', default=False, label=T('Built-in Windows')),
        Field('skip_builtin_unix', 'boolean', default=False, label=T('Built-in UNIX')),
        Field('recombine_creds', 'boolean', default=False, label=T('Recombine credentials')),
        Field('max_guess_per_svc', 'integer', default=0, label=T('Per service'), requires=IS_INT_IN_RANGE(0, 65535)),
        Field('max_guess_per_user', 'integer', default=0, label=T('Per user'), requires=IS_INT_IN_RANGE(0, 65535)),
        Field('max_guess_overall', 'integer', default=0, label=T('Overall'), requires=IS_INT_IN_RANGE(0, 65535)),
        Field('max_time_per_svc', 'integer', default=0, label=T('Per service'), requires=IS_INT_IN_RANGE(0, 1440),
            comment=T('Maximum time to bruteforce per service (in minutes')
        ),
        Field('max_time', 'integer', default=0, label=T('Overall'), requires=IS_INT_IN_RANGE(0, 65535),
            comment=T('Maximum time to run brute force (in minutes)')
        ),
        table_name='msfpro_bruteforce',
        _class="form-horizontal"
    )

    if form.process().accepted:
        args = {
            'workspace': session.msf_workspace,
            'username': session.msf_user,
            'DS_WHITELIST_HOSTS': form.vars.targets,
            'DS_BLACKLIST_HOSTS': form.vars.blacklist,
            'DS_STOP_ON_SUCCESS': form.vars.stop_on_success,
            'DS_VERBOSE': form.vars.verbose,
            'DS_INCLUDE_KNOWN': form.vars.include_known,
            'DS_DRY_RUN': form.vars.dry_run,
            'DS_BRUTEFORCE_SCOPE': form.vars.scope,
            'DS_BRUTEFORCE_SPEED': form.vars.speed,
            'DS_BRUTEFORCE_SERVICES': " ".join(form.vars.services),
            'DS_BRUTEFORCE_GETSESSION': form.vars.getsession,
            'DS_QUICKMODE_CREDS': form.vars.addl_creds,
            'DS_PAYLOAD_METHOD': form.vars.payload,
            'DS_PAYLOAD_TYPE': form.vars.payload_type,
            'DS_PAYLOAD_PORTS': form.vars.payload_ports,
            'DS_SMB_DOMAINS': form.vars.smb_domains,
            'DS_PRESERVE_DOMAINS': form.vars.preverse_domains,
            'DS_MAXGUESSESPERSERVICE': form.vars.max_guess_per_svc,
            'DS_MAXGUESSESPERUSER': form.vars.max_guess_per_user,
            'DS_MAXGUESSESOVERALL': form.vars.max_guess_overall,
            'DS_MAXMINUTESPERSERVICE': form.vars.max_time_per_svc,
            'DS_MAXMINUTESOVERALL': form.vars.max_time,
            'DS_BRUTEFORCE_SKIP_BLANK_PASSWORDS': form.vars.skip_blank_pw,
            'DS_BRUTEFORCE_SKIP_MACHINE_NAMES': form.vars.skip_machine_names,
            'DS_BRUTEFORCE_SKIP_BUILTIN_WINDOWS_ACCOUNTS': form.vars.skip_builtin_windows,
            'DS_BRUTEFORCE_SKIP_BLANK_BUILTIN_UNIX_ACCOUNTS': form.vars.skip_builtin_unix,
            'DS_BRUTEFORCE_RECOMBINE_CREDS': form.vars.recombine_creds,
            'DS_MSSQL_WINDOWS_AUTH': form.vars.mssql_windows_auth
        }
        task = msf.start_bruteforce(args)
        msfurl = os.path.join(auth.user.f_msf_pro_url, 'workspaces', session.msf_workspace_num, 'tasks', task['task_id'])
        redirect(msfurl)
    elif form.errors:
        response.flash = "Error in form"

    return dict(form=form, alert=alert, error=False)

@auth.requires_login()
def exploit():
    """
    Launches Metasploit Pro Exploit based upon a list of host records
    """
    workspace = session.msf_workspace
    response.title = "%s :: Metasploit Pro Exploit" % (settings.title)

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(alert=True, error=str(error), form=None)

    host_records = request.vars.host_records
    if host_records:
        def host_to_ip(host_rec):
            if isinstance(host_rec, (int, str)):
                host_rec = get_host_record(host_rec)
            if not host_rec:
                return None
            return host_rec.get('f_ipv4') or host_rec.get('f_ipv6')
        target_ips = '\n'.join([host_to_ip(x) for x in host_records.split('|')])
    else:
        target_ips = ''

    module_list = []
    alert = False
    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        module_list = msf.module_list(modtype='exploits').get('modules')
    except MSFAPIError, error:
        return dict(alert=True, error=str(error), form=None)

    form = SQLFORM.factory(
        Field('targets', 'text', default=target_ips, label=T('Targets'), requires=IS_NOT_EMPTY(),
            comment=T('Targets to scan can be IP Addresses, ranged lists or subnets. One per line.')
        ),
        Field('blacklist_hosts', 'text', label=T('Blacklisted Targets'),
            comment=T('Targets to blacklist can be IP Addresses, ranged lists or subnets. One per line.')
        ),
        Field('ports', 'string', default='1-65535', label=T('Ports'), requires=IS_NOT_EMPTY(),
            comment=T('List of ports to match exploits to. Example: 21-23,80,443,8000-8999')
        ),
        Field('blacklist_ports', 'string', label=T('Blacklisted Ports'),
            comment=T('List of ports to not exploit. Example: 21-23,80,443,8000-8999')
        ),
        Field('min_rank', 'string', default='great', label=T('Minmum Exploit Rank'),
            requires=IS_IN_SET(['low', 'average', 'normal', 'good', 'great', 'excellent']),
            comment=T('Minimum reliability level of exploits to include')
        ),
        Field('exploit_speed', 'integer', default=5, label=T('Parallel Exploits'), requires=IS_INT_IN_RANGE(1, 11),
            comment=T('How many exploits to run in parallel (1-10)')
        ),
        Field('exploit_timeout', 'integer', default=5, label=T('Timeout (in minutes)'),  requires=IS_INT_IN_RANGE(0, 1440),
            comment=T('Maximum time (in minutes) an exploit is allowed to run')
        ),
        Field('limit_sessions', 'boolean', default=True, label=T('Limit sessions'),
            comment=T('Limit sessions to only one per exploited host')
        ),
        Field('ignore_fragile', 'boolean', default=True, label=T('Skip "fragile" devices'),
            comment=T('Avoid exploit attempts on fragile systems such as network devices and printers.')
        ),
        Field('filter_by_os', 'boolean', default=True, label=T('OS'),
            comment=T('Match exploits to Operating System, known vulnerabilities or ports')
        ),
        Field('filter_by_vuln', 'boolean', default=True, label=T('Vulnerabilities')),
        Field('filter_by_ports', 'boolean', default=True, label=T('Ports')),
        Field('dry_run', 'boolean', default=False, label=T('Dry run'),
            comment=T('Prepare for execution but do nothing')
        ),
        Field('payload', 'string', default='auto', label=T('Payload method'),
            requires=IS_IN_SET(['auto', 'reverse', 'bind'])
        ),
        Field('payload_type', 'string', default='meterpreter', label=T('Paylod type'),
            requires=IS_IN_SET(['meterpreter', 'shell'])
        ),
        Field('payload_ports', 'string', default='4000-5000', label=T('Payload ports'),
            requires=IS_NOT_EMPTY(),
            comment=T('Port range for reverse/connect payloads')),
        Field('evasion_tcp', 'integer', default=0, label=T('TCP Evasion Level'), requires=IS_INT_IN_RANGE(0, 4)),
        Field('evasion_app', 'integer', default=0, label=T('Application Evasion'), requires=IS_INT_IN_RANGE(0, 4)),
        Field('modules', 'list:string', label=T('Specifc Module(s)'),
            requires=IS_EMPTY_OR(IS_IN_SET(module_list, multiple=True)),
            comment=T('A whitelist of modules to execute, by default all that match are tried')
        ),
        table_name='msfpro_exploit',
        _class="form-horizontal"
    )

    if form.process().accepted:
        args = {
            'workspace': session.msf_workspace,
            'username': session.msf_user,
            'DS_WHITELIST_HOSTS': form.vars.targets,
            'DS_BLACKLIST_HOSTS': form.vars.blacklist_hosts,
            'DS_WHITELIST_PORTS': form.vars.ports,
            'DS_BLACKLIST_PORTS': form.vars.blacklist_ports,
            'DS_MinimumRank': form.vars.min_rank,
            'DS_EXPLOIT_SPEED': form.vars.exploit_speed,
            'DS_EXPLOIT_TIMEOUT': form.vars.exploit_timeout,
            'DS_LimitSessions': form.vars.limit_sessions,
            'DS_IgnoreFragileDevices': form.vars.ignore_fragile,
            'DS_FilterByOS': form.vars.filter_by_os,
            'DS_MATCH_VULNS': form.vars.filter_by_vuln,
            'DS_MATCH_PORTS': form.vars.filter_by_ports,
            'DS_OnlyMatch': form.vars.dry_run,
            'DS_PAYLOAD_METHOD': form.vars.payload,
            'DS_PAYLOAD_TYPE': form.vars.payload_type,
            'DS_PAYLOAD_PORTS': form.vars.payload_ports,
            'DS_EVASION_LEVEL_TCP': form.vars.evasion_tcp,
            'DS_EVASION_LEVEL_APP': form.vars.evasion_app,
            #'DS_ModuleFilter': form.vars.filter_by_os,
        }
        task = msf.start_exploit(args)
        msfurl = os.path.join(auth.user.f_msf_pro_url, 'workspaces', session.msf_workspace_num, 'tasks', task['task_id'])
        redirect(msfurl)
    elif form.errors:
        response.flash = "Error in form"

    return dict(form=form, alert=alert)

##-------------------------------------------------------------------------
## loots
##-------------------------------------------------------------------------

@auth.requires_login()
def import_pwdump():
    """Downloads a pwdump loot and processes it"""
    workspace = session.msf_workspace
    alert = False
    error = None
    response.title = "%s :: Import Metasploit PWDUMP Loot" % (settings.title)

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(alert=True, error=str(error), form=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
        data = msf.loot_list(workspace)
    except MSFAPIError, error:
        return dict(alert=True, error=str(error), form=None)

    if not alert:
        loot_list = []    # list of loot IDs and IPs
        loot_hosts = {}   # mapping of IP to loot IDs
        for k,v in data.iteritems():
            if v['ltype'] == 'host.windows.pwdump' or v['ltype'] == 'windows.hashes':
                loot_list.append([k, v['host']])
                loot_hosts.setdefault(v['host'], k)

        form=SQLFORM.factory(
            Field('hosts', 'list', requires=IS_IN_SET(loot_list, multiple=True), label=T('Host')),
            Field('host_text', 'text', label=T('Host list (1 per line)')),
            Field('addevidence', 'boolean', label=T('Add to Evidence')),
        )

        if form.accepts(request, session):
            from skaldship.metasploit import process_pwdump_loot
            data = []
            # based on which form data is entered, make a new loot_list
            if len(form.vars.hosts) > 0:
                loot_list = form.vars.hosts
            elif len(form.vars.host_text) > 0:
                for ip in form.vars.host_text.split('\n'):
                    try:
                        loot_list.append(loot_hosts[ip])
                    except:
                        logging.debug("%s not found in MSF loot list" % (ip))
                        continue

            retval = process_pwdump_loot(loot_list, msf)
            response.flash = "PWDUMP files imported\n%s" % (retval)
        elif form.errors:
            response.flash = "Errors in your form"
    else:
        form = None

    return dict(form=form, alert=alert, error=str(error))

@auth.requires_login()
def import_screenshots():
    """
    Import Screenshot files from Metasploit Pro into Kvasir
    """
    response.title = "%s :: Import Metasploit Screenshots" % (settings.title)
    workspace = session.msf_workspace
    loot_apidata={}

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(form=None, error=str(error), alert=True)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
        loot_apidata = msf.loot_list(workspace)
    except MSFAPIError, error:
        return dict(form=None, error=str(error), alert=True)

    loot_list = []
    loot_dict = {}
    loot_hosts = {}
    for k,v in loot_apidata.iteritems():
        if v['ltype'] == 'host.windows.screenshot':
            loot_list.append([k, v['host']])
            loot_dict.setdefault(k, v['host'])
            loot_hosts.setdefault(v['host'], k)

    form=SQLFORM.factory(
        Field('host', 'list', requires=IS_IN_SET(loot_list, multiple=True), label=T('Host')),
        Field('host_text', 'text', label=T('Host list (1 per line)')),
    )

    if form.accepts(request, session):
        loots = []
        # based on which form data is entered, make a new loot_list
        if form.vars.hosts:
            loot_list = form.vars.hosts
        elif form.vars.host_text:
            for ip in form.vars.host_text.split('\n'):
                try:
                    loot_list.append(loot_hosts[ip])
                except:
                    logging.debug("%s not found in MSF loot list" % (ip))
                    continue

        loot_count = process_screenshot_loot(loot_list, msf)
        repsonse.flash = 'Screenshots added for %s host(s)' % (loot_count)

    elif form.errors:
        response.flash = "Errors in your form"

    return dict(form=form, alert=False, error=None)

@auth.requires_login()
def list_lootfiles():
    """
    Lists local loot files for import processing into Kvasir. This does not
    use the Metasploit API and depends upon a directory being local to the
    web2py server instance. The API is used to check if pro is installed
    and sets the loot_dir to Linux or Windows path
    """
    import os
    import re
    response.title = "%s :: Metasploit Loots" % (settings.title)

    dbsvcs = db.t_services
    # TODO: from skaldship.db import get_services
    from skaldship.general import get_host_record
    loot_dir = request.args(0)

    if not loot_dir:
        try:
            from MetasploitAPI import MetasploitAPI, MSFAPIError
            msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
            if msf.pro_about():
                if platform in ["linux", "linux2"]:
                    loot_dir = "/opt/metasploit_pro/apps/pro/loot"
                else:
                    loot_dir = "C:\\Metasploit\\apps\\pro\\loot"
        except ImportError, error:
            pass

    if not loot_dir:
        from sys import platform
        if platform in ["linux", "linux2", "darwin", "freebsd"]:
            loot_dir = os.path.join(os.environ.get('HOME'), '.msf4/loot')
        elif platform in ["win32", "cygwin"]:
            loot_dir = '$FINDYOUR/msf4/loot/path'

    try:
        os.chdir(loot_dir)
        loot_files = os.listdir(loot_dir)
    except OSError:
        loot_files = []

    loot_file_details = []
    for loot in loot_files:
        try:
            (timestamp, workspace, ipaddr, filetype, extension) = re.split('_', loot)
        except ValueError:
            logging.warn("Invalid loot file: %s" % (loot))
            continue

        # TODO: service_list = get_services(ipaddr)
        host_rec = get_host_record(ipaddr)
        services = []
        for service in db(dbsvcs.f_hosts_id==host_rec).select(dbsvcs.id, dbsvcs.f_proto, dbsvcs.f_number, cache=(cache.ram, 120)):
            services.append([service.id, "%s/%s" % (service.f_proto, service.f_number)])
        loot_file_details.append([
            workspace, ipaddr, services, filetype
        ])

    form_lootdir = SQLFORM.factory(
        Field('lootdir', 'string', default=loot_dir, requires=IS_NOT_EMPTY(), label=T('Metasploit Loot Directory')),
    )

    return dict(form_lootdir=form_lootdir, loot_file_details=loot_file_details)

##-------------------------------------------------------------------------
## report
##-------------------------------------------------------------------------

@auth.requires_login()
def import_report():
    """
    Import a MSF Pro XML Report.

    TODO: FINISH HIM!
    """

    workspace = session.msf_workspace
    if workspace is None:
        redirect(URL('api_settings'))

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    if not msf.login():
        response.flash = "Error logging into Metasploit, check your settings"
        redirect(URL('api_settings'))

    form = SQLFORM.factory(
        Field('whitelist', 'text', label=T('Whitelist hosts/nets')),
        Field('blacklist', 'text', label=T('Blacklist hosts/nets')),
    )

    if form.accepts(request, sesssion):
        # build the configuration hash
        rpt_data = {}
        rpt_data['DS_REPORT_TYPE'] = 'XML'
        rpt_data['DS_WHITELIST_HOSTS'] = form.vars.whitelist
        rpt_data['DS_BLACKLIST_HOSTS'] = form.vars.blacklist
        rpt_data['Workdspace'] = session.msf_workspace

        # send the report request and get the task id
        rpt_taskid = msf.pro_start_report(rpt_data)

        # check the task status


        # download the report data

@auth.requires_login()
def import_report_xml():
    """
    Upload/import Metasploit XML export file
    """
    import time
    import os
    from skaldship.general import check_datadir

    response.title = "%s :: Import Metasploit Pro Report XML" % (settings.title)
    filedir = os.path.join(request.folder,'data','scanfiles')
    fields = []
    alert = False
    error = None

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('Metasploit XML File')))

    # check to see if we have a Metasploit Pro instance configured and talking
    # if so pull a list of the workspaces and present them
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
        msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    except ImportError, error:
        msf = None

    if msf:
        try:
            msf_reports_res = msf.report_list(workspace=session.msf_workspace)
        except MSFAPIError, error:
            msf_reports_res = None

    if msf_reports_res:
        from datetime import datetime
        msf_reports = []
        for rpt in msf_reports_res.keys():
            report_name = "Generated: %s" % (datetime.strftime(datetime.fromtimestamp(msf_reports_res[rpt]['created_at']), "%m-%d-%y %H:%M:%S"))
            msf_reports.append([rpt, report_name])
        fields.append(Field('f_msf_report', type='string', label=T('MSF Pro Report'), requires=IS_EMPTY_OR(IS_IN_SET(msf_reports, zero=None))))

    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group for new Hosts'), default="Metasploit Import", requires=IS_NOT_EMPTY()))
    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_update_hosts', type='boolean', default=True, label=T('Update Existing Hosts')))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='metasploit_xml')

    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # build the hosts only/exclude list
        ip_exclude = []
        data = form.vars.get('f_ignore_list')
        if data:
            ip_exclude = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals
        ip_include = []
        data = form.vars.get('f_include_list')
        if data:
            ip_include = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals

        if form.vars.f_msf_report:
            try:
                msf_report = msf.report_download(rptid=form.vars.f_msf_report)
            except MSFAPIError, error:
                error = "Unable to download report from Metasploit Pro: %s" % (str(error))
                return dict(form=form, alert=True, error=error)
            check_datadir(request.folder)
            filename =  os.path.join(filedir, "msfpro-%s-%s.xml" % (session.msf_workspace, int(time.time())))
            fout = open(filename, "w")
            fout.write(msf_report['data'])
            fout.close()
            del(msf_report)
        else:
            filename = form.vars.f_filename
            filename = os.path.join(filedir, form.vars.f_filename)

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='metasploit',
                    filename=filename,
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
                    update_hosts=form.vars.f_update_hosts,
                    auth_user=auth.user,
                ),
                group_name=settings.scheduler_group_name,
                sync_output=5,
                timeout=3600   # 1 hour
            )
            if task.id:
                redirect(URL('tasks', 'status', args=task.id))
            else:
                response.flash = "Error submitting job: %s" % (task.errors)
        else:
            from skaldship.metasploit import process_report_xml
            logger.info("Starting Metasploit XML Import")
            result = process_report_xml(
                filename=filename,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
                auth_user=auth.user,
            )
            response.flash = result

    return dict(form=form, alert=alert, error=error)


##-------------------------------------------------------------------------
## sending data to metasploit
##-------------------------------------------------------------------------

@auth.requires_login()
def send_scanxml():
    """Sends scan XML output file to MSF Pro for importing"""
    import os

    response.title = "%s :: Send Scan XML Data to Metasploit" % (settings.title)
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, form=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, form=None)

    filedir = os.path.join(request.folder,'data','scanfiles')
    try:
        scanfiles = os.listdir(filedir)
    except OSError:
        scanfiles = []
    file_select = []
    count = 0
    for fn in scanfiles:
        file_select.append([count, fn])
        count += 1

    form = SQLFORM.factory(
        Field('fname', 'string', requires=IS_IN_SET(file_select), label=T('Scan File')),
        Field('blacklist', 'text', label=T('Blacklisted hosts'),
            comment=T('Targets to blacklist can be IP Addresses, ranged lists or subnets. One per line.')
        ),
        Field('preserve_hosts', 'boolean', default=False, label=T('Preserve existing hosts')),
    )

    if form.accepts(request, session):
        fname = file_select[int(form.vars.fname)][1]
        fname = os.path.join(filedir, fname)

        try:
            scan_data = open(fname, "r+").readlines()
        except Exception, error:
            return dict(form=form, error=str(error), alert=True)

        task = msf.pro_import_data(
                msf_workspace,
                "".join(scan_data),
                {
                  'preserve_hosts': form.vars.preserve_hosts,
                  'blacklist_hosts': "\n".join(form.vars.blacklist)
                },
            )

        """
        # documented in API but not valid yet @9/6/13
        #validate = msf.pro_validate_import_file(fname)
        task = msf.pro_start_import({
                  'workspace': msf_workspace,
                  'username': session.msf_user,
                  'DS_PATH': fname,
                  'DS_PRESERVE_HOSTS': form.vars.preserve_hosts,
                  'DS_BLACKLIST_HOSTS': "\n".join(form.vars.blacklist),
                  'DS_REMOVE_FILE': False,
                  'DS_ImportTags': True,
                })
        """
        msfurl = os.path.join(auth.user.f_msf_pro_url, 'workspaces', session.msf_workspace_num, 'tasks', task['task_id'])
        redirect(msfurl)
    elif form.errors:
        response.flash = "Errors in your form"

    return dict(form=form, alert=False, error=None)

@auth.requires_login()
def send_accounts():
    """Builds a list of username:passwords and sends it to Metasploit"""
    response.title = "%s :: Send Kvasir Passwords to Metasploit Pro" % (settings.title)
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, form=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, form=None)

    form = SQLFORM.factory(
        Field('userpass', 'boolean', default=True, label=T('User/Pass Combos')),
        Field('pwdump', 'boolean', default=True, label=T('PWDUMP Hashes')),
    )

    if form.accepts(request, session):
        pass
    elif form.errors:
        reseponse.flash = "Error in your form"
        return dict(form=form, alert=False, error=None)
    else:
        return dict(form=form, alert=False, error=None)

    """
    First build a list of username:passwords from the t_accounts database and
    make a temporary file, then start_import_creds the file

    Second build a pwdump list for LM/NT hashes, make a temporary file, then
    start_import_creds that file!

    Requires MSFPRO and Kvasir be on the same workstation.
    """
    tasks = {}
    import tempfile
    if form.vars.userpass:
        # build username:password file
        rows = db(db.t_accounts.f_compromised == True).select(db.t_accounts.f_username, db.t_accounts.f_password, cache=(cache.ram, 60))
        if rows is not None:
            tmpfile = tempfile.NamedTemporaryFile(delete=False)
            fname = tmpfile.name
            for row in rows:
                tmpfile.write("%s %s\n" % (row.f_username, row.f_password))
            tmpfile.close()
            opts = {
                'workspace': msf_workspace,
                'DS_FTYPE': 'userpass',
                'DS_IMPORT_PATH': fname,
                'DS_NAME': 'Kvasir import %s' % (fname),
                'DS_DESC': 'Kvasir import',
                'DS_REMOVE_FILE': True,
            }
            task = msf.pro_start_import_creds(opts)
            redirect(URL('task_log', args=task.get('id')))
        else:
            response.flash = "No user:pass combos to import"

    if form.vars.pwdump:
        # build pwdump file
        rows = db(db.t_accounts.f_hash1_type == "LM").select(
            db.t_accounts.f_username,
            db.t_accounts.f_uid,
            db.t_accounts.f_hash1,
            db.t_accounts.f_hash2,
            cache=(cache.ram, 60)
        )
        if rows is not None:
            tmpfile = tempfile.NamedTemporaryFile(delete=False)
            fname = tmpfile.name
            for row in rows:
                tmpfile.write("%s:%s:%s:%s:::\n" % (row.f_username, row.f_uid, row.f_hash1, row.f_hash2))

            tmpfile.close()
            opts = {
                'workspace': msf_workspace,
                'DS_FTYPE': 'pwdump',
                'DS_IMPORT_PATH': fname,
                'DS_NAME': 'Kvasir pwdump import %s' % (fname),
                'DS_DESC': 'Kvasir pwdump import',
                'DS_REMOVE_FILE': True,
            }
            task = msf.pro_start_import_creds(opts)
            redirect(URL('task_log', args=task.get('id')))
        else:
            response.flash = "No pwdump hashes to import"

    return dict(form=form, alert=False, error=None)

##-------------------------------------------------------------------------
## task monitoring / killing
##-------------------------------------------------------------------------

@auth.requires_login()
def task_list():
    """Obtains a list of tasks"""
    response.title = "%s :: Metasploit Task List" % (settings.title)
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, tasks=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, tasks=None)

    tasks = msf.task_list()
    tasklist = []
    if request.vars.has_key('status'):
        # only return specific tasks as defined in status
        for taskid,task in tasks.iteritems():
            if task['status'] == request.vars.status.lower():
                tasklist.append({taskid: task})
    else:
        tasklist = tasks

    return dict(tasks=tasklist)

@auth.requires_login()
def task_status():
    """Show details of a specifc task (but not the log file)"""
    response.title = "%s :: Metasploit Task Status" % (settings.title)
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, data=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, data=None)

    if not request.vars.has_key('taskid'):
        tasks = msf.task_list()
        task_list = []
        for taskid,task in tasks.iteritems():
            task_list.append(
                [taskid, "%s (%s) :: %s :: %s" % (
                    taskid,
                    tasks[taskid]['status'],
                    tasks[taskid]['description'],
                    tasks[taskid]['info'],
               )])
        form = SQLFORM.factory(
            Field('taskid', 'string', requires=IS_IN_SET(task_list), label=T('Task ID'))
        )
        return dict(form=form)

    data = msf.task_status(request.vars.taskid)
    return dict(data=data)

@auth.requires_login()
def task_log():
    """Show the details and log file of a specifc task"""
    response.title = "%s :: Metasploit Task Log" % (settings.title)
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, data=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, data=None)

    if not request.vars.has_key('taskid'):
        tasks = msf.task_list()
        task_list = []
        for taskid,task in tasks.iteritems():
            task_list.append(
                [taskid, "%s (%s) :: %s :: %s" % (
                    taskid,
                    tasks[taskid]['status'],
                    tasks[taskid]['description'],
                    tasks[taskid]['info'],
               )])
        form = SQLFORM.factory(
            Field('taskid', 'string', requires=IS_IN_SET(task_list), label=T('Task ID'))
        )
        return dict(form=form)

    data = msf.task_log(request.vars.taskid)
    return dict(data=data)

@auth.requires_login()
def task_stop():
    """Stop a running task"""
    msf_workspace = session.msf_workspace
    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, form=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, form=None)

    if not request.vars.has_key('taskid'):
        tasks = msf.task_list()
        task_list = []
        for taskid,task in tasks.iteritems():
            if tasks[taskid]['status'] == 'running':
                task_list.append(
                    [taskid, "%s (%s) :: %s :: %s" % (
                        taskid,
                        tasks[taskid]['status'],
                        tasks[taskid]['description'],
                        tasks[taskid]['info'],
                   )])
        form = SQLFORM.factory(
            Field('taskid', 'string', requires=IS_IN_SET(task_list), label=T('Task ID'))
        )
        return dict(form=form)

    response.title = "%s :: Stop Metasploit Task" % (settings.title)
    data = msf.task_stop(request.vars.taskid)
    return dict(data=data)

##-------------------------------------------------------------------------
## Targeted exploit
##-------------------------------------------------------------------------

@auth.requires_login()
def exploit_host():
    """
    Build an exploit for a specific target
    """

    try:
        from MetasploitAPI import MetasploitAPI, MSFAPIError
    except ImportError, error:
        return dict(error=str(error), alert=True, form=None)

    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        msf.login()
    except MSFAPIError, error:
        return dict(error=str(error), alert=True, form=None)

    target = request.vars.f_target or None
    exploit = request.vars.f_exploit or None

    form = SQLFORM.factory()
