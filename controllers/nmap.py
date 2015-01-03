# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Nmap controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------


@auth.requires_login()
def list_scripts():
    """
    Lists nmap scripts
    """
    from skaldship.nmap import script_metadata
    scr = script_metadata()
    return dict(scripts=scr)

##-------------------------------------------------------------------------


@auth.requires_login()
def import_xml_scan():
    """
    Upload/import Nmap XML Scan file via scheduler task
    """
    import time
    from skaldship.general import check_datadir
    from skaldship.metasploit import msf_get_config
    msf_settings = msf_get_config(session)

    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitProAPI import MetasploitProAPI
        msf_api = MetasploitProAPI(host=msf_settings['url'], apikey=msf_settings['key'])
        working_msf_api = msf_api.login()
    except:
        working_msf_api = False

    filedir = os.path.join(request.folder,'data','scanfiles')
    check_datadir(request.folder)
    response.title = "%s :: Import Nmap XML Scan Results" % (settings.title)

    fields = []

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('Nmap XML File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))

    # If Metasploit available, pull a list of the workspaces and present them
    if working_msf_api:
        msf_workspaces = []
        msf_workspaces.append( "None" )
        for w in msf_api.pro_workspaces().keys():
            msf_workspaces.append(w)
        fields.append(Field('f_msf_workspace', type='string', label=T('MSF Pro Workspace'), requires=IS_EMPTY_OR(IS_IN_SET(msf_workspaces, zero=None))))

    fields.append(Field('f_addnoports', type='boolean', label=T('Add Hosts w/o Ports'), default=False))
    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_update_hosts', type='boolean', label=T('Update Host Information'), default=False))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='nmap_xml')

    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # process a nmap file
        filename = os.path.join(filedir, form.vars.f_filename)

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

        if form.vars.f_msf_workspace:
            msf_workspace = form.vars.f_msf_workspace
            if msf_workspace == "None":
                msf_workspace = None
        else:
            msf_workspace = None
        msf_settings = {'workspace': msf_workspace, 'url': msf_settings['url'], 'key': msf_settings['key']}

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='nmap',
                    filename=filename,
                    addnoports=form.vars.f_addnoports,
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    msf_settings=msf_settings,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
                    update_hosts=form.vars.f_update_hosts,
                ),
                group_name=settings.scheduler_group_name,
                sync_output=5,
                timeout=settings.scheduler_timeout
            )
            if task.id:
                redirect(URL('tasks', 'status', args=task.id))
            else:
                response.flash = "Error submitting job: %s" % (task.errors)
        else:
            from skaldship.nmap import process_xml
            print("Starting Nmap XML Import")
            process_xml(
                filename=filename,
                addnoports=form.vars.f_addnoports,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_settings=msf_settings,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            response.flash = "Nmap XML upload complete"
            redirect(URL('default', 'index'))

    return dict(form=form)

##-------------------------------------------------------------------------


@auth.requires_login()
def nmap_scan():
    """
    Run nmap scan and hand file over to parser
    """
    from skaldship.general import check_datadir
    import time
    import os

    response.title = "%s :: Run Nmap Scan" % (settings.title)

    scan_profiles = {
        'Ping Scan': ["-sn"],
        'Intense Scan': ["-T4", "-A", "-v"],
        'Intense Scan (All TCP Ports)': ["-p", "1-65535", "-T4", "-A", "-v"],
        'Intense Scan (No Ping)': ["-T4", "-A", "-v", "-Pn"],
        'Quick Scan': ["-T4", "-F"],
        'Quick Scan Plus': ["-sV", "-T4", "-O", "-F", "--version-light"],
        'Slow Comprehensive Scan': ["-sS", "-sU", "-T4", "-A", "-v", "-PE", "-PP", "-PS80,443", "-PA3389", "-PU40125", "-PY", "-g 53", "--script", "default"]
    }

    fields = []
    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))
    fields.append(Field('f_scan_profile', label=T('Scan Profile'),
                        requires=IS_EMPTY_OR(IS_IN_SET(sorted(scan_profiles.keys()), zero=None))))
    fields.append(Field('f_scan_options', type='string', label=T('Scan Options')))
    fields.append(Field('f_target_list', type='text', label=T('Scan Targets')))
    fields.append(Field('f_blacklist', type='text', label=T('Blacklist')))
    fields.append(Field('f_addnoports', type='boolean', label=T('Add Hosts w/o Ports'), default=False))
    fields.append(Field('f_update_hosts', type='boolean', label=T('Update Host Information'), default=False))

    form = SQLFORM.factory(*fields, table_name='nmap_scan')

    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # process a nmap scan
        # build the hosts only/exclude list
        ip_blacklist = []
        data = form.vars.get('f_blacklist')
        if data:
            ip_blacklist = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals
        ip_targets = []
        data = form.vars.get('f_target_list')
        if data:
            ip_targets = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals

        if form.vars.f_scan_options:
            scan_options = form.vars.f_scan_options.split(' ')
        else:
            scan_options = scan_profiles[form.vars.f_scan_profile]

        check_datadir(request.folder)
        filename = "nmap-%s-%s.xml" % (form.vars.f_asset_group, int(time.time()))
        filedir = os.path.join(request.folder, 'data', 'scanfiles', filename)
        scan_options.extend(['--stats-every', '5s', '-oX', filedir])

        task = scheduler.queue_task(
            run_scanner,
            pvars=dict(
                scanner='nmap',
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                target_list=ip_targets,
                blacklist=ip_blacklist,
                scan_options=scan_options,
                addnoports=form.vars.f_addnoports,
                update_hosts=form.vars.f_update_hosts,
            ),
            group_name=settings.scheduler_group_name,
            sync_output=5,
            timeout=settings.scheduler_timeout
        )

        if task.id:
            redirect(URL('tasks', 'status', args=task.id))
        else:
            response.flash = "Error submitting job: %s" % (task.errors)

    return dict(form=form)
