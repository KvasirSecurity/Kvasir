# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Nmap controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
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
    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitAPI import MetasploitAPI
        msf_api = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
        working_msf_api = msf_api.login()
    except:
        working_msf_api = False

    filedir = os.path.join(request.folder,'data','scanfiles')
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
        filename = form.vars.f_filename
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
            if msf_workspace == "None": msf_workspace = None
        else:
            msf_workspace = None

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='nmap',
                    filename=filename,
                    addnoports=form.vars.f_addnoports,
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    msf_workspace=msf_workspace,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
                    update_hosts=form.vars.f_update_hosts,
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
            from skaldship.nmap import process_xml
            print("Starting Nmap XML Import")
            process_xml(
                filename=filename,
                addnoports=form.vars.f_addnoports,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_workspace=form.vars.f_msf_workspace,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            response.flash = "Nmap XML upload complete"
            redirect(URL('default', 'index'))

    return dict(form=form)
