# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Nessus controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

@auth.requires_login()
def list_reports():
    import NessusAPI
    nessus = NessusAPI.NessusConnection(auth.user.f_nessus_user, auth.user.f_nessus_pw, url=auth.user.f_nessus_host)
    try:
        reports = nessus.list_reports()
        error = None
    except Exception, e:
        error = "Error listing reports: %s" % (str(e))
        reports = None

    return dict(reports=reports, error=error)

@auth.requires_login()
def import_xml_scan():
    """
    Upload/import Nexpose XML Scan file via scheduler task
    """
    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitAPI import MetasploitAPI
        msf_api = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
        working_msf_api = msf_api.login()
    except:
        working_msf_api = False

    from skaldship.general import check_datadir
    import time
    import os

    filedir = os.path.join(request.folder, 'data', 'scanfiles')
    response.title = "%s :: Import Nessus Scan Results" % (settings.title)
    fields = []

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    nessusreports = []
    if auth.user.f_nessus_host is not None:
        try:
            # check to see if NessusAPI is working
            import NessusAPI
            n = NessusAPI.NessusConnection(auth.user.f_nessus_user, auth.user.f_nessus_pw, url=auth.user.f_nessus_host)
            reports = n.list_reports()
        except Exception, e:
            logger.error("Error communicating with Nessus: %s" % str(e))

        for report in reports:
            nessusreports.append( [ report.name, report.readableName ])

        if nessusreports:
            fields.append(Field('f_nexpose_site', type='integer', label=T('Nessus Report'), requires=IS_IN_SET(nessusreports, zero=None)))

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('Nessus XML File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))

    # check to see if we have a Metasploit Pro instance configured and talking
    # if so pull a list of the workspaces and present them
    msf = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
    try:
        res = msf.login()
    except:
        res = False

    if res:
        msf_workspaces = []
        msf_workspaces.append( "None" )
        for w in msf.pro_workspaces().keys():
            msf_workspaces.append(w)
        fields.append(Field('f_msf_workspace', type='string', label=T('MSF Pro Workspace'), requires=IS_EMPTY_OR(IS_IN_SET(msf_workspaces, zero=None))))

    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_update_hosts', type='boolean', label=T('Update Host Information'), default=False))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='nessus_xml')

    # form processing
    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        """
        if not nxsitelist:
            nexpose_site = '0'
        else:
            nexpose_site = form.vars.f_nexpose_site

        if nexpose_site != '0':
            report = Report()
            report.host = auth.user.f_nexpose_host
            report.port = auth.user.f_nexpose_port
            nx_loggedin = report.login(user_id=auth.user.f_nexpose_user, password=auth.user.f_nexpose_pw)
            if nx_loggedin:
                # have nexpose generate the adhoc report
                check_datadir(request.folder)
                filename =  os.path.join(filedir, "%s-%s.xml" % (form.vars.f_asset_group, int(time.time())))
                fout = open(filename, "w")
                fout.write(report.adhoc_generate(filterid=nexpose_site))
                fout.close()
            else:
                response.flash = "Unable to login to Nexpose"
                return dict(form=form)
        else:
        """
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
                    scanner='nessus',
                    filename=filename,
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
            from skaldship.nessus import process_xml
            logger.info("Starting Nessus Report Import")
            process_xml(
                filename=filename,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_workspace=msf_workspace,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            redirect(URL('default', 'index'))

    return dict(form=form)
