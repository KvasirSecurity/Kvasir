# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Nessus controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

from skaldship.metasploit import msf_get_config
from skaldship.nessus import nessus_get_config
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

@auth.requires_login()
def import_scan():
    """
    Upload and import Nessus Scan file
    """
    msf_settings = msf_get_config(session)
    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitProAPI import MetasploitProAPI
        msf_api = MetasploitProAPI(host=msf_settings['url'], apikey=msf_settings['key'])
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
        userlist.append([user.id, user.username])

    nessus_config = nessus_get_config()
    # {'ignored_vulnids': [19506, 11219, 34277],
    #  'servers': {'server_1': {'password': 'password',
    #                           'url': 'https://localhost:8834/',
    #                           'user': 'admin'}}}
    nessusreports = [[0, None]]
    import NessusAPI
    #if auth.user.f_nessus_host is not None:
    servers = nessus_config.get('servers', {})
    for k, v in servers.iteritems():
        try:
            # check to see if NessusAPI is working
            nessus = NessusAPI.NessusConnection(v.get('user'), v.get('password'), url=v.get('url'))
            reports = nessus.list_reports()
            for report in reports:
                ts = time.ctime(float(report.timestamp))
                nessusreports.append(["%s:%s" % (k, report.name), "%s: %s - %s (%s)" % (k, report.readablename, ts, report.status)])
        except Exception, e:
            logger.error("Error communicating with %s: %s" % (k, str(e)))

    if len(nessusreports) > 1:
        fields.append(Field('f_nessus_report', type='integer', label=T('Nessus Report'), requires=IS_IN_SET(nessusreports, zero=None)))

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('Nessus Scan File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))

    # check to see if we have a Metasploit Pro instance configured and talking
    # if so pull a list of the workspaces and present them
    if working_msf_api:
        msf_workspaces = ["None"]
        for w in msf_api.pro_workspaces().keys():
            msf_workspaces.append(w)
        fields.append(Field('f_msf_workspace', type='string', label=T('MSF Pro Workspace'), requires=IS_EMPTY_OR(IS_IN_SET(msf_workspaces, zero=None))))

    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_update_hosts', type='boolean', label=T('Update Host Information'), default=False))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='nessus_scan')

    # form processing
    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # if no Nessus servers configured or valid, set report_name to 0
        if nessusreports == [[0, None]]:
            report_name = '0'
        else:
            if form.vars.f_nessus_report != "0":
                # If a nessus report is selected, try to parse it to set report_name
                try:
                    (server, report_name) = form.vars.f_nessus_report.split(':')
                except ValueError, e:
                    msg = "Invalid report name sent: %s" % (form.vars.f_nessus_report)
                    response.flash = msg
                    logging.error(msg)
                    return dict(form=form)
            else:
                # set report_name to 0 if no f_nessus_report sent
                report_name = '0'

        if report_name != '0':
            # download a report from a Nessus server
            filename = os.path.join(filedir, "nessus-%s-%s.xml" % (form.vars.f_asset_group, int(time.time())))
            check_datadir(request.folder)
            fout = open(filename, "w")
            try:
                # build a new nessus connection with the configured server details and download the report
                n_server = nessus_config.get('servers').get(server)
                nessus = NessusAPI.NessusConnection(n_server.get('user'), n_server.get('password'), url=n_server.get('url'))
                nessus.download_report(report_name, fout)
                fout.close()
            except Exception, e:
                msg = ("Error download Nessus report: %s" % (e))
                logger.error(msg)
                response.flash = msg
                return dict(form=form)
        else:
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
                    scanner='nessus',
                    filename=filename,
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
            from skaldship.nessus.processor import process_scanfile
            logger.info("Starting Nessus Report Import")
            response.flash = process_scanfile(
                filename=filename,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_settings=msf_settings,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            redirect(URL('default', 'index'))

    return dict(form=form)
