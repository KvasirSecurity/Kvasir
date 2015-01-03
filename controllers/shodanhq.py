# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Metasploit controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

#from skaldship.general import get_oreally_404, host_title_maker


@auth.requires_login()
def download():
    return response.download(request, db)

@auth.requires_login()
def call():
    session.forget()
    return service()
### end requires

@auth.requires_login()
def index():
    return dict()

@auth.requires_login()
def import_report():
    """
    Upload/import ShodanHQ XML export file
    """
    import os

    #try:
    #    from shodan import WebAPI
    #    from shodan.api import WebAPIError
    #    webapi = WebAPI(settings.kvasir_config.get('shodanhq_api_key', '')
    #except ImportError:
    #    webapi = None

    filedir = os.path.join(request.folder, 'data', 'scanfiles')
    response.title = "%s :: Import ShodanHQ Data" % (settings.title)
    fields = []

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append([user.id, user.username])

    #if webapi:
    #    fields.append(Field('f_query', 'string', label=A('ShodanHQ Query', _href="http://www.shodanhq.com/help/filters", _target="blank", _rel="noreferrer")))
    #    fields.append(Field('f_max_responses', 'integer', default=1000, label=T('Limit of searches'), requires=IS_INT_IN_RANGE(1, 1000001),
    #        comment="Maximum number of responses, in 100s up to 1,000,000"))
    #    fields.append(Field('f_hosts', 'text', label=T('IP Addresses')))

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('ShodanHQ XML File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group for new Hosts'), default="ShodanHQ Import", requires=IS_NOT_EMPTY()))
    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='shodanhq')

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

        filename = form.vars.f_filename
        if filename:
            filename = os.path.join(filedir, form.vars.f_filename)
        else:
            filename = None
        hosts = form.vars.get('f_hosts')
        max_responses = form.vars.get('f_max_responses')
        query = form.vars.get('f_query')

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='shodanhq',
                    filename=filename,
                    host_list=hosts,
                    query=[query, max_responses],
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
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
            from skaldship.shodanhq import process_report
            result = process_report(
                filename=filename,
                host_list=hosts,
                query=[query, max_responses],
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
            )
            response.flash = result

    return dict(form=form)
