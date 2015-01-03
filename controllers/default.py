# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Default controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

from skaldship.general import get_oreally_404
from skaldship.hosts import host_title_maker
from skaldship.statistics import db_statistics, adv_db_statistics, graphs_index
crud.settings.formstyle = formstyle_bootstrap_kvasir

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

import logging
logger = logging.getLogger("web2py.app.kvasir")

### required - do no delete
def user():
    response.title = T('Kvasir Login')
    return dict(form=auth())

@auth.requires_login()
def download(): return response.download(request,db)

@auth.requires_login()
def call():
    session.forget()
    return service()
### end requires

@auth.requires_login()
def index():
    """
    Kvasir welcoming index page.
    """
    response.files.append(URL(request.application, 'static', 'js/jquery.tagcloud-2.js'))
    response.files.append(URL(request.application, 'static', 'js/highcharts.js'))

    statistics = db_statistics()
    adv_stats = adv_db_statistics()
    graphs = graphs_index()
    return dict(statistics=statistics, adv_stats=adv_stats, graphs=graphs)

def error():
    response.title = "%s :: Error!" % (settings.title)
    return dict(
        err404=get_oreally_404(request.folder),
        msg=request.vars.msg
    )

@auth.requires_login()
def purge_data():
    # Purges all the data except user tables
    response.title = "%s :: Database Purge" % (settings.title)

    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    hosts = db(db.t_hosts).select()
    hostlist = []
    for host in hosts:
        hostlist.append( [ host.id, host_title_maker(host) ] )

    ag_rows = db(db.t_hosts).select(db.t_hosts.f_asset_group, distinct=True).as_list()
    asset_groups = []
    for ag in ag_rows:
        asset_groups.append(ag['f_asset_group'])

    form = SQLFORM.factory(
        Field('host', type='list:integer', label=T('Delete a host'), requires=IS_EMPTY_OR(IS_IN_SET(hostlist))),
        Field('engineer', type='list:integer', label=T('Hosts by user'), requires=IS_EMPTY_OR(IS_IN_SET(userlist))),
        Field('asset_group', type='string', label=T('Asset Group'), requires=IS_EMPTY_OR(IS_IN_SET(asset_groups))),
        Field('all_data', type='boolean', label=T('Truncate all tables')),
        Field('are_you_sure', type='boolean', label=T('Are you sure?'), requires=IS_NOT_EMPTY(error_message='ARE YOU SURE?!?!')),
        )

    if form.accepts(request.vars, session):
        if not form.vars.are_you_sure:
            form.errors.are_you_sure = 'ARE YOU SURE?'
        else:
            if form.vars.all_data:
                db.t_hosts.truncate(mode="CASCADE")
                db.t_services.truncate(mode="CASCADE")
                db.t_os.truncate(mode="CASCADE")
                db.t_host_os_refs.truncate(mode="CASCADE")
                db.t_apps.truncate(mode="CASCADE")
                db.t_services_apps_refs.truncate(mode="CASCADE")
                db.t_service_vulns.truncate(mode="CASCADE")
                db.t_service_info.truncate(mode="CASCADE")
                db.t_accounts.truncate(mode="CASCADE")
                db.t_host_notes.truncate(mode="CASCADE")
                db.t_evidence.truncate(mode="CASCADE")
                db.t_snmp.truncate(mode="CASCADE")
                db.commit()
                response.flash = 'All data purged'
            elif form.vars.host:
                host_id = form.vars.host
                del db.t_hosts[host_id]
                response.flash = "Host %s purged" % (form.vars.host)
            elif form.vars.engineer:
                # TODO: Test this
                delcnt = db(db.t_hosts.f_engineer == form.vars.engineer).delete()
                db.commit()
                response.flash = "Hosts owned by %s purged (%d records)" % (form.vars.engineer, delcnt)
            elif form.vars.asset_group:
                delcnt = db(db.t_hosts.f_asset_group == form.vars.asset_group).delete()
                db.commit()
                response.flash = "Asset group %s purged (%d records)" % (form.vars.asset_group, delcnt)
    elif form.errors:
        response.flash = 'Error in form'

    return dict(
        form=form,
        err404=get_oreally_404(request.folder),
    )

@auth.requires_login()
def update_dynamic_fields():
    """
    Executes the following functions that update dynamic field entries:

       skaldship.hosts.do_host_status
       skaldship.exploits.connect_exploits
    """
    response.title = "%s :: Update Dynamic Fields" % (settings.title)

    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    ag = db(db.t_hosts).select(db.t_hosts.f_asset_group, distinct=True).as_list()
    asset_groups = map((lambda x: x['f_asset_group']), ag)

    form = SQLFORM.factory(
        Field('f_exploit_link', type='boolean', default=True, label=T('Exploit linking')),
        Field('f_host_status', type='boolean', default=True, label=T('Host Service/Vuln counts')),
        Field('f_asset_group', type='list:string', label=T('Asset Group'), requires=IS_EMPTY_OR(IS_IN_SET(asset_groups, multiple=False))),
        Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')),
    )

    from skaldship.hosts import do_host_status
    from skaldship.exploits import connect_exploits
    if form.accepts(request.vars, session):
        if form.vars.f_exploit_link:
            connect_exploits()
        if form.vars.f_host_status:
            if form.vars.f_taskit:
                task = scheduler.queue_task(
                    do_host_status,
                    pvars=dict(asset_group=form.vars.f_asset_group),
                    group_name=settings.scheduler_group_name,
                    sync_output=5,
                    timeout=settings.scheduler_timeout,
                )
                if task.id:
                    redirect(URL('tasks', 'status', args=task.id))
                else:
                    resp_text = "Error submitting job: %s" % (task.errors)
            else:
                do_host_status(asset_group=form.vars.f_asset_group)
        response.flash = "Task completed!"

    elif form.errors:
        response.flash = 'Error in form'

    return dict(
        form=form,
        err404=get_oreally_404(request.folder),
    )

@auth.requires_login()
def database_backup():
    """
    Export/backup database in CSV format
    """
    response.title = "%s :: Database CSV Backup" % (settings.title)
    import os
    import gzip
    from datetime import datetime

    backup_dir = os.path.join(request.folder, 'data/backups')
    form = SQLFORM.factory(
        Field('download', type='boolean', default=True, label=T('Download')),
        Field('gzip', type='boolean', default=True, label=T('GZip Compress')),
    )

    if form.process().accepted:
        fname = "kvasir-%s-%s-%s" % (settings.customer, settings.assesment_type, datetime.now().strftime("%m%d%y-%H%M%S"))
        fname= "".join([x if x.isalnum() else "_" for x in fname])
        if form.vars.download:
            # generate csv and download
            s = StringIO.StringIO()
            db.export_to_csv_file(s)
            response.headers['Content-Type'] = 'text/csv'
            if form.vars.gzip:
                gz_s = StringIO.StringIO()
                response.headers['Content-Disposition'] = 'attachment; filename="%s.gz"' % fname
                gz = gzip.GzipFile(filename='temp.gz', mode='wb', fileobj=gz_s)
                gz.write(s.getvalue())
                gz.close()
                return gz_s.getvalue()
            else:
                response.headers['Content-Disposition'] = 'attachment; filename="%s"' % fname
                return s.getvalue()
        else:
            # generate csv and store locally
            from skaldship.general import check_datadir
            check_datadir(request.folder)
            tmpfile = os.path.join(request.folder, 'data/backups', fname)
            if form.vars.gzip:
                fobj = gzip.open(tmpfile + '.gz', 'wb')
            else:
                fobj = open(tmpfile, 'wb')
            db.export_to_csv_file(fobj)
            return redirect(URL('default', 'data_dir/backups'))
    elif form.errors:
        response.flash = "Error in form"

    return dict(form=form, backup_dir=backup_dir)

@auth.requires_login()
def database_restore():
    """
    Retore a database from CSV data
    """
    response.title = "%s :: Database CSV Restore" % (settings.title)
    import os
    import glob
    from skaldship.general import check_datadir

    check_datadir(request.folder)
    backup_dir = os.path.join(request.folder, 'data/backups')
    os.chdir(backup_dir)
    csv_files = []
    for ext in ["*.csv", "*.csv.gz"]:
        csv_files.extend(glob.glob(ext))

    form = SQLFORM.factory(
        Field('file', type='string', requires=IS_EMPTY_OR(IS_IN_SET(csv_files)), label=T('Local File')),
        Field('upload', type='upload', uploadfolder=backup_dir, label=T('Upload CSV File')),
        Field('wipe', type='boolean', default=False, label=T('Wipe all existing data'))
    )

    if form.process().accepted:
        if form.vars.wipe:
            db.t_hosts.truncate(mode="CASCADE")
            db.t_services.truncate(mode="CASCADE")
            db.t_os.truncate(mode="CASCADE")
            db.t_host_os_refs.truncate(mode="CASCADE")
            db.t_apps.truncate(mode="CASCADE")
            db.t_services_apps_refs.truncate(mode="CASCADE")
            db.t_service_vulns.truncate(mode="CASCADE")
            db.t_service_info.truncate(mode="CASCADE")
            db.t_accounts.truncate(mode="CASCADE")
            db.t_host_notes.truncate(mode="CASCADE")
            db.t_evidence.truncate(mode="CASCADE")
            db.t_snmp.truncate(mode="CASCADE")
            db.commit()

        if form.vars.file:
            fname = form.vars.file
        elif form.vars.upload:
            fname = form.vars.upload

        if fname.endswith('.gz'):
            import gzip
            fobj = gzip.open(fname, 'rb')
        else:
            fobj = open(fname, 'rb')

        db.import_from_csv_file(fobj)

    elif form.errors:
        response.flash = "Error in form"

    os.chdir(request.folder)
    return dict(form=form, backup_dir=backup_dir)

@auth.requires_login()
def wiki():
    # web2py wiki is a bit of a beast in a multi-user environment
    # The db.auth_user.id == 1 has implicit auth_editor permission. The databases for the wiki are
    # not created until the person who installed the database visits the wiki.
    # Any user id > 1 must manually be added to the auth_editor group unless manage_permission is False
    return auth.wiki(migrate=settings.migrate, manage_permissions=False)

@auth.requires_login()
def data_dir():
    from gluon.tools import Expose
    import os
    response.title = "%s :: Browsing Data Directory" % (settings.title)
    data_path = os.path.join(request.folder, 'data')
    return dict(files=Expose(data_path))

def ip_calc():
    response.files.append(URL(request.application, 'static', 'js/ipv4_calc.js'))
    response.files.append(URL(request.application, 'static', 'js/teredo_calc.js'))
    response.title = "%s :: IP Calculators" % (settings.title)
    return dict()

def redirect():
    redirect_url = request.vars.get('url', '')
    pwnwiki = request.vars.get('pwniki', False)
    response.title = "%s :: Redirecting to %s" % (settings.title, redirect_url)
    return dict(redirect_url=redirect_url, pwnwiki=pwnwiki)
