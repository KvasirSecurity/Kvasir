# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## CPE controller
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
## os
##-------------------------------------------------------------------------

@auth.requires_signature()
@auth.requires_login()
def os_add_to_kvasir():
    """
    Adds a CPE OS record to the current Kvasir t_os db
    """
    count = 0
    if request.vars.has_key('ids'):
        for arg in request.vars.ids.split('|'):
            if arg is not '':
                cpe_record = db.t_cpe_os[arg]
                if cpe_record is None: continue
                osinfo = {}
                osinfo['f_cpename'] = cpe_record.f_cpename
                osinfo['f_edition'] = cpe_record.f_edition
                osinfo['f_language'] = cpe_record.f_language
                osinfo['f_product'] = cpe_record.f_product
                osinfo['f_title'] = cpe_record.f_title
                osinfo['f_vendor'] = cpe_record.f_vendor
                osinfo['f_version'] = cpe_record.f_version
                osinfo['f_isincpe'] = True
                try:
                    db.t_os.insert(**osinfo)
                    count += 1
                except:
                    pass
                db.commit()
    response.flash = "Added %s CPE OS record(s) to Kvasir" % (count)
    response.headers['web2py-component-command'] = "jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return

@auth.requires_login()
def os_add():
    response.title = "%s :: Add CPE OS" % (settings.title)
    form=crud.create(db.t_cpe_os,next='os_edit/[id]')
    return dict(form=form)

@auth.requires_login()
def os_edit():
    record = db.t_cpe_os(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('OS record not found')}))
    response.title = "%s :: Update CPE OS :: %s" % (settings.title, record.f_title)
    form=crud.update(db.t_cpe_os,record,next='os_edit/[id]',
                     ondelete=lambda form: redirect(URL('os_list')),
                     onaccept=crud.archive)
    return dict(form=form)

@auth.requires_login()
def os_list():
    response.title = "%s :: CPE Operating Systems" % (settings.title)
    if request.extension == 'json':
        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            limit = start + int(request.vars.iDisplayLength)
            if limit == -1:
                limit = db(db.t_cpe_os).count()
        else:
            limit = int(auth.user.f_show_size)
        if request.vars.has_key('sSearch'):
            # sSearch global search box
            # only need to do cpename and title since the other fields
            # are just these broken out
            query = db.t_cpe_os.f_cpename.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_cpe_os.f_title.like("%%%s%%" % request.vars.sSearch)
        else:
            query = db.t_cpe_os

        if request.vars.iSortingCols == '1':
            # sorting by a column
            cols = ( db.t_cpe_os.id,
                     db.t_cpe_os.f_cpename,
                     db.t_cpe_os.f_title,
                     db.t_cpe_os.f_vendor,
                     db.t_cpe_os.f_product,
                     db.t_cpe_os.f_version,
                     db.t_cpe_os.f_update,
                     db.t_cpe_os.f_edition,
                     db.t_cpe_os.f_language,
                   )

            orderby = cols[int(request.vars.iSortCol_0)]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(query)(db.t_cpe_os).select(orderby=orderby, limitby=(start, limit))
            else:
                rows=db(query)(db.t_cpe_os).select(orderby=~orderby, limitby=(start, limit))
        else:
            rows=db(query)(db.t_cpe_os).select(limitby=(start, limit))

        nolimit=db(query)(db.t_cpe_os).count()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = []
            atxt.append(A(r.id, _target="os_update_%s" % (r.id), _href="os_edit/%s" % (r.id)).xml())
            atxt.append('<input class="add_to_kvasir" name="sel_id" id="sel_id" value="' + str(r.id) + '" type="checkbox">')
            atxt.append(r.f_cpename)
            atxt.append(r.f_title)
            atxt.append(r.f_vendor)
            atxt.append(r.f_product)
            atxt.append(r.f_version)
            atxt.append(r.f_update)
            atxt.append(r.f_edition)
            atxt.append(r.f_language)
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        totalrecords = db(db.t_cpe_os).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   'iTotalDisplayRecords': nolimit,
                   'aaData': aaData,
                 }

        return result
    else:
        return dict()

##-------------------------------------------------------------------------
## apps
##-------------------------------------------------------------------------

'''
@auth.requires_login()
def apps_add():
    response.title = "%s :: Add CPE Application" % (settings.title)
    form=crud.create(db.t_cpe_apps,next='apps_edit/[id]')
    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def apps_add_to_kvasir():
    """
    Adds a CPE App record to the current Kvasir t_os db
    """
    count = 0
    if request.vars.has_key('ids'):
        for arg in request.vars.ids.split('|'):
            if arg is not '':
                cpe_record = db.t_cpe_apps[arg]
                if cpe_record is None: continue
                info = {}
                info['f_cpename'] = cpe_record.f_cpename
                info['f_edition'] = cpe_record.f_edition
                info['f_language'] = cpe_record.f_language
                info['f_product'] = cpe_record.f_product
                info['f_title'] = cpe_record.f_title
                info['f_vendor'] = cpe_record.f_vendor
                info['f_version'] = cpe_record.f_version
                info['f_isincpe'] = True
                try:
                    db.t_apps.insert(**info)
                    count += 1
                except:
                    pass
                db.commit()
    response.flash = "Added %s CPE App record(s) to Kvasir" % (count)
    response.headers['web2py-component-command'] = "jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return

@auth.requires_login()
def apps_edit():
    record = db.t_cpe_apps(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Apps record not found')}))
    response.title = "%s :: Edit CPE Application :: %s" % (settings.title, record.f_title)
    form=crud.update(db.t_cpe_apps,record,next='apps_edit/[id]',
                     ondelete=lambda form: redirect(URL('apps_list')),
                     onaccept=crud.archive)
    return dict(form=form)

@auth.requires_login()
def apps_list():
    response.title = "%s :: CPE Applications" % (settings.title)
    if request.extension == 'json':
        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            limit = start + int(request.vars.iDisplayLength)
            if limit == -1:
                limit = db(db.t_cpe_apps).count()
        else:
            limit = int(auth.user.f_show_size)
        if request.vars.has_key('sSearch'):
            # sSearch global search box
            # only need to do cpename and title since the other fields
            # are just these broken out
            query = db.t_cpe_apps.f_cpename.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_cpe_apps.f_title.like("%%%s%%" % request.vars.sSearch)
        else:
            query = db.t_cpe_apps

        if request.vars.iSortingCols == '1':
            # sorting by a column
            cols = ( db.t_cpe_apps.id,
                     db.t_cpe_apps.f_cpename,
                     db.t_cpe_apps.f_title,
                     db.t_cpe_apps.f_vendor,
                     db.t_cpe_apps.f_product,
                     db.t_cpe_apps.f_version,
                     db.t_cpe_apps.f_update,
                     db.t_cpe_apps.f_edition,
                     db.t_cpe_apps.f_language,
                   )

            orderby = cols[int(request.vars.iSortCol_0)]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(query)(db.t_cpe_apps).select(orderby=orderby, limitby=(start, limit))
            else:
                rows=db(query)(db.t_cpe_apps).select(orderby=~orderby, limitby=(start, limit))
        else:
            rows=db(query)(db.t_cpe_apps).select(limitby=(start, limit))

        nolimit=db(query)(db.t_cpe_apps).count()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = []
            atxt.append(A(r.id, _target="apps_update_%s" % (r.id), _href="apps_edit/%s" % (r.id)).xml())
            atxt.append('<input class="add_to_kvasir" name="sel_id" id="sel_id" value="' + str(r.id) + '" type="checkbox">')
            atxt.append(r.f_cpename)
            atxt.append(r.f_title)
            atxt.append(r.f_vendor)
            atxt.append(r.f_product)
            atxt.append(r.f_version)
            atxt.append(r.f_update)
            atxt.append(r.f_edition)
            atxt.append(r.f_language)
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        totalrecords = db(db.t_cpe_apps).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   'iTotalDisplayRecords': nolimit,
                   'aaData': aaData,
                 }

        return result
    else:
        return dict()

##-------------------------------------------------------------------------
## hardware
##-------------------------------------------------------------------------

@auth.requires_login()
def hardware_add():
    response.title = "%s :: Add CPE Hardware" % (settings.title)
    form=crud.create(t_cpe_hardware_refs,next='hardware_edit/[id]')
    return dict(form=form)

@auth.requires_login()
def hardware_edit():
    record = db.t_app_fingerprints(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Hardware record not found')}))
    response.title = "%s :: Edit CPE Hardware :: %s" % (settings.title, record.f_title)
    form=crud.update(t_cpe_hardware,record,next='hardware_edit/[id]',
                     ondelete=lambda form: redirect(URL('hardware_list')),
                     onaccept=crud.archive)
    return dict(form=form)

@auth.requires_login()
def hardware_list():
    response.title = "%s :: CPE Hardware" % (settings.title)
    if request.extension == 'json':
        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            limit = start + int(request.vars.iDisplayLength)
            if limit == -1:
                limit = db(db.t_pe_hardware).count()
        else:
            limit = int(auth.user.f_show_size)
        if request.vars.has_key('sSearch'):
            # sSearch global search box
            # only need to do cpename and title since the other fields
            # are just these broken out
            query = db.t_cpe_hardware.f_cpename.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_cpe_hardware.f_title.like("%%%s%%" % request.vars.sSearch)
        else:
            query = db.t_cpe_hardware

        if request.vars.iSortingCols == '1':
            # sorting by a column
            cols = ( db.t_cpe_hardware.id,
                     db.t_cpe_hardware.f_cpename,
                     db.t_cpe_hardware.f_title,
                     db.t_cpe_hardware.f_vendor,
                     db.t_cpe_hardware.f_product,
                     db.t_cpe_hardware.f_version,
                     db.t_cpe_hardware.f_update,
                     db.t_cpe_hardware.f_edition,
                     db.t_cpe_hardware.f_language,
                   )

            orderby = cols[int(request.vars.iSortCol_0)]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(query)(db.t_cpe_hardware).select(orderby=orderby, limitby=(start, limit))
            else:
                rows=db(query)(db.t_cpe_hardware).select(orderby=~orderby, limitby=(start, limit))
        else:
            rows=db(query)(db.t_cpe_hardware).select(limitby=(start, limit))

        nolimit=db(query)(db.t_cpe_hardware).count()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = []
            atxt.append(A(r.id, _target="hardware_update_%s" % (r.id), _href="hardware_edit/%s" % (r.id)).xml())
            atxt.append(r.f_cpename)
            atxt.append(r.f_title)
            atxt.append(r.f_vendor)
            atxt.append(r.f_product)
            atxt.append(r.f_version)
            atxt.append(r.f_update)
            atxt.append(r.f_edition)
            atxt.append(r.f_language)
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        totalrecords = db(db.t_cpe_hardware).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   'iTotalDisplayRecords': nolimit,
                   'aaData': aaData,
                 }

        return result
    else:
        return dict()
'''

##-------------------------------------------------------------------------
## Purge CPE data from database
##-------------------------------------------------------------------------
@auth.requires_login()
def purge():
    response.title = "%s :: CPE Database Purge" % (settings.title)
    form = SQLFORM.factory(
        Field('cpe_os', type='boolean', label=T('CPE OS Database')),
        Field('cpe_apps', type='boolean', label=T('CPE Apps Database')),
        Field('cpe_hardware', type='boolean', label=T('CPE HW Database')),
        Field('are_you_sure', type='boolean', label=T('Are you sure?')),
        )

    if form.accepts(request.vars,session):
        if not form.vars.are_you_sure:
            form.errors.are_you_sure = 'ARE YOU SURE?'
        if form.vars.cpe_os:
            response.flash = 'Deleted CPE OS Data'

        if form.vars.cpe_apps:
            response.flash = 'Deleted CPE Apps Data'
        if form.vars.cpe_hardware:
            response.flash = 'Deleted CPE Hardware Data'
    elif form.errors:
        response.flash = 'Error in form'

    response.title = "%s :: CPE Purge" % (settings.title)
    return dict(form=form)

##-------------------------------------------------------------------------
## Import CPE XML file
##-------------------------------------------------------------------------
@auth.requires_login()
def import_cpe_xml():
    import os, sys
    response.title = "%s :: Import CPE XML Data" % (settings.title)

    form = SQLFORM.factory(
        Field('f_filename', 'upload', label=T('XML File'), uploadfolder=os.path.join(request.folder, 'data', 'misc')),
        Field('f_download_cpe', 'boolean', label=T('D/L from MITRE')),
        Field('f_wipe', 'boolean', label=T('Clear existing'), comment=T('Clears existing entries before importing.')),
        Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background')),
        table_name='cpe_xml'
    )

    if form.accepts(request.vars, session):
        if form.vars.f_filename:
            filename = os.path.join(request.folder,'data','misc',form.vars.f_filename)
        else:
            if not form.vars.f_download_cpe:
                form.errors.f_filename = "Must select file or download from MITRE"
                response.flash = 'Error in submission'
            filename = None

        if filename or form.vars.f_download_cpe:
            if form.vars.f_taskit:
                task = scheduler.queue_task(
                    cpe_import_xml,
                    pargs = [filename, form.vars.f_download_cpe, form.vars.f_wipe],
                    group_name = settings.scheduler_group_name,
                    sync_output = 5,
                    timeout = 1800   # 1/2 hour
                )
                if task.id:
                    redirect(URL('tasks', 'status', args=task.id))
                else:
                    resp_text = "Error submitting job: %s" % (task.errors)
            else:
                from skaldship.cpe import process_xml
                res = process_xml(filename, form.vars.f_download_cpe, form.vars.f_wipe)
                response.flash = res

    elif form.errors:
        response.flash = 'Error in submission'
    else:
        pass

    return dict(form=form)

##-------------------------------------------------------------------------
## backup/restore processes
##-------------------------------------------------------------------------

@auth.requires_login()
def backup():
    """
    Backup CPE database to CSV
    """
    s = StringIO.StringIO()
    db(db.t_cpe_os).select().export_to_csv_file(s)
    response.headers['Content-Type'] = 'text/csv'
    return s.getvalue()
