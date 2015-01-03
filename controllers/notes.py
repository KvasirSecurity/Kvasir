# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Evidence controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

from skaldship.hosts import get_host_record, host_title_maker, host_a_maker
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------
## notes
##-------------------------------------------------------------------------

@auth.requires_login()
def add():
    if request.vars.has_key('id'):
        host_id = db.t_hosts[request.vars.id] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipaddr'):
        host_id = db(db.t_hosts.f_ipaddr == request.vars.ipaddr) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    else:
        host_id = None

    if host_id:
        db.t_host_notes.f_hosts_id.default = host_id.id
        form=crud.create(db.t_host_notes, next=URL('edit', vars={'id': host_id.id}),
                         message="Note added")
        db.t_host_notes.f_hosts_id.default = None

    else:
        form=crud.create(db.t_host_notes,next='edit/[id]', message="Note added")

    response.title = "%s :: Create Host Note" % (settings.title)
    return dict(form=form)

#@auth.requires_signature()
@auth.requires_login()
def add_ajax():
    record = None
    if request.vars.has_key('f_hosts_id'):
        record = get_host_record(request.vars.f_hosts_id)
    if record:
        db.t_host_notes.f_hosts_id.default = record.id

    form=SQLFORM(db.t_host_notes, buttons=[], _action=URL('add_ajax', extension='json'), _id="notes_add_form")
    if form.accepts(request.vars, formname='t_host_notes_create'):
        response.flash = 'Note added'
        response.headers['web2py-component-command'] = 'notesumstable.fnReloadAjax(); notestable.fnReloadAjax();'
        return
    elif form.errors:
        response.flash = "Error in form submission"
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])

    db.t_host_notes.f_hosts_id.default = None
    return dict(form=form)

@auth.requires_login()
def read():
    record = db.t_host_notes(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Note record not found')}))
    response.title = "%s :: Host Notes " % (settings.title)
    form=crud.read(db.t_host_notes,record)
    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    if request.vars.has_key('note_ids'):
        for z in request.vars.note_ids.split('|'):
            if z is not '':
                db(db.t_host_notes.id == z).delete()
                db.commit()
                count += 1
    response.flash = "%s Note(s) deleted" % (count)
    # change the javascript reload command based upon the source page
    if 'notes/list' in request.env.http_web2py_component_location:
        response.headers['web2py-component-command'] = 'notestable.fnReloadAjax();'
    elif 'hosts/detail' in request.env.http_web2py_component_location:
        response.headers['web2py-component-command'] = 'notesumstable.fnReloadAjax();'
    return

@auth.requires_login()
def edit():
    record = db.t_host_notes(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Note record not found')}))
    response.title = "%s :: Update Host Note :: %s" % (settings.title, host_title_maker(db.t_hosts[record.f_hosts_id]))
    form=crud.update(db.t_host_notes,record,next='edit/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    return dict(form=form)

@auth.requires_login()
def list():
    """
    Returns a list of notes records based upon an host identifier
    (id, ipv4, ipv6)
    """

    aaData = []
    response.title = "%s :: Notes" % (settings.title)
    if request.args(0) is not None:
        record = get_host_record(request.args(0))
        if record:
            response.title = "%s :: Notes for %s" % (settings.title, host_title_maker(record))
    else:
        record = None

    if request.extension == "json":
        if record:
            rows = db(db.t_host_notes.f_hosts_id == record.id).select()
        else:
            rows = db(db.t_host_notes.id > 0).select()

        for r in rows:
            aTxt = {}
            aaData.append({
                '0': A('edit', _target="host_notes_%s" % (r.id), _href=URL('edit', args=r.id)).xml(),
                '1': host_a_maker(r.f_hosts_id).xml(),
                '2': r.f_note,
                'DT_RowId': r.id
            })

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    if record:
        add_fields = ['f_note']
    else:
        add_fields = ['f_hosts_id', 'f_note']

    add_note = AddModal(
        db.t_host_notes, 'Add', 'Add Note', 'Add Note',
        #fields=add_fields,
        cmd='notestable.fnReloadAjax();',
        flash="Note added"
    )
    if record:
        db.t_host_notes.f_hosts_id.default = record.id
    db.t_host_notes.id.comment = add_note.create()

    notes = TABLE(THEAD(TR(TH(T('ID'), _width="5%"),
                           TH(T('Host'), _width="20%"),
                           TH(T('Note'), _width="95%"),
                           )  ),
                  _class="datatable",
                  _id="notestable",
                  _style="width:100%")

    return dict(notes=notes, host=record, add_note=add_note)

@auth.requires_login()
def summary_by_host():
    """
    Returns a list of notes records based upon an host identifier
    (id, ipv4, ipv6)
    """
    if request.args(0) is None: redirect(URL('default', 'error', vars={'msg': T('No host record provided')}))

    record = get_host_record(request.args(0))

    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.title = "%s :: Notes for host %s" % (settings.title, host_title_maker(record))
    rows = db(db.t_host_notes.f_hosts_id == record.id)(db.t_host_notes).select(db.t_host_notes.id, db.t_host_notes.f_note)

    aaData = []
    if request.extension == "json":
        for r in rows:
            # datatables json requires aaData to be specificly formatted
            atxt = []
            atxt.append('<a href="javascript:void()" onclick="delnotes_summ(' + str(r.id)  +')">X</a>')
            atxt.append(r.f_note)
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }
        return result

    notes = TABLE(THEAD(TR(TH(T('[X]'), _width="5%"),
                           TH(T('Note'), _width="90%"),
                           ), _style="display:none" ),
                  _class="table table-condensed", _id="notestable_summary", _style="width:100%")

    return dict(notes=notes)
