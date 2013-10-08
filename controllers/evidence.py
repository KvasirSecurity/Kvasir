# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Evidence controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import get_host_record, host_title_maker, host_a_maker, create_hostfilter_query
from datetime import datetime
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir

@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------
## evidence
##-------------------------------------------------------------------------

@auth.requires_login()
def add():
    if request.args(0) is not None:
        record = get_host_record(request.args(0))
        db.t_evidence.f_hosts_id.default = record.id
    else:
        record = None

    if request.extension == 'load':
        buttons=[]
    else:
        buttons=['submit']

    if record:
        form=SQLFORM(db.t_evidence, buttons=buttons, upload=URL('download'), fields=['f_type', 'f_other_type', 'f_text', 'f_evidence'],
                     _action=URL('add', args=[ record.id ]), _id="evidence_add_form")
    else:
        form=SQLFORM(db.t_evidence, buttons=buttons, upload=URL('download'), fields=['f_hosts_id', 'f_type', 'f_other_type', 'f_text', 'f_evidence'],
                     _action=URL('add'), _id="evidence_add_form")

    if request.vars.f_evidence is not None:
        form.vars.f_filename = request.vars.f_evidence.filename
    if form.accepts(request.vars, session):
        response.flash = "Evidence added"
        response.headers['web2py-component-command'] = 'evidencetable.fnReloadAjax();'
        return ""
    elif form.errors:
        response.flash = "Error in form submission"
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])

    db.t_evidence.f_hosts_id.default = None
    response.title = "%s :: Add Evidence" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def edit():
    record = db.t_evidence(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Evidence record not found')}))
    response.title = "%s :: Evidence Update :: %s" % (settings.title, host_title_maker(db.t_hosts[record.f_hosts_id]))
    form=crud.update(db.t_evidence,record,next='edit/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    if request.vars.has_key('ids'):
        for r in request.vars.ids.split('|'):
            if r is not '':
                db(db.t_evidence.id == r).delete()
                count += 1
    db.commit()
    response.flash = "%s Evidence record(s) deleted" % (count)
    response.headers['web2py-component-command'] = 'evidencetable.fnReloadAjax();'
    return

@auth.requires_login()
def download():
    import gluon.contenttype as cc
    f_evidence =request.args[0]

    row=db(db.t_evidence.f_evidence==f_evidence).select(db.t_evidence.f_data, db.t_evidence.f_filename, db.t_evidence.f_evidence).first()

    response.headers['Content-Type']=cc.contenttype(f_evidence)
    # convert unknowns (x-XXXX) into text/plain
    if "/x-" in response.headers['Content-Type']:
        response.headers['Content-Type'].replace('x-log', 'plain')
    response.headers['Content-Disposition'] = "attachment; filename=%s" % (row.f_filename)
    response.headers['Content-Type']='text/plain'
    if row.f_data is not None:
        return row.f_data
    else:
        return ""

@auth.requires_login()
def list():
    """
    Returns a list of evidence based on a host (id, ipv4, ipv6) or all
    """
    import os, string
    if request.args(0) is not None:
        record = get_host_record(request.args(0))
        if record is None:
            redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
        response.title = "%s :: Evidence for host %s" % (settings.title, host_title_maker(record))
    else:
        response.title = "%s :: Evidence listing" % (settings.title)
        record = None

    aaData = []
    if request.extension == "json":
        if record is None:
            rows = db(db.t_evidence).select(db.t_evidence.id,
                                            db.t_evidence.f_hosts_id,
                                            db.t_evidence.f_type,
                                            db.t_evidence.f_other_type,
                                            db.t_evidence.f_text,
                                            db.t_evidence.f_filename,
                                            db.t_evidence.f_evidence,
                                            db.t_evidence.f_data.len()+1)
        else:
            rows = db(db.t_evidence.f_hosts_id == record.id).select(db.t_evidence.id,
                                                                    db.t_evidence.f_hosts_id,
                                                                    db.t_evidence.f_type,
                                                                    db.t_evidence.f_other_type,
                                                                    db.t_evidence.f_text,
                                                                    db.t_evidence.f_filename,
                                                                    db.t_evidence.f_evidence,
                                                                    db.t_evidence.f_data.len()+1)

        for r in rows:
            atxt = {}
            cnt = 0
            atxt[cnt] = A('edit', _target="evidence_edit_%s" % (r.t_evidence.id), _href=URL('edit', extension='html', args=r.t_evidence.id)).xml()
            cnt += 1
            if record is None:
                atxt[cnt] = host_a_maker(r.t_evidence.f_hosts_id).xml()
                cnt += 1
            if r.t_evidence.f_other_type:
                atxt[cnt] = "Other: %s" % (r.t_evidence.f_other_type)
            else:
                atxt[cnt] = r.t_evidence.f_type
            cnt += 1
            atxt[cnt] = r.t_evidence.f_text
            cnt += 1
            if r.t_evidence.f_filename is not None:
                if string.lower(os.path.splitext(r.t_evidence.f_filename)[1]) in ('.png', '.jpeg', '.jpg', '.gif'):
                    atxt[cnt] = A(IMG(_src=URL('download', args=[r.t_evidence.f_evidence]), _width="50%", _height="20%"),
                                  _href=URL('download', args=[r.t_evidence.f_evidence]),
                                  _target="evidence_image_%s" % (r.t_evidence.id), _id="evidence_image").xml()
                    cnt += 1
                    atxt[cnt] = "%sb" % (r._extra['(LENGTH(t_evidence.f_data) + 1)'])
                    cnt += 1
                else:
                    atxt[cnt] = A(r.t_evidence.f_filename, _target="evidence_other_%s" % (r.t_evidence.id), _id="evidence_other",
                                  _href=URL('download', args=[r.t_evidence.f_evidence])).xml()
                    cnt += 1
                    atxt[cnt] = "%sb" % (r._extra['(LENGTH(t_evidence.f_data) + 1)'])
                    cnt += 1
            else:
                atxt[cnt] = r.t_evidence.f_filename
                cnt += 1
            atxt['DT_RowId'] = r.t_evidence.id

            aaData.append(atxt)

        return { 'sEcho': request.vars.sEcho,
                 'iTotalRecords': len(aaData),
                 'aaData': aaData,
                 }

    if record:
        th_rows = (TH(T(''), _width="5%"),
                   TH(T('Type')),
                   TH(T('Text')),
                   TH(T('Evidence')),
                   TH(T('File Size')),
                   )
    else:
        th_rows = (TH(T(''), _width="5%"),
                   TH(T('Host')),
                   TH(T('Type')),
                   TH(T('Text')),
                   TH(T('Evidence'), _width="35%"),
                   TH(T('File Size')),
                   )

    evidence = TABLE(THEAD(TR(th_rows)),
                     _class="datatable",
                     _id="evidencetable",
                     _style="width:100%")

    return dict(evidence=evidence, host=record)
