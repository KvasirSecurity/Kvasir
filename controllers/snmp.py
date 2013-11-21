# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## SNMP controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.hosts import get_host_record, host_title_maker, host_a_maker
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return redirect(URL('list'))

##-------------------------------------------------------------------------
## snmp
##-------------------------------------------------------------------------

@auth.requires_login()
def add():
    if request.args(0) is not None:
        record = get_host_record(request.args(0))
        db.t_snmp.f_hosts_id.default = record.id

    response.title = "%s :: Create SNMP Entry" % (settings.title)
    form=crud.create(db.t_snmp,next='edit/[id]')
    db.t_snmp.f_hosts_id.default = None
    return dict(form=form)

@auth.requires_login()
def read():
    record = db.t_snmp(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('SNMP record not found')}))
    response.title = "%s :: SNMP :: %s" % (settings.title, host_title_maker(db.t_hosts[record.f_hosts_id]))
    form=crud.read(db.t_snmp,record)
    return dict(form=form)

@auth.requires_login()
def edit():
    record = db.t_snmp(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('SNMP record not found')}))
    response.title = "%s :: SNMP Update :: %s" % (settings.title, host_title_maker(db.t_hosts[record.f_hosts_id]))
    form=crud.update(db.t_snmp,record,next='read/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    if 'ids' in request.vars:
        for z in request.vars.ids.split('|'):
            if z is not '':
                db(db.t_host_snmp.id == z).delete()
                db.commit()
                count += 1
    msg = "%s SNMP record(s) deleted" % (count)
    response.flash = msg
    response.headers['web2py-component-command'] = 'snmptable.fnReloadAjax();'
    return dict(msg=msg)

@auth.requires_login()
def list():
    aaData = []
    response.title = "%s :: SNMP" % (settings.title)

    if request.extension == "json":
        rows = db(db.t_snmp.id > 0).select()

        for r in rows:
            aTxt = {}
            aaData.append({
                '0': A('edit', _target="snmp_%s" % (r.id), _href=URL('edit', args=r.id)).xml(),
                '1': host_a_maker(r.f_hosts_id).xml(),
                '2': r.f_community,
                '3': r.f_version,
                '4': r.f_access,
                'DT_RowId': r.id
            })

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    add = AddModal(
        db.t_snmp, 'Add', 'Add SNMP', 'Add SNMP',
        #fields=add_fields,
        cmd='snmptable.fnReloadAjax();',
        flash="SNMP entry added"
    )
    db.t_snmp.id.comment = add.create()

    table = TABLE(THEAD(TR(TH(T('ID'), _width="5%"),
                           TH(T('Host')),
                           TH(T('Community')),
                           TH(T('Version')),
                           TH(T('Access Level')),
                           )  ),
                  _class="datatable",
                  _id="snmptable",
                  _style="width:100%")

    return dict(table=table, add=add)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    for r in request.vars.ids.split('|'):
        if r is not None:
            db(db.t_snmp.id == r).delete()
            count += 1
    db.commit()
    response.flash = "%s SNMP Record(s) deleted" % (count)
    response.headers['web2py-component-command'] = "snmptable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return

@auth.requires_login()
def by_host():
    """
    Returns a list of OS records based upon an host identifier
    (id, ipv4, ipv6)
    """
    if request.args(0) is None: redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    record = get_host_record(request.args(0))

    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.title = "%s :: SNMP Records for %s" % (settings.title, host_title_maker(record))
    snmplist = db(db.t_snmp.f_hosts_id==record.id).select()

    aaData = []
    if request.extension == "json":
        for snmp in snmplist:
            # datatables json requires aaData to be specificly formatted
            aaData.append({
                '0': A("edit", _target="snmp_update_%s" % (snmp.id), _href=URL('edit',extension='html',args=snmp.id)).xml(),
                '1': snmp.f_community,
                '2': snmp.f_version,
                '3': snmp.f_access,
                'DT_RowId': snmp.id,
            })

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    form = TABLE(THEAD(TR(TH(T('ID'), _width="5%"),
                          TH(T('Community')),
                          TH(T('Version')),
                          TH(T('Access')),
                          )  ),
                 _class="datatable",
                 _id="snmptable",
                 _style="width:100%")

    add = AddModal(
        db.t_snmp, 'Add', 'Add', 'Add SNMP String',
        fields=[ 'f_community', 'f_version', 'f_access'],
        cmd='snmptable.fnReloadAjax();'
    )
    db.t_snmp.f_hosts_id.default = record.id
    db.t_snmp.id.comment = add.create()

    return dict(form=form, host=record, add=add)
