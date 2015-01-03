# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## NetBIOS controller
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

from skaldship.hosts import create_hostfilter_query, get_host_record, host_title_maker, host_a_maker
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


##-------------------------------------------------------------------------
## netbios
##-------------------------------------------------------------------------

@auth.requires_login()
def index():
    return redirect(URL('list'))

def list():
    form=SQLFORM.grid(
        db.t_netbios,
        details=False,
        maxtextlength=50,
    )
    response.title = "%s :: NetBIOS Data" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def add():
    if request.args(0):
        record = get_host_record(request.args(0))
        db.t_netbios.f_hosts_id.default = record.id
    response.title = "%s :: Add NetBIOS Data" % (settings.title)
    form=crud.create(db.t_netbios, next='edit/[id]', message="NetBIOS data added")
    return dict(form=form)

@auth.requires_login()
def edit():
    """Creates and process a form to edit a NetBIOS record"""
    referrer = request.env.http_referer or ''
    if "hosts/detail" in referrer:
        # check for hosts/detail form in referrer and grab the netbios record
        # given the t_hosts.id or provide an add form
        record = db(db.t_netbios.f_hosts_id==request.args(0)).select().first()
        if not record and request.extension == 'load':
            redirect(URL('add', args=request.args(0)))
        form=crud.update(db.t_netbios, record, next='edit/%s' % request.args(0),
                         message="NetBIOS data updated",
                         ondelete=lambda form: redirect(URL('add')))
    else:
        record = db.t_netbios(request.args(0)) or redirect(URL('add'))
        form=crud.update(db.t_netbios, record, next='edit/[id]',
                         ondelete=lambda form: redirect(URL('add')))

    response.title = "%s :: Edit NetBIOS" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def by_host():
    record = db(db.t_netbios.f_hosts_id==request.args(0)).select().first()
    if not record and request.extension == 'load':
        form=None
    else:
        form=crud.update(db.t_netbios, record, next='by_host/%s' % request.args(0),
                         message="NetBIOS data updated")

    addnetbios = AddModal(
        db.t_netbios, 'Add NetBIOS', 'Add', 'Add NetBIOS',
        #fields=[],
    )
    db.t_netbios.f_hosts_id.default = request.args(0)
    db.t_netbios.id.comment = addnetbios.create()

    return dict(form=form, addnetbios=addnetbios)

##-------------------------------------------------------------------------
## NetBIOS Domain Details
##-------------------------------------------------------------------------

@auth.requires_login()
def domain_detail():
    """Creates a page of all netbios related information for a workgroup/domain"""

    from gluon.serializers import json
    aaData = []
    acctData = []
    response.title = "%s :: NetBIOS Details" % (settings.title)
    if not request.vars.domain:
        response.title = "%s :: NetBIOS Details for ALL" % (settings.title)
        query = (db.t_netbios.id>0)
    else:
        response.title = "%s :: NetBIOS Details for %s" % (settings.title, request.vars.domain)
        query = (db.t_netbios.f_domain == request.vars.domain)

    query &= (db.t_netbios.f_hosts_id == db.t_hosts.id)
    # pull the list of all servers in a NetBIOS Domain
    servers = db(query)(db.t_netbios).select()

    for server in servers:
        #query = (db.t_accounts.f_services_id == db.t_services.id)
        # go through each service looking for any compr accounts,
        accts_list = []
        for svc in server.t_hosts.t_services.select():
            query = (db.t_accounts.f_services_id == db.t_services.id)
            query &= (db.t_services.id == svc.id)
            query &= ((db.t_accounts.f_password != None) | (db.t_accounts.f_hash1 != None))
            for accts in db(query).select():
                accts_list.append((accts.t_accounts.f_username,
                                   accts.t_accounts.f_password,
                                   accts.t_accounts.f_level,
                                   "%s:%s" % (accts.t_accounts.f_hash1, accts.t_accounts.f_hash2),
                                   accts.t_accounts.f_source,
                                   "%s/%s (%s)" % (accts.t_services.f_proto, accts.t_services.f_number, accts.t_services.f_name),
                                   ))

        atxt = []
        if len(accts_list) > 0:
            atxt.append(TD(IMG(_src=URL(request.application,'static','images/details_open.png'))))
        else:
            atxt.append(TD())
        atxt.append(TD(host_a_maker(server.t_hosts)))
        atxt.append(TD(json(accts_list)))
        atxt.append(TD(server.t_netbios.f_domain))
        atxt.append(TD(server.t_netbios.f_type))
        atxt.append(TD(server.t_netbios.f_lockout_duration))
        atxt.append(TD(server.t_netbios.f_shares))
        aaData.append(TR(atxt))

    table = TABLE(THEAD(TR(TH('', _width="5%"),
                           TH(T('Host')),
                           TH(T('Compr. Accts')),
                           TH(T('Domain')),
                           TH(T('Type')),
                           TH(T('Lockout Duration')),
                           TH(T('Shares'))
                           )  ),
                  TBODY(aaData),
                  _class="datatable",
                  _id="netbiostable",
                  _style="width:100%")

    domains= []
    for domain in db(db.t_netbios).select(db.t_netbios.f_domain, distinct=True):
        domains.append(domain.f_domain)

    return dict(table=table, domains=domains)