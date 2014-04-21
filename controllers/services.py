# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Services controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.hosts import get_host_record, host_title_maker, host_a_maker, create_hostfilter_query
import re
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------
## services
##-------------------------------------------------------------------------

@auth.requires_login()
def add():
    if request.vars.has_key('id'):
        host_id = db.t_hosts[request.vars.id] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv4'):
        host_id = db(db.t_hosts.f_ipv4 == request.vars.ipv4) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv6'):
        host_id = db(db.t_hosts.f_ipv6 == request.vars.ipv6) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    else:
        host_id = None

    if host_id:
        db.t_services.f_hosts_id.default = host_id.id
        form=crud.create(db.t_services, next=URL('edit', vars={'id': host_id.id}),
                         message="Service added")
        db.t_services.f_hosts_id.default = None

    else:
        form=crud.create(db.t_services,next='read/[id]', message="Service added")

    response.title = "%s :: Add Service" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def read():
    record = db.t_services(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
    response.title = "%s :: Service Details :: %s/%s" % (settings.title, record.f_proto, record.f_number)
    #service=crud.read(db.t_services,record)
    service=crud.update(db.t_services,record,next='read/[id]',
                        ondelete=lambda form: redirect(URL('list')))

    # pagination
    svclist = []
    for svc_rec in db(db.t_services.f_hosts_id==record.f_hosts_id).select():
        if svc_rec.id == record.id:
            svclist.append(OPTION("%s/%s" % (svc_rec.f_proto, svc_rec.f_number), _value=svc_rec.id, _selected=True))
        else:
            svclist.append(OPTION("%s/%s" % (svc_rec.f_proto, svc_rec.f_number), _value=svc_rec.id))

    #pagination = pagination_services(db, request, session, record)
    pagination = None   # pagination_services is too slow and may not be necessary here

    vulntr = []
    accttr = []
    svcinfotr = []
    # vulnerabilities
    q = db(db.t_service_vulns.f_services_id == record.id).select()
    for k in q:
        vulninfo = db.t_vulndata(k.f_vulndata_id)
        if vulninfo:
            if settings.use_cvss:
                severity = vulninfo.f_cvss_score
            else:
                severity = vulninfo.f_severity
            vulntr.append(TR(TD("%s/%s" % (record.f_proto, record.f_number)),
                             TD(A(vulninfo.f_vulnid, _href=URL('vulns', 'vulninfo_by_vulnid', args=vulninfo.f_vulnid), _target="vulndata_%s" % (k.f_vulndata_id), extension='html').xml()),
                             TD(severity),
                             TD(k.f_status),
                             TD(XML(k.f_proof, sanitize=False).xml()),
                             ) )

    # accounts
    q = db(db.t_accounts.f_services_id == record.id).select()
    for k in q:
        accttr.append(TR(TD("%s/%s" % (record.f_proto, record.f_number)),
                         TD(k["f_username"]),
                         TD(k["f_password"]),
                         TD(k["f_source"]),
                         TD(k["f_level"]),
                         TD(k["f_description"]),
                         TD(k["f_services_id"]),
                         ) )

    # service info
    q = db(db.t_service_info.f_services_id == record.id).select()
    for k in q:
        svcinfotr.append(TR(TD("%s/%s" % (record.f_proto, record.f_number)),
                            TD(k["f_name"]),
                            TD(k["f_text"]),
                            ) )

    if len(svcinfotr) > 0:
        svcinfotable = TABLE(THEAD(TR(TH(T('Port')), TH(T('Name')), TH(T('Text')))),
                             TBODY(svcinfotr),
                             _style="width:100%",
                             _class="table table-condensed table-striped")
    else:
        svcinfotable = None

    if len(vulntr) > 0:
        vulns = TABLE(THEAD(TR(TH(T('Port')), TH(T('Vulnerability')), TH(T('Severity')), TH(T('Status')), TH(T('Proof')))),
                      TBODY(vulntr),
                      _style="width:100%",
                      _class="table table-condensed")
    else:
        vulns = None

    if len(accttr) > 0:
        accts = TABLE(THEAD(TR(TH(T('Port')), TH(T('Username')), TH(T('Password')), TH(T('Source')), TH(T('Level')), TH(T('Description')), TH(T('Service')))),
                      TBODY(accttr),
                      _style="width:100%",
                      _class="table table-condensed")
    else:
        accts = None

    # grab the notes
    #notes=db(db.t_host_notes.f_hosts_id == record.id)(db.t_host_notes).select(db.t_host_notes.id, db.t_host_notes.f_note)
    #notes = SQLTABLE( db(db.t_service_notes.f_services_id == record.id)(db.t_service_notes).select(db.t_service_notes.id, db.t_service_notes.f_note),
    #                  headers = 'labels',
    #                  _style="width:100%",
    #                  _class = "datatable",
    #                  )

    response.title = "%s :: Service info :: %s ::: %s/%s" % (settings.title, host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)
    return dict(service=service,
                record=record,
                svcinfotable=svcinfotable,
                vulns=vulns,
                #notes=notes,
                accts=accts,
                pagination=pagination)

@auth.requires_login()
def svc_infos():
    """
    Returns Service Info key/values in a grid based on f_services_id
    """
    svc_id = request.args(0) or redirect(URL('index'))
    db.t_service_info.f_services_id.default == svc_id
    infos = SQLFORM.grid(
        db.t_service_info.f_services_id == svc_id,
        args=[svc_id],
        fields = [ db.t_service_info.f_name, db.t_service_info.f_text ],
        maxtextlength=255,
        searchable=False,
        deletable=True,
        details=False,
        selectable=False,
        csv=False,
    )
    return infos

@auth.requires_login()
def edit():
    record = db.t_services(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
    response.title = "%s :: Update Service :: %s/%s" % (settings.title, record.f_proto, record.f_number)
    form=crud.update(db.t_services,record,next='read/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    infos = LOAD(request.controller, 'svc_infos', args=[record.id], ajax=True)
    return dict(form=form, infos=infos)

@auth.requires_login()
def list():
    from skaldship.general import severity_mapping
    response.title = "%s :: Services" % (settings.title)

    # if no filter is set then we blank it out
    if session.hostfilter is None:
        session.hostfilter = [(None, None), False]

    if request.extension == 'json':

        q = (db.t_services.id > 0)
        proto = request.vars.f_proto
        pnum = request.vars.f_number
        if pnum:
            q &= (db.t_services.f_number == pnum)
        if proto:
            q &= (db.t_services.f_protocol == proto)

        q = create_hostfilter_query(session.hostfilter, q, 't_services')

        # Datatables Server-side: http://datatables.net/usage/server-side
        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            if request.vars.iDisplayLength == '-1':
                limit = db(q).count()
            else:
                limit = start + int(request.vars.iDisplayLength)
        else:
            limit = int(auth.user.f_show_size)

        srch_data = request.vars.get('sSearch')
        if srch_data:
            # sSearch global search box

            # parse the search into fields (port:num proto:tcp etc)
            srch_vals = [
                ["port", db.t_services.f_number],
                ["proto", db.t_services.f_proto],
                ["status", db.t_services.f_status],
                ["name", db.t_services.f_name],
                ["banner", db.t_services.f_banner],
                ["ip", db.t_hosts.f_ipv4],
                ["ipv4", db.t_hosts.f_ipv4],
                ["ipv6", db.t_hosts.f_ipv6],
                ["hostname", db.t_hosts.f_hostname],
            ]

            parsed = False
            for val in srch_vals:
                srch_str = "%s:(?P<f>\w+)" % val[0]
                srch_res = re.findall(srch_str, srch_data)
                for res in srch_res:
                    parsed = True
                    if val[0] == 'banner':
                        q &= (val[1].contains(res))
                    else:
                        q &= (val[1].upper() == res.upper())

            if not parsed:
                q &= db.t_services.f_proto.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_services.f_number.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_services.f_name.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_services.f_banner.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_services.f_status.like("%%%s%%" % request.vars.sSearch)

        if request.vars.iSortingCols == '1':
            cols = (
                None,
                None,
                None,
                db.t_services.f_hosts_id,
                db.t_services.f_proto,
                db.t_services.f_number,
                db.t_services.f_status,
                None,
                None,
                None,
                None,
                db.t_services.f_name,
                db.t_services.f_banner,
            )

            orderby = cols[int(request.vars.iSortCol_0)]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(q).select(orderby=orderby, limitby=(start, limit))
            else:
                rows=db(q).select(orderby=~orderby, limitby=(start, limit))
        else:
            rows=db(q).select(limitby=(start, limit))

        nolimit = db(q).count()

        aaData = []

        # datatable formatting is specific
        # gather all the vulndata and exploits into a big row
        # later we'll do a find(lambda: row: row.<db>.<field> == <value>)
        # to slice it into the bits we need. Maybe it'll be faster?
        #vulndata = db().select(db.t_vulndata.f_vulnid, db.t_vulndata.id, db.t_exploit_references.f_exploit_id,
        #                       left=db.t_exploit_references.on(db.t_vulndata.id==db.t_exploit_references.f_vulndata_id))

        for r in rows:
            atxt = {}
            vulncount = 0
            vulns = db(db.t_service_vulns.f_services_id==r.t_services.id).select(db.t_service_vulns.f_vulndata_id, cache=(cache.ram, 60))

            vulnlist = []
            explist=[]
            for vuln in vulns:
                vuln_rec = db.t_vulndata[vuln.f_vulndata_id]
                if vuln_rec.f_vulnid not in vulnlist:
                    if settings.use_cvss:
                        vulnlist.append((vuln_rec.f_vulnid, vuln_rec.f_cvss_score))
                    else:
                        vulnlist.append((vuln_rec.f_vulnid, vuln_rec.f_severity))
                exploits = db(db.t_exploit_references.f_vulndata_id == vuln.f_vulndata_id).select(cache=(cache.ram, 60))
                if len(exploits) > 0:
                    for expinfo in exploits:
                        exp = db.t_exploits[expinfo.f_exploit_id]
                        explist.append(TR(TD(exp.f_name),
                                          TD(exp.f_title),
                                          TD(exp.f_source),
                                          TD(exp.f_rank)
                                          )  )

            q = r.t_services.t_service_info.select(cache=(cache.ram, 60))
            if (len(q) > 0) or (len(explist) > 0) or (len(vulnlist) > 0):
                atxt['0'] = IMG(_src=URL(request.application,'static','images/details_open.png')).xml()
            else:
                atxt['0'] = ""
            atxt['1'] = A("edit", _target="services_edit_%s" % (r.t_services.id), _href=URL('edit', args=[r.t_services.id], extension='html')).xml()
            if len(q) > 0:
                addl = []
                for svcinfo in q:
                    addl.append(TR(TD(svcinfo.f_name), TD(svcinfo.f_text)))
                atxt['2'] = TABLE(THEAD(TR(TH(T('Name')),
                                           TH(T('Text')))),
                                  TBODY(addl),
                                  _class="table table-condensed table-striped",
                                  _style="width:100%").xml()
            else:
                atxt['2'] = ''
            host_rec = db.t_hosts[r.t_services.f_hosts_id]
            atxt['3'] = host_a_maker(host_rec).xml(),
            atxt['4'] = r.t_services.f_proto

            # Append A tags around services with HTTP Ports
            if r.t_services.f_number in HTTP_PORTS and r.t_services.f_proto == "tcp" or r.t_services.f_name == "HTTP":
                atxt['5'] = A(r.t_services.f_number,
                              _href=URL('default', 'redirect', extension='html', vars={'url': "http://%s:%s/" % (host_rec.f_ipv4, r.t_services.f_number)}),
                              _target="%s-tcp-%s" % (host_rec.f_ipv4, r.t_services.f_number)).xml()
            elif r.t_services.f_number in HTTPS_PORTS and r.t_services.f_proto == "tcp" or r.t_services.f_name == "HTTPS":
                atxt['5'] = A(r.t_services.f_number,
                              _href=URL('default', 'redirect', extension='html', vars={'url': "https://%s:%s/" % (host_rec.f_ipv4, r.t_services.f_number)}),
                              _target="%s-tcp-%s" % (host_rec.f_ipv4, r.t_services.f_number)).xml()
            else:
                atxt['5'] = r.t_services.f_number

            atxt['6'] = r.t_services.f_status
            atxt['7'] = len(vulnlist)
            vulntxt = []
            for vuln in vulnlist:
                color = severity_mapping(vuln[1])[2]
                vulntxt.append(A(vuln[0], _id="vuln", _target="vulninfo_by_vulnid_%s" % (vuln[0]), _href=URL('vulns', 'vulninfo_by_vulnid', args=[vuln[0]], extension='html'),
                                 _style="color:"+color).xml())
            atxt['8'] = " :: ".join(vulntxt)
            if len(explist) > 0:
                atxt['9'] = "Yes (%d)" % (len(explist))
            else:
                atxt['9'] = ''
            if len(explist) > 0:
                atxt['10'] = TABLE(THEAD(TR(TH(T('Name')),
                                           TH(T('Title')),
                                           TH(T('Source')),
                                           TH(T('Rank')))),
                                  TBODY(explist),
                                  _class="table table-condensed",
                                  _style="width:100%").xml()
            else:
                atxt['10'] = ''
            atxt['11'] = r.t_services.f_name
            atxt['12'] = r.t_services.f_banner
            atxt['DT_RowId'] = r.t_services.id

            aaData.append(atxt)

        result = {
            'sEcho': request.vars.sEcho,
            'iTotalRecords': db(db.t_services).count(),
            'iTotalDisplayRecords': nolimit,
            'aaData': aaData,
        }

        return result
    else:
        add = AddModal(
            db.t_services, 'Add', 'Add', 'Add Service',
            #fields=[
            #    'f_proto', 'f_number', 'f_status', 'f_name', 'f_banner'
            #],
            cmd='servicetable.fnReloadAjax();'
        )
        db.t_services.id.comment = add.create()
        return dict(add=add)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '':
                db(db.t_services.id == z).delete()
                count += 1
        db.commit()
        response.flash = '%s Services(s) deleted' % (count)
        response.headers['web2py-component-command'] = "servicetable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return


@auth.requires_login()
def by_host():
    """
    Returns a list of services + serviceinfo based upon an host identifier
    (id, ipv4, ipv6)
    """
    record = get_host_record(request.args(0))
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.title = "%s :: Services for %s" % (settings.title, host_title_maker(record))
    services = db(db.t_services.f_hosts_id==record.id).select(db.t_services.id,
                                                              db.t_services.f_proto, db.t_services.f_number, db.t_services.f_status,
                                                              db.t_services.f_name, db.t_services.f_banner)#, cache=(cache.ram,60))

    svcq = (db.t_services.f_hosts_id==record.id)
    infoq = (db.t_service_info.f_services_id == db.t_services.id)

    if request.extension == "json":
        #rows = db(svcq).select(db.t_services.ALL, db.t_service_info.ALL, left=db.t_service_info.on(infoq))
        aaData = []
        for svc in services:
            # service info
            atxt = {}
            q = db(db.t_service_info.f_services_id == svc.id).select()
            if len(q) > 0:
                addl = []
                for svcinfo in q:
                    addl.append(TR(TD(svcinfo.f_name), TD(svcinfo.f_text)))
                atxt['0'] = IMG(_src=URL(request.application,'static','images/details_open.png')).xml()
                atxt['1'] = TABLE(THEAD(TR(TH(T('Name')), TH(T('Text')))), TBODY(addl)).xml()
            else:
                atxt['0'] = ("")
                atxt['1'] = ("")
            atxt['2'] = A('edit', _target="services_edit_%s" % (svc.id),
                          _href=URL('edit', args=[svc['id']], extension='html')).xml()
            atxt['3'] = svc.f_proto
            if svc.f_number in HTTP_PORTS and svc.f_proto == "tcp" or svc.f_name == "HTTP":
                atxt['4'] = A(svc.f_number,
                              _href="http://%s:%s/" % (record.f_ipv4, svc.f_number),
                              _target="%s-tcp-%s" % (record.f_ipv4, svc.f_number)).xml()
            elif svc.f_number in HTTPS_PORTS and svc.f_proto == "tcp" or svc.f_name == "HTTPS":
                atxt['4'] = A(svc.f_number,
                              _href="https://%s:%s/" % (record.f_ipv4, svc.f_number),
                              _target="%s-tcp-%s" % (record.f_ipv4, svc.f_number)).xml()
            else:
                atxt['4'] = svc.f_number
            atxt['5'] = svc.f_status
            atxt['6'] = svc.f_name or ""
            atxt['7'] = svc.f_banner or ""
            atxt['DT_RowId'] = svc.id

            aaData.append(atxt)

        result = { 'sEcho': request.vars._,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    add = AddModal(
        db.t_services, 'Add', 'Add', 'Add Service',
        fields=[
            'f_proto', 'f_number', 'f_status', 'f_name', 'f_banner'
        ],
        cmd='servicetable.fnReloadAjax();'
    )
    db.t_services.f_hosts_id.default = record.id
    db.t_services.id.comment = add.create()

    form = TABLE(THEAD(TR(TH('', _width="5%"),
                          TH('Info'),
                          TH(T('')),
                          TH(T('Protocol')),
                          TH(T('Number')),
                          TH(T('Status')),
                          TH(T('Name')),
                          TH(T('Banner')),
                          )  ),
                 _class="datatable",
                 _id="servicetable",
                 _style="width:100%")

    return dict(form=form, host=record, add=add)

@auth.requires_login()
def hosts_with_port():
    """
    Creates a CSV file of ipv4,ipv6 for hosts with a user-specified
    tcp/udp port
    """

    # XXX: This is broken and needs some TLC

    # buld the dropdown user list
    #users = db(db.auth_user).select()
    #userlist = []
    #for user in users:
    #    userlist.append( [ user.id, user.username ] )

    form = SQLFORM.factory(
        Field('f_proto', 'string', label=T('Protocol'), default="tcp", requires=IS_IN_SET(("tcp", "udp", "info"))),
        Field('f_number', type='string', label=T('Port')),
        Field('f_name', type='string', label=T('Name (exact)')),
        Field('f_banner', type='string', label=T('Banner (contains)')),
        Field('ignore_filter', type='boolean', default=False, label=T('Ignore Hostfilter')),
        #Field('f_ipv4', type='boolean', default=True, label=T('Show IPv4')),
        #Field('f_ipv6', type='boolean', default=False, label=T('Show IPv6')),
        #Field('f_hostname', type='boolean', default=False, label=T('Show Hostname')),
        #Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)),
        #Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()),
        _action=URL(request.application,'services','hosts_with_port.csv'),
    )

    db_svcs = db.t_services
    db_hosts = db.t_hosts
    if form.accepts(request.vars, session):
        q = (db_svcs.id > 0)
        q1 = None
        if form.vars.f_number:
            q1 = (db_svcs.f_number == form.vars.f_number)
        if form.vars.f_proto:
            q2 = (db_svcs.f_proto == form.vars.f_proto)
            if q1:
                q1 = q1 & q2
        if form.vars.f_name:
            q2 = (db_svcs.f_name == form.vars.f_name)
            if q1:
                q1 = q1 & q2
        if form.vars.f_banner:
            q2 = (db_svcs.f_banner.contains(form.vars.f_banner))
            if q1:
                q1 = q1 & q2

        if q1:
            q = q & q1

        if not form.vars.ignore_filter:
            q = create_hostfilter_query(session.hostfilter, q, 't_services')
        else:
            q &= (db_svcs.f_hosts_id == db_hosts.id)

        ip_list = db(q).select(db_hosts.f_ipv4, db_hosts.f_ipv6, db_svcs.f_number, db_hosts.f_hostname, cache=(cache.ram, 60))

        return dict(
            ip_list=ip_list,
        )
    elif form.errors:
        response.flash = 'Error in form'
        redirect(URL('hosts_with_port', extension=''))

    return dict(form=form)

##-------------------------------------------------------------------------
## service_info
##-------------------------------------------------------------------------

@auth.requires_login()
def info_add():
    if request.vars.has_key('id'):
        host_id = db.t_hosts[request.vars.id] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv4'):
        host_id = db(db.t_hosts.f_ipv4 == request.vars.ipv4) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv6'):
        host_id = db(db.t_hosts.f_ipv6 == request.vars.ipv6) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    else:
        host_id = None

    if host_id:
        db.t_service_info.f_hosts_id.default = host_id.id
        form=crud.create(db.t_service_info, next=URL('info_edit', vars={'id': host_id.id}),
                         message="Serivce Info added")
        db.t_service_info.f_hosts_id.default = None

    else:
        form=crud.create(db.t_service_info,next='info_edit/[id]', message="Service Info added")

    response.title = "%s :: Create Service Info" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def info_edit():
    record = db.t_service_info(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
    response.title = "%s :: Update Service Info :: %s" % (settings.title, record.f_services_id)
    form=crud.update(db.t_service_info,record,next='info_edit/[id]',
                     ondelete=lambda form: redirect(URL('info_list')))
    return dict(form=form)

@auth.requires_login()
def info_list():
    response.title = "%s :: Services Info" % (settings.title)
    if request.extension == 'json':
        rows=db(db.t_service_info).select()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            svc = db.t_services[r.f_services_id]
            atxt = []
            atxt.append(A(r.id, _target="service_info_%s" % (r.id), _href="info_edit/%s" % (r.id)).xml(), )
            atxt.append(A(db.t_hosts[svc.f_hosts_id].f_ipv4, _target="host_detail_%s" % (svc.f_hosts_id), _href=URL('hosts', 'detail', args=svc.f_hosts_id, extension='html')).xml())
            atxt.append(svc.f_proto)
            atxt.append(svc.f_number)
            atxt.append(r.f_name)
            atxt.append(r.f_text)
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        totalrecords = db(db.t_service_info).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   #'iTotalDisplayRecords': nolimit,
                   'aaData': aaData,
                   }

        return result
    else:
        return dict()

@auth.requires_login()
def info_by_svcid():
    svc = db.t_services(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
    response.title = "%s :: Service Info for %s" % (settings.title, svc.f_hosts_id.f_ipv4)
    rows = db(db.t_service_info.f_services_id == svc.id).select(db.t_service_info.id,
                                                                db.t_service_info.f_services_id,
                                                                db.t_service_info.f_name,
                                                                db.t_service_info.f_text)
    return dict(rows=rows)

##-------------------------------------------------------------------------
## services_apps
##-------------------------------------------------------------------------

@auth.requires_login()
def apps_add():
    form=crud.create(db.t_services_apps_refs,next='apps_edit/[id]')
    return dict(form=form)

@auth.requires_login()
def apps_edit():
    record = db.t_services_apps_refs(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
    form=crud.update(db.t_services_apps_refs,record,next='apps_edit/[id]',
                     ondelete=lambda form: redirect(URL('apps_list')))
    return dict(form=form)

@auth.requires_login()
def apps_list():
    f,v=request.args(0),request.args(1)
    query=f and db.t_services_apps_refs[f]==v or db.t_services_apps_refs
    rows=db(query)(db.t_services_apps_refs).select()
    return dict(rows=rows)

##-------------------------------------------------------------------------
## service tasks (web images, banner grabs, etc)
##-------------------------------------------------------------------------

@auth.requires_signature()
@auth.requires_login()
def valkyries_ajax():
    """
    Take a list of service_ids, build relevant data send them to the right valkyrie
    """

    valkyrie_type = request.vars.get('valkyrie')
    svc_count = 0
    good_count = 0
    if 'ids' in request.vars:
        svc_list = []
        for z in request.vars.ids.split('|'):
            if z is not '':
                svc_list.append(z)
        if len(svc_list) > 5 or request.vars.f_taskit:
            # we have to scheduler task 20 or more images because of timeouts
            # submit tasks in service groups of 50 at a time to be executed

            total_svcs = len(svc_list)
            task_ids = []
            for cnt in range(0, total_svcs, 50):
                task = scheduler.queue_task(
                    run_valkyrie,
                    pvars=dict(
                        valkyrie_type=valkyrie_type,
                        services=svc_list[cnt:cnt+49]
                    ),
                    group_name=settings.scheduler_group_name,
                    sync_output=5,
                    timeout=1800    # 30 minutes
                )
                if task.id:
                    task_ids.append(task.id)
                else:
                    logger.error("Error creating webshot task: %s" % task.error)
            msg = "%s web screenshot tasks for %s services started" % (len(task_ids), len(svc_list))

        else:
            if valkyrie_type == 'webshot':
                from skaldship.valkyries.webimaging import do_screenshot
            elif valkyrie_type == 'vncshot':
                from skaldship.valkyries.vncscreenshot import do_screenshot
            else:
                msg = "Unknown valkyrie type"
                reponse.flash = msg
                return dict(msg=msg)

            res = do_screenshot(svc_list)
            msg = "%s screenshot(s) taken from %s services(s), %s failed" % (res[0], len(svc_list), res[1])
            response.headers['web2py-component-command'] = "jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"

    else:
        msg = "No services sent!"

    response.flash = msg
    return dict(msg=msg)
