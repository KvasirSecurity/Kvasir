# -*- coding: utf-8 -*-
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Vulns controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import cvss_metrics, host_title_maker, host_a_maker, get_host_record, severity_mapping, create_hostfilter_query
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return redirect(URL('vulndata_list'))

##-------------------------------------------------------------------------
## vuln references and exploits SQLTABLE.grid() functions
##-------------------------------------------------------------------------

@auth.requires_login()
def vuln_refs():
    """
    Returns Vulnerability References in a grid based on f_vulndata_id
    """
    vuln_id = request.args(0) or redirect(URL('index'))
    db.t_vuln_references.f_vulndata_id.default == vuln_id
    refs = SQLFORM.grid(
        db.t_vuln_references.f_vulndata_id == vuln_id,
        args=[vuln_id],
        #fields = [ db.t_vuln_refs.f_source, db.t_vuln_refs.f_text ],
        fields = [ db.t_vuln_references.f_vuln_ref_id ],
        maxtextlength=255,
        searchable=False,
        deletable=True,
        details=False,
        selectable=False,
        csv=False,
        formstyle='bootstrap',
        formname='vuln_refs_grid',
        client_side_delete=True,
        paginate=None,
    )
    return refs

@auth.requires_login()
def vuln_exploits():
    """
    Returns vulnerability exploits in a grid based on f_vulndata_id
    """
    vuln_id = request.args(0) or redirect(URL('index'))
    db.t_exploit_references.f_vulndata_id == vuln_id
    exploits = SQLFORM.grid(
        db.t_exploit_references.f_vulndata_id == vuln_id,
        args=[vuln_id],
        fields = [ db.t_exploit_references.f_exploit_id ],
        maxtextlength=255,
        searchable=False,
        deletable=True,
        details=False,
        selectable=False,
        csv=False,
        formstyle='bootstrap',
        formname='vuln_exploits_grid',
        client_side_delete=True,
        paginate=None,
)
    return exploits

@auth.requires_login()
def vuln_hosts():
    """
    Returns a grid of hosts based on f_vulndata_id
    """
    vuln_id = request.args(0) or None
    query = (db.t_hosts.id > 0)
    query = create_hostfilter_query(session.hostfilter, query, 't_services')
    query &= (db.t_services.f_hosts_id == db.t_hosts.id)
    query &= (db.t_service_vulns.f_services_id == db.t_services.id)
    query &= (db.t_service_vulns.f_vulndata_id == vuln_id)
    hosts = SQLFORM.grid(
        query,
        args=[vuln_id],
        fields = [
            db.t_hosts.f_ipv4,
            db.t_hosts.f_ipv6,
            db.t_hosts.f_hostname,
            db.t_services.f_proto,
            db.t_services.f_number,
            db.t_service_vulns.f_proof,
        ],
        maxtextlength=255,
        searchable=True,
        deletable=True,
        details=False,
        selectable=True,
        create=False,
        csv=True,
        formstyle='bootstrap',
        formname='vuln_hosts_grid',
        client_side_delete=True,
        paginate=None,
    )
    return hosts

##-------------------------------------------------------------------------
## vulninfo_by_vulnid
##-------------------------------------------------------------------------

@auth.requires_login()
def vulninfo_by_vulnid():
    """
    Returns the vulnerablilty details
    """
    if request.args(0) is None:
        redirect(URL('default', 'error', vars={'msg': T('No Vulnerability ID sent')}))

    record = db(db.t_vulndata.f_vulnid==request.args(0)).select().first()
    if record is not None:
        # grab vuln references and format the table
        response.title = "%s :: Vulnerability Popup :: %s" % (settings.title, record.f_vulnid)
        #cvss_metrics = "AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s" % (record.f_cvss_av,
        #                                                     record.f_cvss_ac,
        #                                                     record.f_cvss_au,
        #                                                     record.f_cvss_c,
        #                                                     record.f_cvss_i,
        #                                                     record.f_cvss_a)

        vulninfo = record
        cvssmetrics = cvss_metrics(record)

        refs = LOAD(request.controller, 'vuln_refs', args=[record.id], ajax=True)
        exploits = LOAD(request.controller, 'vuln_exploits', args=[record.id], ajax=True)

        # TODO: Add hosts with vulnerability -- include service info (proto/port) and
        # ability to delete vuln from service

        query = db.t_service_vulns.f_vulndata_id == record.id
        svc_vulns = db(query).select(db.t_service_vulns.f_services_id,
                                     db.t_service_vulns.f_proof,
                                     db.t_service_vulns.f_status,
                                     db.t_service_vulns.id,
                                     distinct=True)

        # if no filter is set then we blank it out
        if session.hostfilter is None:
            session.hostfilter = [(None, None), False]

        hosts_tr = []
        query = (db.t_hosts.id > 0)
        query = create_hostfilter_query(session.hostfilter, query, 't_services')
        hosts_dict = db(query).select(db.t_hosts.id, cache=(cache.ram, 30)).as_dict()
        hostlist = map(lambda x: x['id'], hosts_dict.itervalues())
        for svc_vuln in svc_vulns:
            svc = db.t_services[svc_vuln.f_services_id]
            if svc is None:
                logger.error("t_servics_vuln #%s does not link to a t_services.id!" % (svc_vuln.id))
                continue

            if svc.f_hosts_id not in hostlist:
                continue

            host_rec = db.t_hosts[svc.f_hosts_id]
            hosts_tr.append(TR(TD(SPAN(I(_class="icon-trash"), _name="host_del", _id=svc_vuln.id)),
                               TD(A(IMG(_src=URL(request.application, 'static/images', 'terminal.png'),
                                        _width="20",
                                        _height="20",
                                        _style="float:left"), "  ",
                                    _href="#", _onclick="launchterm('%s')" % (host_rec.id)),
                                   host_a_maker(host_rec)),
                               TD("%s/%s" % (svc.f_proto, svc.f_number)),
                               TD(MARKMIN(svc_vuln.f_proof)),
                               TD(svc_vuln.f_status),
                               _id=svc_vuln.id ) )

        if len(hosts_tr) > 0:
            hosts = TABLE(THEAD(TR(TH(T('Del'), _width="5%"),
                                   TH(T('Host Information')),
                                   TH(T('Port')),
                                   TH(T('Proof')),
                                   TH(T('Status')),
                                )  ),
                          TBODY(hosts_tr),
                          _id="vulntable", _class="datatable", _width="100%")
        else:
            hosts = None
    else:
        response.title = "%s :: Invalid Vulnerability ID"
        return dict(vulninfo={}, refs={}, exploits={}, hosts={})

    # vuln form data
    vuln=crud.read(db.t_vulndata, record) #returns read-only for for t_vulndata
    vuln.attributes['_id'] = "vuln_record"
    return dict(vuln=vuln, vulninfo=vulninfo, cvssmetrics=cvssmetrics, refs=refs, exploits=exploits, hosts=hosts)

##-------------------------------------------------------------------------
## vulndata
##-------------------------------------------------------------------------

@auth.requires_login()
def vulndata_add():
    response.title = "%s :: Add Vulnerability" % (settings.title)
    form=crud.create(db.t_vulndata,next='vulndata_edit/[id]', message="Vulnerability added")
    return dict(form=form)

@auth.requires_login()
def vulndata_edit():
    vuln_id = request.args(0) or redirect(URL('vulndata_list'))

    # first check for f_vulnid being passed as argument
    record = db(db.t_vulndata.f_vulnid == vuln_id).select().first()
    if not record:
        record = db.t_vulndata[vuln_id]
    if not record:
        redirect(URL('vulndata_list'))

    #form=crud.update(db.t_vulndata,record,next='vulndata_edit/[id]',
    #                 ondelete=lambda form: redirect(URL('vulndata_list')),
    #                 onaccept=crud.archive)

    form = SQLFORM(
        db.t_vulndata,
        record,
        submit_button='Update',
        deletable=True,
        formstyle='bootstrap',
        showid=False,
    )

    hosts = LOAD(request.controller , 'vuln_hosts', args=[record.id], ajax=True, target='vuln_hosts_grid')
    refs = LOAD(request.controller, 'vuln_refs', args=[record.id], ajax=True, target='vuln_refs_grid')
    exploits = LOAD(request.controller, 'vuln_exploits', args=[record.id], ajax=True, target='vuln_exploits_grid')

    if form.process().accepted:
       response.flash = 'Record updated'
    elif form.errors:
       response.flash = 'Error in form'

    response.title = "%s :: Edit Vulnerability :: %s" % (settings.title, record.f_vulnid)
    return dict(form=form, hosts=hosts, refs=refs, exploits=exploits)

# Edit Modal Form
@auth.requires_login()
def edit():
    """ Creates and processes vulndata modal form """
    record = db.t_vulndata(request.args(0)) or redirect(URL('error'))
    if request.extension in ['load', 'json']:
        form=SQLFORM(db.t_vulndata, record, buttons=[], _action=URL('edit', args=[record.id]), _id="vuln_edit_form")
    else:
        response.title = "%s :: Edit Vuln" % (settings.title)
        form=SQLFORM(db.t_vulndata, record, _id="vuln_edit_form")

    if form.accepts(request.vars, session):
        response.flash = "Vuln information updated"
    elif form.errors:
        response.flash = "Error in form submission"
    return dict(form=form)

@auth.requires_login()
def vulndata_list():
    response.title = "%s :: Vulnerabilites" % (settings.title)
    if request.extension == 'json':
        # Datatables Server-side: http://datatables.net/usage/server-side
        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            if request.vars.iDisplayLength == '-1':
                limit = db(db.t_vulndata).count()
            else:
                limit = start + int(request.vars.iDisplayLength)
        else:
            limit = int(auth.user.f_show_size)

        if request.vars.has_key('sSearch'):
            # sSearch global search box
            query = db.t_vulndata.f_vulnid.like("%%%s%%" % request.vars.sSearch) | db.t_vulndata.f_title.like("%%%s%%" % request.vars.sSearch)
        else:
            query = db.t_vulndata.f_active == True
        #query &= (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)

        #total_count = db.t_vulndata.id.count()
        if request.vars.iSortingCols == '1':
            # sorting by a column - this is a little trippy because tuples start at 0
            # and datatables starts at 1 so we have to subtract 1 from iSortCol_0
            cols = ( None,
                     db.t_vulndata.id,
                     db.t_vulndata.f_vulnid,
                     db.t_vulndata.f_title,
                     db.t_vulndata.f_severity,
                     None,
                     db.t_vulndata.f_cvss_score
                     )

            orderby = cols[int(request.vars.iSortCol_0) ]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(query).select(orderby=orderby,
                                      limitby=(start, limit), cache=(cache.ram, 180))
            else:
                rows=db(query).select(orderby=~orderby,
                                      limitby=(start, limit), cache=(cache.ram, 180))
        else:
            rows=db(query).select(limitby=(start,limit), cache=(cache.ram, 180))

        nolimit=db(query).count()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = []
            atxt.append(IMG(_src=URL(request.application,'static','images/details_open.png')).xml())
            #atxt.append(r.total_count)
            atxt.append(A(r.id, _target="vulndata_edit_%s" % (r.id), _href=URL('vulns', 'vulndata_edit', args=r.id, extension='html')).xml())
            atxt.append(A(r.f_vulnid, _target="vulninfo_%s" % (r.f_vulnid), _href=URL(request.application, 'vulns', 'vulninfo_by_vulnid', args=r.f_vulnid, extension='html')).xml())
            atxt.append(r.f_title)
            atxt.append(r.f_severity)
            atxt.append(r.f_pci_sev)
            atxt.append(r.f_cvss_score)
            atxt.append(MARKMIN(r.f_description).xml())
            atxt.append(MARKMIN(r.f_solution).xml())
            # add columns after this, don't do anything prior since it'll affect the hidden fields

            aaData.append(atxt)

        totalrecords = db(db.t_vulndata).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   'iTotalDisplayRecords': nolimit,
                   'aaData': aaData,
                   }

        return result
    else:
        return dict()

@auth.requires_login()
def vulndata_by_host():
    """
    Returns a list of vulnerabilties based upon an host identifier
    (id, ipv4, ipv6)
    """
    record = get_host_record(request.args(0))
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.title = "%s :: Vulnerabilities for %s" % (settings.title, host_title_maker(record))
    services = db(db.t_services.f_hosts_id==record.id).select(db.t_services.id,
                                                              db.t_services.f_proto, db.t_services.f_number)

    if request.extension == "json":
        aaData = []
        for svc in services:
            # service info
            q = db(db.t_service_vulns.f_services_id == svc.id).select()
            for vulninfo in q:
                atxt = {}
                exploit_list = []
                vulndetails = db(db.t_vulndata.id == vulninfo.f_vulndata_id).select(cache=(cache.ram, 300)).first()
                exploits = db(db.t_exploit_references.f_vulndata_id == vulninfo.f_vulndata_id).select(orderby=~db.t_exploit_references.id)
                if len(exploits) > 0:
                    expl_count = "Yes (%d)" % (len(exploits))
                    for expl in exploits:
                        for expl_data in db(db.t_exploits.id == expl.f_exploit_id).select(cache=(cache.ram, 300)):
                            exp_link = expl_data.f_name
                            if expl_data.f_source == 'exploitdb':
                                exp_link = A(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/exploitdb.ico')), ' exploitdb - ' + expl_data.f_name,_href='http://www.exploit-db.com/exploits/' + expl_data.f_title, _target="exploitdb_%s" % (expl_data.f_name))
                            elif expl_data.f_source == 'metasploit':
                                if session.msf_workspace:
                                    msf_uri = os.path.join(auth.user.f_msf_pro_url, 'workspaces', session.msf_workspace_num, 'tasks/new_module_run')
                                else:
                                    msf_uri = 'http://www.metasploit.com/modules/'
                                exp_link = A(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/msf.gif')), ' metasploit - ' + expl_data.f_name,_href=os.path.join(msf_uri, expl_data.f_title), _target="msf_%s" % (expl_data.f_name))
                            elif expl_data.f_source == 'canvas':
                                exp_link = SPAN(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/canvas.png')), ' canvas - ' + expl_data.f_name)

                            exploit_list.append("%s : %s (%s/%s)" % (expl_data.f_title, exp_link, expl_data.f_rank, expl_data.f_level))
                else:
                    expl_count = ""

                atxt['0'] = IMG(_src=URL(request.application,'static','images/details_open.png')).xml()
                atxt['1'] = A('edit', _target="service_vuln_update_%s" % (vulninfo.id), _href=URL('vulns', 'service_vulns_edit', args=vulninfo.id, extension='html')).xml()
                if vulninfo.f_exploited:
                    atxt['2'] = '<input id="exploited" value="' + str(vulninfo.id) + '" type="checkbox", checked>'
                else:
                    atxt['2'] = '<input id="exploited" value="' + str(vulninfo.id) + '" type="checkbox">'
                atxt['3'] = "%s/%s" % (svc.f_proto, svc.f_number)
                atxt['4'] = A(vulndetails.f_vulnid, _target="vulndata_%s" % (vulndetails.id), _href=URL('vulns', 'vulninfo_by_vulnid', args=vulndetails.f_vulnid, extension='html')).xml()
                atxt['5'] = vulndetails.f_severity
                atxt['6'] = vulndetails.f_cvss_score
                atxt['7'] = SPAN(vulninfo.f_status,_id="vulninfo_status",_vulnstatus=vulninfo.f_status).xml()
                atxt['8'] = expl_count
                atxt['9'] = MARKMIN(vulninfo.f_proof).xml()
                atxt['10'] = MARKMIN(vulndetails.f_description).xml()
                atxt['11'] = vulndetails.f_title
                atxt['12'] = "<br />\n".join(exploit_list)
                atxt['DT_RowId'] = vulninfo.id
                aaData.append(atxt)

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    add = AddModal(
        db.t_service_vulns, 'Add', 'Add', 'Add Vulnerability',
        #fields=[
        #],
        cmd='vulntable.fnReloadAjax();'
    )
    #db.t_service_vulns.f_services_id.default = svc.id
    svc_set = []
    for svc in services:
        svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.id]), svc.f_proto, svc.f_number)])
    db.t_service_vulns.f_services_id.requires = IS_IN_SET(svc_set)
    db.t_service_vulns.id.comment = add.create()

    form = TABLE(THEAD(TR(TH('', _width="5%"),
                          TH(T(''), _width="5%"),
                          TH(T('Pwned'), width="5%"),
                          TH(T('Port')),
                          TH(T('Vuln ID')),
                          TH(T('Sev')),
                          TH(T('CVSS')),
                          TH(T('Status')),
                          TH(T('Exploits')),
                          TH(T('Proof')),
                          TH(T('Description')),
                          TH(T('Title')),
                          TH(T('Exploit List')),
                          )  ),
                 _class="datatable",
                 _id="vulntable",
                 _style="width:100%")

    return dict(form=form, host=record, add=add)

##-------------------------------------------------------------------------
## service_vulns
##-------------------------------------------------------------------------

@auth.requires_login()
def service_vulns_add():
    if request.vars.has_key('service'):
        svc = db.t_services[request.vars.service] or redirect(URL('default', 'error', vars={'msg': T('Service record not found')}))
        svc_id = [svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)]
    else:
        svc_id = None

    if request.vars.has_key('host'):
        # grab services for a host
        host_id = db.t_hosts[request.vars.host] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
        services = db(db.t_services.f_hosts_id == host_id.id).select()
        svc_set = []
        for svc in services:
            svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)])
    else:
        host_id = None

    if svc_id or host_id:
        if svc_id:
            db.t_service_vulns.f_services_id.default = svc_id
            response.title = "%s :: Add Service Vulnerablity :: %s" % (settings.title, svc)
        else:
            db.t_service_vulns.f_services_id.requires = IS_IN_SET(svc_set)
            response.title = "%s :: Add Service Vulnerablity :: %s" % (settings.title, host_title_maker(db.t_hosts[svc.f_hosts_id]))
        form=crud.create(db.t_service_vulns,message='Vulnerability added',next=URL('service_vulns_add', vars={'id': svc.id}))
        db.t_service_vulns.f_services_id.requires = None
        response.title = "%s :: Add Service Vulnerablity :: %s" % (settings.title, host_title_maker(db.t_hosts[svc.f_hosts_id]))
    else:
        form=crud.create(db.t_service_vulns,next='service_vulns_edit/[id]')
        response.title = "%s :: Add Service Vulnerablity" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def service_vulns_edit():
    record = db.t_service_vulns(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Service vulnerability record not found')}))
    form=crud.update(db.t_service_vulns,record,next='service_vulns_edit/[id]',
                     ondelete=lambda form: redirect(URL('service_vulns_list')),
                     onaccept=crud.archive)
    response.title = "%s :: Edit Service Vulnerablity" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def service_vulns_list():
    # XXX: this doesn't work yet. . .
    if session.hostfilter is None:
        session.hostfilter = [(None, None), False]

    query = (db.t_service_vulns.id > 0) & (db.t_service_vulns.f_services_id == db.t_services.id) & (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)
    query = create_hostfilter_query(session.hostfilter, query, 't_services')

    columns = [
        db.t_hosts.f_ipv4, db.t_hosts.f_ipv6, db.t_hosts.f_hostname, db.t_services.f_proto, db.t_services.f_number,
        db.t_vulndata.f_vulnid, db.t_service_vulns.f_status, db.t_service_vulns.f_proof,
        #db.t_service_vulns.id
    ]
    rows = SQLFORM.grid(query, columns, deletable=True, selectable=True, details=False, field_id=db.t_service_vulns.id)
    response.title = "Services with Vulnerabilities"
    return dict(rows=rows)

@auth.requires_login()
def new_service_vulns():
    # server-side processing of service vulns.. faster..better?
    # TODO: This...?
    response.title = "%s :: Services and Vulnerabilities" % (settings.title)
    if request.extension == 'json':
        if session.hostfilter is None:
            session.hostfilter = [(None, None), False]

        query = (db.t_service_vulns.id > 0) & (db.t_service_vulns.f_services_id == db.t_services.id) & (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)
        query = create_hostfilter_query(session.hostfilter, query, 't_services')

        if request.vars.has_key('iDisplayStart'):
            start = int(request.vars.iDisplayStart)
        else:
            start = 0
        if request.vars.has_key('iDisplayLength'):
            if request.vars.iDisplayLength == '-1':
                limit = db(query).count()
            else:
                limit = start + int(request.vars.iDisplayLength)
        else:
            limit = int(auth.user.f_show_size)

        if request.vars.has_key('sSearch'):
            # sSearch global search box
            query &= db.t_vulndata.f_vulnid.like("%%%s%%" % request.vars.sSearch) | db.t_vulndata.f_title.like("%%%s%%" % request.vars.sSearch)

        if request.vars.iSortingCols == '1':
            # sorting by a column - this is a little trippy because tuples start at 0
            # and datatables starts at 1 so we have to subtract 1 from iSortCol_0
            cols = ( None,
                     db.t_vulndata.id,
                     db.t_vulndata.f_vulnid,
                     db.t_vulndata.f_title,
                     db.t_vulndata.f_severity,
                     None,
                     db.t_vulndata.f_cvss_score
                     )

@auth.requires_signature()
@auth.requires_login()
def service_vulns_delete():
    count = 0
    for r in request.vars.ids.split('|'):
        if r is not '':
            db(db.t_service_vulns.id == r).delete()
            count += 1
    db.commit()
    response.flash = "%s Vuln(s) deleted" % (count)
    response.headers['web2py-component-command'] = 'vulntable.fnReloadAjax();'
    return

@auth.requires_signature()
@auth.requires_login()
def service_vuln_exploited():
    uncount = 0
    spacount = 0
    if request.vars.has_key('ids'):
        for r in request.vars.ids.split("|"):
            if r is not '':
                rec = db.t_service_vulns[int(r)]
                if rec.f_exploited:
                    db.t_service_vulns[int(r)] = dict(f_exploited = False, f_status = 'vulnerable-exploited')
                    uncount += 1
                else:
                    db.t_service_vulns[int(r)] = dict(f_exploited = True, f_status = 'exploited')
                    spacount += 1
        db.commit()
    response.flash = "%s Exploited / %s Un-exploited" % (spacount, uncount)
    response.headers['web2py-component-command'] = "vulntable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return

##-------------------------------------------------------------------------
## vuln_references
##-------------------------------------------------------------------------

@auth.requires_login()
def vuln_references_add():
    if request.extension in ['load']:
        record = db.t_vuln_references(request.args(0)) or None
        form=SQLFORM(db.t_vuln_references, buttons=[], _action=URL('vuln_references_add'), _id="vulnrefs_link_form")
        if record:
            form.vars.f_vulndata_id = record.id

        if form.accepts(request.vars, session):
            response.flash = "Vulnerability Reference Added"
            #response.headers['web2py-component-command'] = 'hosttable.fnReloadAjax();'
            return
        elif form.errors:
            response.flash = "Error in form submission"
            return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    else:
        form=crud.create(db.t_vuln_references,next='vuln_references_edit/[id]',message='Vulnerability added')
        response.title = "%s :: Add Vulnerability Reference" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def vuln_references_edit():
    record = db.t_vuln_references(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    form=crud.update(db.t_vuln_references,record,next='vuln_references_edit/[id]',
                     ondelete=lambda form: redirect(URL('vuln_references_list')))
    response.title = "%s :: Edit Vulnerability Reference" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def vuln_references_list():
    #f,v=request.args(0),request.args(1)
    #query=f and db.t_vuln_references[f]==v or db.t_vuln_references
    #rows=db(query).select()
    #return dict(rows=rows)
    rows = SQLFORM.smartgrid(db.t_vuln_references)
    response.title = "%s :: Vulnerability References" % (settings.title)
    return dict(rows=rows)

@auth.requires_login()
def vuln_references_by_vulnid():
    """
    Returns a list of vulnerability references by a vulnerability id #
    """
    rows = db(db.t_vuln_references.f_vulndata_id==request.args(0)).select()
    return rows

##-------------------------------------------------------------------------
## aa_by_host
##-------------------------------------------------------------------------

@auth.requires_login()
def aa_by_host():
    """
    Returns a list of vulnerabilties per port in a tree view format based upon an host identifier
    (id, ipv4, ipv6)
    """
    record = get_host_record(request.args(0))
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    treeul=UL(_id='aatree_ul')

    db_svcs = db.t_services
    db_svulns = db.t_service_vulns
    db_vulns = db.t_vulndata

    services = db(db_svcs.f_hosts_id==record.id).select(db_svcs.f_number, db_svcs.id,
                                                        db_svcs.f_proto, db_svcs.f_name,orderby=db_svcs.id)

    tree = DIV(_id="aatree")
    for svc in services:

        nexlist = []
        nexlist_single = []
        expl_count = 0
        exploit_list = UL()
        exploitdb = 0
        metasploit = 0
        canvas = 0
        prev_f_status = ''
        vulnclass = ''
        for vulninfo in db(
                (db_svulns.f_services_id == svc.id) & (db_vulns.id == db_svulns.f_vulndata_id)
                ).select(orderby=~db_svulns.f_status|~db_vulns.f_severity, cache=(cache.ram, 120)):

            #init variables
            vulndetails = vulninfo.t_vulndata
            vulninfo = vulninfo.t_service_vulns

            cur_f_status = vulninfo.f_status

            #Generating the exploit lists

            exploits = db(db.t_exploit_references.f_vulndata_id == vulninfo.f_vulndata_id).select(orderby=~db.t_exploit_references.id)

            exploit_list_single = UL()
            if len(exploits) > 0:

                for expl in exploits:
                    for expl_data in db(db.t_exploits.id == expl.f_exploit_id).select(db.t_exploits.f_source, db.t_exploits.f_title, db.t_exploits.f_name, db.t_exploits.f_rank, db.t_exploits.f_level):
                        exp_link = expl_data.f_name
                        if expl_data.f_source == 'exploitdb':
                            exploitdb += 1
                            exp_link = A(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/exploitdb.ico')), ' exploitdb - ' + expl_data.f_name,_href='http://www.exploit-db.com/exploits/' + expl_data.f_title, _target="exploitdb_%s" % (expl_data.f_name))
                        elif expl_data.f_source == 'metasploit':
                            metasploit += 1
                            if session.msf_workspace:
                                msf_uri = auth.user.f_msf_pro_url + "/" + session.msf_workspace + "/modules/"
                            else:
                                msf_uri = 'http://www.metasploit.com/modules/'
                            exp_link = A(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/msf.gif')), ' metasploit - ' + expl_data.f_name,_href=os.path.join(msf_uri, expl_data.f_title), _target="msf_%s" % (expl_data.f_name))
                        elif expl_data.f_source == 'canvas':
                            canvas += 1
                            exp_link = SPAN(IMG(_align="absmiddle", _width=16, _height=16, _src=URL('static','images/canvas.png')), ' canvas - ' + expl_data.f_name)
                            #expl_link = ' canvas - ' + expl_data.f_name
                        expl_count += 1
                        exploit_list_single.append(LI(expl_data.f_title , " : " , exp_link , " (" , expl_data.f_rank , "/" , expl_data.f_level, ")"))

            textdecoration=""
            if vulninfo.f_exploited == True and len(exploits) > 0:
                textdecoration="text-decoration:line-through underline; "
            elif vulninfo.f_exploited == True and len(exploits) == 0:
                textdecoration="text-decoration: line-through; "
            elif (vulninfo.f_exploited == False or vulninfo.f_exploited == None) and len(exploits) == 0:
                textdecoration="text-decoration: none;"

            #generation vuln link
            style = textdecoration + "color:" + severity_mapping(vulndetails.f_severity - 1)[2]
            vuln_title_link = A(vulndetails.f_vulnid, _title = vulninfo.f_status+ ' Severity: ' + str(vulndetails.f_severity),_style=style, _target="vulndata_%s" % (vulndetails.id), _href=URL(request.application, 'vulns', 'vulninfo_by_vulnid', args=vulndetails.f_vulnid, extension='html'))

            if cur_f_status != prev_f_status and prev_f_status != '':
                nexlist.append(SPAN(nexlist_single, _class=vulnclass)) #for a line in the bottom
                nexlist.append(' ')
                nexlist_single = []
            else:
                nexlist_single.append(' ')

            nexlist_single.append(vuln_title_link )
            prev_f_status = vulninfo.f_status
            vulnclass = ''

            #style for vuln links
            if vulninfo.f_status == 'vulnerable-version':
                vulnclass='host_detail_vulnerable-version'
            if vulninfo.f_status == 'vulnerable-exploited':
                vulnclass='host_detail_vulnerable-exploited'
            if vulninfo.f_status == 'potential':
                vulnclass='host_detail_potential'

            if len(exploit_list_single) > 0: exploit_list.append(LI(SPAN(vuln_title_link), exploit_list_single))

        #attach the last vuln list

        if len(nexlist_single)>0: nexlist.append(SPAN(nexlist_single, _class=vulnclass))
        service_disp=SPAN(svc.f_proto + '/' + svc.f_number + ' - ' + str(svc.f_name))
        expl_count = "Exploits - (%d)" % (expl_count)

        if len(nexlist)>0:
            if len(exploit_list) == 0:
                treeul.append(LI(service_disp,UL(LI(nexlist)))) #No exploits
            else:
                expl_count = SPAN(expl_count + " : metasploit (%d) exploitdb (%d) canvas (%d)" % (metasploit, exploitdb, canvas),_style="color:red")
                treeul.append(LI(service_disp,UL(LI(nexlist)), UL(LI(expl_count,exploit_list,_class="closed"))))
        else:
            treeul.append(LI(service_disp)) #No vulns

        tree = DIV(treeul, _id="aatree")
    return dict(tree=tree)

