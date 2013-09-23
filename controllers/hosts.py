# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Hosts controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import create_hostfilter_query, get_host_record, pagination, host_title_maker
import gluon.contrib.simplejson
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return redirect(URL('hosts', 'list'))

##-------------------------------------------------------------------------
## hosts
##-------------------------------------------------------------------------

@auth.requires_signature()
@auth.requires_login()
def accessed():

    host = db.t_hosts(request.vars.get('host'))
    if not host:
        response.flash = "No host/ip address provided."
        return

    confval = request.vars.get('checked', None)
    if confval:
        if confval in ['1', 'true']:
            db(db.t_hosts.id == host.id).update(f_accessed = True)
            msg = "Host accessed"
        else:
            db(db.t_hosts.id == host.id).update(f_accessed = False)
            msg = "Host no longer accessed"
    else:
        if host.f_accessed:
            db(db.t_hosts.id == host.id).update(f_accessed = False)
            msg = "Host no longer accessed"
        else:
            db(db.t_hosts.id == host.id).update(f_accessed = True)
            msg = "Host accessed"

    db.commit()
    response.flash = msg
    return dict(msg=msg)

@auth.requires_signature()
@auth.requires_login()
def accessed_multi():
    """Access/unaccess tags multiple hosts via ajax"""

    count = 0
    if request.vars.get('method').lower() in ['accessed', 'unaccessed']:
        method = request.vars.get('method').lower()
        if method == 'accessed':
            conftype = True
        else:
            conftype = False

    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '':

                db(db.t_hosts.id == z).update(f_accessed = conftype)
                count += 1

        db.commit()

    msg = "%s host(s) %sed" % (count, method)
    response.flash = msg
    response.headers['web2py-component-command'] = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return dict(msg=msg)

@auth.requires_signature()
@auth.requires_login()
def followup():

    host = db.t_hosts(request.vars.get('host'))
    if not host:
        response.flash("No host/ip address provided.")
        return

    confval = request.vars.get('checked', None)
    if confval:
        if confval in ['1', 'true']:
            db(db.t_hosts.id == host.id).update(f_followup = True)
            msg = "Host marked for followup"
        else:
            db(db.t_hosts.id == host.id).update(f_followup = False)
            msg = "Host no longer marked for followup"
    else:
        if host.f_followup:
            db(db.t_hosts.id == host.id).update(f_followup = False)
            msg = "Host no longer marked for followup"
        else:
            db(db.t_hosts.id == host.id).update(f_followup = True)
            msg = "Host marked for followup"

    db.commit()
    response.flash = msg
    return dict(msg=msg)

@auth.requires_signature()
@auth.requires_login()
def followup_multi():
    """Followup tags multiple hosts via ajax"""

    count = 0
    if request.vars.get('method').lower() in ['followup', 'nofollowup']:
        method = request.vars.get('method').lower()
        if method == 'followup':
            conftype = True
        else:
            conftype = False

    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '':

                db(db.t_hosts.id == z).update(f_followup = conftype)
                count += 1

        db.commit()

    msg = "%s host(s) marked %s" % (count, method)
    response.flash = msg
    response.js = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return dict(msg=msg)

@auth.requires_signature()
@auth.requires_login()
def confirm():

    host = db.t_hosts(request.vars.get('host'))
    if not host:
        response.flash("No host/ip address provided.")
        return

    confval = request.vars.get('checked', None)
    if confval:
        if confval in ['1', 'true']:
            db(db.t_hosts.id == host.id).update(f_confirmed = True)
            msg = "Host confirmed"
        else:
            db(db.t_hosts.id == host.id).update(f_confirmed = False)
            msg = "Host no longer confirmed"
    else:
        if host.f_confirmed:
            db(db.t_hosts.id == host.id).update(f_confirmed = False)
            msg = "Host no longer confirmed"
        else:
            db(db.t_hosts.id == host.id).update(f_confirmed = True)
            msg = "Host confirmed"

    db.commit()
    response.flash = msg
    referrer = request.env.http_referer or ''
    if "hosts/list" in referrer:
        response.js = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return dict(msg=msg)

@auth.requires_signature()
@auth.requires_login()
def confirmation_multi():
    """Confirms/unconfirms multiple hosts via ajax"""

    count = 0
    if request.vars.get('method').lower() in ['confirm', 'unconfirm']:
        method = request.vars.get('method').lower()
        if method == 'confirm':
            conftype = True
        else:
            conftype = False

    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '':

                db(db.t_hosts.id == z).update(f_confirmed = conftype)
                count += 1

        db.commit()

    msg = "%s host(s) %sed" % (count, method)
    response.flash = msg
    response.headers['web2py-component-command'] = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return dict(msg=msg)

@auth.requires_login()
def detail():

    if request.args(0) is None: redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.files.append(URL(request.application,'static','js/jquery.sparkline.js'))
    response.files.append(URL(request.application,'static','jstree/jstree.min.js'))

    #query = db.t_hosts.id == request.args(0)
    #query = create_hostfilter_query(session.hostfilter, query)

    record = get_host_record(request.args(0))

    if record is None:
        redirect(URL('hosts', 'list'))

    hostipv4=record.f_ipv4
    engineername = db.auth_user[record.f_engineer].username

    # to allow updating of the host record from this page
    host=crud.read(db.t_hosts,record)
    host.attributes['_id'] = "host_record"

    host_points = {}
    # build the host_points field which will cover:
    # the top t_host_os_ref cpe string
    os_list = db(db.t_host_os_refs.f_hosts_id == record.id).select()
    host_points['os'] = (0, 'Unknown')
    for os_rec in os_list:
        if os_rec.f_certainty > host_points['os'][0]:
            host_points['os'] = (os_rec.f_certainty, db.t_os[os_rec.f_os_id].f_title)

    host_points['account_cnt'] = 0
    host_points['password_cnt'] = 0
    host_points['cracked_pct'] = 0
    host_points['vuln_cnt'] = 0
    host_points['vuln_exploited_cnt'] = 0
    host_points['vuln_potential_cnt'] = 0
    vulns = {}
    vuln_list = []
    services = db(db.t_services.f_hosts_id == record.id).select()
    for svc in services:
        for vuln in db(db.t_service_vulns.f_services_id == svc.id).select():
            vulndata = db.t_vulndata[vuln.f_vulndata_id]
            vulns[vulndata.f_vulnid] = ( vulndata.f_severity, vulndata.f_cvss_score )
            vuln_list.append(vulndata)
        host_points['vuln_exploited_cnt'] += db((db.t_service_vulns.f_services_id==svc.id) & (db.t_service_vulns.f_status.like('%exploited%'))).count()
        host_points['vuln_potential_cnt'] += db((db.t_service_vulns.f_services_id==svc.id) & (db.t_service_vulns.f_status.like('%potential%'))).count()
        host_points['vuln_cnt'] += db(db.t_service_vulns.f_services_id==svc.id).count()
        host_points['account_cnt'] += db(db.t_accounts.f_services_id==svc.id).count()
        pwq = ((db.t_accounts.f_services_id==svc.id) & (db.t_accounts.f_compromised == True))
        #pwq &= (((db.t_accounts.f_password != None) | (db.t_accounts.f_password != '')) | (db.t_accounts.f_compromised == True))
        host_points['password_cnt'] += db(pwq).count()
        try:
            host_points['cracked_pct'] = 100 * (host_points['password_cnt'] / host_points['account_cnt'])
        except ZeroDivisionError:
            host_points['cracked_pct'] = 0

    # breakdown of vuln severity
    sev_sum_dict = {}
    for a in range(1, 11):
        sev_sum_dict[a] = 0

    for k,v in vulns.iteritems():
        # take the severity and increment the sev_sum set item
        count = sev_sum_dict.setdefault(v[0], 0)
        count += 1
        sev_sum_dict[v[0]] = count

    sev_sum_spark = []
    sev_sum = []
    for k,v in sev_sum_dict.iteritems():
        sev_sum_spark.append(str(v))
        if v > 0:
            sev_sum.append("%s: %s" % (k, v))

    host_points['sev_sum_spark'] = ",".join(sev_sum_spark)
    host_points['sev_sum'] = " / ".join(sev_sum)

    # netbios record (or none if it's empty)
    netb_record = db(db.t_netbios.f_hosts_id == record.id).select().first() or None
    if netb_record is not None:
        netbios=crud.update(db.t_netbios, netb_record,
                            ondelete=lambda netbios: redirect(URL('host_detail', args=[ record.id ])))
        host_points['netb_domain'] = netb_record.f_domain
        host_points['netb_type'] = netb_record.f_type
    else:
        db.t_netbios.f_hosts_id.default = record.id
        netbios = LOAD('netbios', 'add.load', args=[host.record.id], ajax=True, target='netbios_info')

    host_pagination = pagination(request, record)

    response.title = "%s :: Host info :: %s" % (settings.title, host_title_maker(record))
    return dict(host=host,
                netbios=netbios,
                host_points=host_points,
                host_pagination=host_pagination, hostipv4=hostipv4, engineername=engineername)

@auth.requires_login()
def popover():
    """
    Returns the detail of a host for popovers
    """
    host_rec = get_host_record(request.args(0))
    resp = {}
    if not host_rec:
        resp['title'] = "Host not found"
        resp['content'] = ""
    else:
        svcs = host_rec.t_services
        svc_cnt = 0
        vuln_cnt = 0
        acct_cnt = 0
        for svc in svcs.select():
            svc_cnt += 1
            vuln_cnt += svc.t_service_vulns.count()
            acct_cnt += svc.t_accounts.count()

        host_os = (0, 'Unknown')
        for os_rec in host_rec.t_host_os_refs.select():
            if os_rec.f_certainty > host_os[0]:
                host_os = (os_rec.f_certainty, db.t_os[os_rec.f_os_id].f_title)

        resp['title'] = host_title_maker(host_rec)
        resp['content'] = XML(TABLE(
            TR(TD(T('Asset Group')), TD(host_rec.f_asset_group)),
            TR(TD(T('Engineer')), TD(db.auth_user[host_rec.f_engineer].username)),
            TR(TD(T('OS')), TD("%s (%s)" % (host_os[1], host_os[0]))),
            TR(TD(T('Services')), TD(svc_cnt)),
            TR(TD(T('Vulnerabilities')), TD(vuln_cnt)),
            TR(TD(T('Accounts')), TD(acct_cnt)),
            _class="table table-condensed",
        ))

    return resp

@auth.requires_login()
def add():
    """
    Add a host record to the database
    """
    fields = [
        'f_ipv4',
        'f_ipv6',
        'f_hostname',
        'f_netbios_name',
        'f_macaddr',
        'f_engineer',
        'f_asset_group',
    ]
    db.t_hosts.f_engineer.default = auth.user.id
    if request.extension in ['load', 'json']:
        form=SQLFORM(db.t_hosts, fields=fields, buttons=[], formstyle='bootstrap', _id="hosts_add_form")
        #form=SQLFORM(db.t_hosts, fields=fields, formstyle='bootstrap')
        if form.process().accepted:
            response.flash = "Host Added"
            #response.headers['web2py-component-command'] = 'hosttable.fnReloadAjax();'
            response.js = 'hosttable.fnReloadAjax();'
            return
        elif form.errors:
            response.flash = "Error in form submission"
            #return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    else:
        response.title = "%s :: Add Host" % (settings.title)
        form=crud.create(db.t_hosts,next='detail/[id]', fields=fields)
    return dict(form=form)

@auth.requires_login()
def edit():
    """Creates and process a form to edit a host record"""
    record = db.t_hosts(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    if request.extension in ['load', 'json']:
        form=SQLFORM(db.t_hosts, record, buttons=[], _action=URL('edit', args=[record.id]), _id="host_edit_form")
        if form.accepts(request.vars, session):
            response.flash = "Host information updated"
        elif form.errors:
            response.flash = "Error in form submission"
    else:
        response.title = "%s :: Edit Host" % (settings.title)
        form=crud.update(db.t_hosts, record, next='edit/[id]')

    return dict(form=form)

@auth.requires_login()
def list():
    response.title = "%s :: Host Listing" % (settings.title)
    # hostfilter is a session variable that can be
    # None -- no host filtering
    # (userid, <x>) - limit on user id
    # (assetgroup, <x>) - limit on asset group
    # (range, <x>) - limit on subnet (eg: 192.168)
    hostfilter = session.hostfilter
    if hostfilter is None:
        # if no filter is set then we blank it out
        if session.hostfilter is None:
            session.hostfilter = [(None, None), False]

    if request.extension == 'json':
        # from datetime import datetime, timedelta
        # host_start = datetime.now()
        tot_vuln = 0
        tot_hosts = 0

        """
        # load all the vulndata from service_vulns into a dictionary
        # so we only have to query the memory variables instead of
        # the database each time. We need to collect:
        # svc_vulndata[f_service_id] = (f_vulnid, f_severity, f_cvss_score)
        svc_vulndata = {}

        rows = s_service_vuln_data.select( db.t_vulndata.id, db.t_vulndata.f_vulnid, db.t_vulndata.f_severity, db.t_vulndata.f_cvss_score, cache=(cache.ram, 60))
        for r in rows:
            #exploitcount = db(db.t_exploit_references.f_vulndata_id == r.id).count()
            svc_vulndata[r.id] = ( r.f_vulnid,
                                   r.f_severity,
                                   r.f_cvss_score,
                                   r.t_exploit_references.count())
        """

        # build the query variable.. first all hosts then check
        # if a hostfilter is applied
        q = (db.t_hosts.id > 0)
        q = create_hostfilter_query(session.hostfilter, q)

        aaData = []
        rows = db(q).select(db.t_hosts.ALL, db.t_host_os_refs.f_certainty, db.t_os.f_title, db.auth_user.username,
                            left=(db.t_host_os_refs.on(db.t_hosts.id==db.t_host_os_refs.f_hosts_id),
                                  db.t_os.on(db.t_os.id==db.t_host_os_refs.f_os_id),
                                  db.auth_user.on(db.t_hosts.f_engineer==db.auth_user.id)),
                            orderby=db.t_hosts.id|~db.t_host_os_refs.f_certainty)
        # datatable formatting is specific, crud results are not
        seen = set()
        for r in rows:
            if r.t_hosts.id not in seen and not seen.add(r.t_hosts.id): # kludge way to select only rows per host with the best OS-guess
                spanflags = []
                if r.t_hosts.f_confirmed:
                    confirmed = 'hosts_select_confirmed'
                    spanflags.append('<span class="badge"><i class="icon-check"></i></span>')
                else:
                    confirmed = 'hosts_select_unconfirmed'

                if r.t_hosts.f_accessed:
                    spanflags.append('<span class="badge badge-success"><i class="icon-heart"></i></span>')
                if r.t_hosts.f_followup:
                    spanflags.append('<span class="badge badge-important"><i class="icon-flag"></i></span>')

                confirmed = '<div class="%s">%s</div>' % (confirmed, " ".join(spanflags))

                if r.t_hosts.f_ipv4:
                    ipv4 = A(r.t_hosts.f_ipv4, _id='ipv4', _href=URL('detail', extension='html', args=[r.t_hosts.id]), _target="host_detail_%s" % (r.t_hosts.id)).xml()
                else:
                    ipv4 = ""
                if r.t_hosts.f_ipv6:
                    ipv6 = A(r.t_hosts.f_ipv6, _id='ipv6', _href=URL('detail', extension='html', args=[r.t_hosts.id]), _target="host_detail_%s" % (r.t_hosts.id)).xml()
                else:
                    ipv6 = ""

                if r.t_os.f_title is None:
                    os = "Unknown"
                else:
                    os = r.t_os.f_title

                atxt = {
                     '0': confirmed,
                     '1': ipv4,
                     '2': ipv6,
                     '3': r.t_hosts.f_service_count,
                     '4': r.t_hosts.f_vuln_count,
                     '5': "<span class=\"severity_sparkline\" values=\"%s\"></span>" % (r.t_hosts.f_vuln_graph),
                     '6': r.t_hosts.f_exploit_count,
                     '7': r.t_hosts.f_hostname,
                     '8': r.t_hosts.f_netbios_name,
                     '9': os,
                     '10': r.auth_user.username,
                     '11': r.t_hosts.f_asset_group,
                     'DT_RowId': "%s" % (r.t_hosts.id),
                }

                aaData.append(atxt)
                #print("Total time in vuln processing: %s seconds" % (tot_vuln))
                #print("Host record processed in %s seconds" % (timedelta.total_seconds(datetime.now() - row_start)))
                tot_hosts += 1

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'iTotalDisplayRecords': len(aaData),
                   'aaData': aaData,
                   }

        #print("Host_select processed %s hosts in %s seconds" % (tot_hosts, timedelta.total_seconds(datetime.now() - host_start)))
        return result
    else:
        add_hosts = AddModal(
            db.t_hosts, 'Add Host', 'Add Host', 'Add Host',
            fields = [
                'f_ipv4',
                'f_ipv6',
                'f_hostname',
                'f_netbios_name',
                'f_macaddr',
                'f_engineer',
                'f_asset_group',
            ],
            cmd = 'hosttable.fnReloadAjax();'
        )
        db.t_hosts.id.comment = add_hosts.create()
        response.files.append(URL(request.application,'static','js/jquery.sparkline.js'))
        return dict(hostfilter=session.hostfilter, add_hosts=add_hosts)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    for r in request.vars.ids.split('|'):
        if r is not None:
            db(db.t_hosts.id == r).delete()
            count += 1
    db.commit()
    response.flash = "%s Host(s) deleted" % (count)
    response.headers['web2py-component-command'] = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    #response.js = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"

    return dict()

@auth.requires_login()
def filter():
    """
    hostfilter is a session variable that can be
      None -- no host filtering
      (userid, <x>) - limit on user id
      (group, <x>) - limit on asset group
      (range, <x>) - limit on subnet (eg: 192.168)
    """
    if type(session.hostfilter) is type(None):
        session.hostfilter = [(None, None), False]

    hostfilter = session.hostfilter[0]
    unconfirmed = session.hostfilter[1]
    response.title = "%s :: Host Filter" % (settings.title)

    if request.extension == 'json':
        # process filter function requests
        function = request.vars.get('function', '')

        if function.lower() in ['assetgroup', 'range']:
            hostfilter = (function.lower(), request.vars.get('filter', ''))
        elif function.lower() == 'userid':
            userid = request.vars.get('userid', '')
            username = db.auth_user[userid].username or ''
            hostfilter = (function.lower(), username)
        elif function.lower() == 'clear':
            hostfilter = (None, None)

        if request.vars.has_key('_formname'):
            if request.vars.get('unconfirmed'):
                unconfirmed = True
            else:
                unconfirmed = False

        session.hostfilter = [hostfilter, unconfirmed]
        referrer = request.env.http_referer or ''
        if function:
            if "hosts/list" in referrer:
                response.headers['web2py-component-command'] = 'hosttable.fnReloadAjax();'
            elif "accounts/list" in referrer:
                response.headers['web2py-component-command'] = 'accounttable.fnReloadAjax();'
            elif "services/list" in referrer:
                response.headers['web2py-component-command'] = 'servicetable.fnReloadAjax();'
            elif "stats/vulnlist" in referrer:
                response.headers['web2py-component-command'] = 'vulntable.fnReloadAjax();'

        return dict(hostfilter=session.hostfilter)

    elif request.extension in ['load', 'html']:
        # send filter form
        if request.extension == 'load':
            buttons = []
        else:
            buttons = ['submit']
        form = SQLFORM.factory(
            Field('function', 'list', label=T('Filter by'), requires=IS_IN_SET(['UserID', 'AssetGroup', 'Range'], multiple=False)),
            Field('filter', 'string', label=T('Filter text')),
            Field('userid', db.auth_user, label=T('User'), requires=IS_EMPTY_OR(IS_IN_DB(db, db.auth_user.id, '%(username)s'))),
            Field('unconfirmed', 'boolean', default=False, label=T('Unconfirmed Only')),
            _id="host_filter_form",
            buttons=buttons,
        )
        if form.accepts(request.vars, session):
            function = request.vars.get('function', '')

            if function.lower() == 'userid':
                userid = request.vars.get('userid', '')
                username = db.auth_user[userid].username or ''
                hostfilter = (function.lower(), username)
            elif function.lower() in ['assetgroup', 'range']:
                hostfilter = (function.lower(), request.vars.get('filter', ''))
            elif function.lower() == 'clear':
                hostfilter = [(None, None), False]

            unconfirmed = form.vars.get('unconfirmed', False)
            if unconfirmed == 'on':
                unconfirmed = True
            else:
                unconfirmed = False
            session.hostfilter = [hostfilter, form.vars.unconfirmed]
        elif form.errors:
            pass
        return dict(form=form)

@auth.requires_login()
def csv_hostupdate():
    """Takes an uploaded csv file and processes it, updating host records"""
    import csv, os
    form=SQLFORM.factory(
        Field('csvfile', 'upload', uploadfolder=os.path.join(request.folder, 'data', 'misc'), label=T('CSV Filename')),
        Field('overwrite', 'boolean', default=False, label=T('Overwrite existing data')),
        Field('add_hosts', 'boolean', default=False, label=T('Add missing hosts')),
    )
    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        filename = os.path.join(request.folder, 'data/misc', form.vars.csvfile)
        csv_rdr = csv.reader(open(filename, "r"))
        updated = 0
        skipped = 0
        for row in csv_rdr:
            record = None
            if row[0] != '':
                record=db(db.t_hosts.f_ipv4==row[0]).select().first()
            elif row[1] != '':
                record=db(db.t_hosts.f_ipv6==row[1]).select().first()
            if record is None:
                logging.warning("Host record not found for %s" % row)
                skipped += 1
                continue
            if record.f_hostname is None or record.f_hostname == '':
                record.update_record(f_hostname = row[2].strip('\n'))
                updated += 1
            elif form.vars.overwrite:
                record.update_record(f_hostname = row[2].strip('\n'))
                updated += 1
            else:
                skipped += 1
            db.commit()
        response.flash = "Updated %s records, skipped %s" % (updated, skipped)
        os.remove(filename)

    response.title = "%s :: CSV Hostname Update" % (settings.title)
    return dict(form=form)

##-------------------------------------------------------------------------
## mass host functions
##-------------------------------------------------------------------------

@auth.requires_signature()
@auth.requires_login()
def mass_os_refs():
    """Receives a list of host records and relevant OS information and assigns them!"""

    fields = ['f_os_id', 'f_certainty', 'f_class', 'f_family']
    host_ids = []
    if request.vars.has_key('host_ids'):
        for z in request.vars.host_ids.split('|'):
            if z is not '':
                host_ids.append(z)
    form=SQLFORM(db.t_host_os_refs, fields=fields, buttons=[], _id="mass_os_form")
    if form.validate():
        insert = []
        for idrec in host_ids:
            insert.append({
                'f_hosts_id': idrec,
                'f_os_id': form.vars.f_os_id,
                'f_class': form.vars.f_class,
                'f_family': form.vars.f_family,
                'f_certainty': form.vars.f_certainty,
            })
        db.t_host_os_refs.bulk_insert(insert)
        response.flash = "Operating System updated on %s host(s)" % (len(host_ids))
        response.headers['web2py-component-command'] = "hosttable.fnReloadAjax();  jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
        return
    elif form.errors:
        response.flash = "Error in form submission"

    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def mass_asset_group():
    """Receives a list of host records and assetgroup and assigns them!"""

    host_ids = []
    if request.vars.has_key('host_ids'):
        for z in request.vars.host_ids.split('|'):
            if z is not '':
                host_ids.append(z)
    form=SQLFORM.factory(
        Field('asset_group', 'string', label=T('Asset Group')),
        buttons=[], _id="mass_asset_form")

    if form.validate():
        insert = []
        for idrec in host_ids:
            db(db.t_hosts.id == idrec).update(
                f_asset_group=form.vars.asset_group,
            )
            db.commit()
        response.flash = "%s host(s) assigned to %s" % (len(host_ids), form.vars.asset_group)
        response.headers['web2py-component-command'] = "hosttable.fnReloadAjax();  jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
        return
    elif form.errors:
        response.flash = "Error in form submission"

    return dict(form=form)

@auth.requires_signature()
@auth.requires_login()
def mass_vulndata():
    """
    Add a vulndata to a lot of hosts
    TODO: This!
    """

    host_ids = []
    if request.vars.has_key('host_ids'):
        for z in request.vars.host_ids.split('|'):
            if z is not '':
                host_ids.append(z)
    form=SQLFORM.factory(
        Field('vulndata', 'reference t_vulndata', label=T('Vulnerability')),
        buttons=[], _id="mass_asset_form")

    if form.validate():
        pass

#@auth.requires_signature()
@auth.requires_login()
def launch():
    """
    Launches a terminal session using the Scheduler
    """

    record = request.vars.get('record', None)
    if record is None:
        response.flash = "No record sent to launch"
        return dict()

    #db.scheduler_task.insert(
    #    task_name='launch_%s' % (record),
    #    function_name='launch_terminal',
    #    args=gluon.contrib.simplejson.dumps([record, auth.user.f_launch_cmd]),
    #    timeout = 86400, # 1 day
    #    group_name = settings.scheduler_group_name,
    #    sync_output = 5,
    #)

    task = scheduler.queue_task(
        launch_terminal,
        pargs=[record, auth.user.f_launch_cmd],
        group_name = settings.scheduler_group_name,
        immediate=True,
    )

    if task.id:
        response.flash = "Terminal launch queued!"
    else:
        response.flash = "Error submitting job: %s" % (task.errors)

    return dict()
