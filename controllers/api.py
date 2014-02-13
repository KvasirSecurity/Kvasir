# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## API Library
##
## One of the quirks with JSON-RPC is that function variables must be submitted
## in order as they appear, no assigning them when passing. Thus if the
## function calls for three fields and you only want to pass the second
## field then submit (None, secondvariable, None)
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

__version__ = "1.0"
from skaldship.hosts import get_host_record, create_hostfilter_query
from skaldship.general import cvss_metrics, vuln_data

import logging
logger = logging.getLogger("web2py.app.kvasir")

@auth.requires_login()
def download():
    return response.download(request,db)

@auth.requires_login()
def call():
    #session.forget()
    return service()
### end requires

@service.jsonrpc
def version():
    """Returns the API version number"""
    return __version__

##-------------------------------------------------------------------------
## evidence
##-------------------------------------------------------------------------

@service.jsonrpc
def evidence_list(recid=None):
    """List evidence on a host

Accepts: Record ID, ipv4, ipv6 or hostname or None for all records

Returns: List of evidence records
"""
    record = get_host_record(recid)
    if not record:
        query = db.t_evidence.id > 0
    else:
        query = (db.t_evidence.f_hosts_id == record.id)
    data = db(query).select(cache=(cache.ram,120))

    return [(evidence.id, evidence.f_type, evidence.f_other_type,
             evidence.f_text, evidence.f_evidence, evidence.f_filename) for evidence in data]

##-------------------------------------------------------------------------

@service.jsonrpc
def evidence_download(filename):
    """Download an evidence file

Accepts: filename to download

Returns: f_data blob (base64 decoded, of course)
"""
    row=db(db.t_evidence.f_evidence==filename).select(db.t_evidence.f_data).first()
    if row is None:
        return None

    return row.f_data

##-------------------------------------------------------------------------

@service.jsonrpc
def evidence_del(records=[]):
    """Delete an evidence record id

Accepts: List of record IDs to delete

Returns: [(True/False, message)]
"""
    if not records: return (False, 'No records sent')
    msg = []
    for rec in records:
        try:
            del db.t_evidence[rec]
            msg.append((True, 'Record %s deleted' % (rec)))
        except Exception, e:
            msg.append((False, 'Error: %s' % (e)))

    return msg

##-------------------------------------------------------------------------

@service.jsonrpc
def evidence_add(recid, filename, f_data, f_type, f_other_type=None, f_text=''):
    """Receive evidence file and store in t_evidence.

Accepts: Host ID/IPv4/IPv6/Hostname, filename, data, type, other_type, text

Returns: True/False, Record ID/Message
"""

    if not recid: return (False, 'No record id or IP address')
    if not filename: return (False, 'No filename')
    if not f_data: return (False, 'No data')
    if not f_type: return (False, 'No type')

    record = get_host_record(recid)
    if not record: return (False, 'Invalid record id or IP address')

    try:
        recid = db.t_evidence.insert(f_hosts_id = record.id,
                                     f_filename = filename,
                                     f_evidence = filename,
                                     f_data = f_data,
                                     f_type = f_type,
                                     f_other_type = f_other_type,
                                     f_text = f_text)
        db.commit()
        return (True, recid)
    except Exception, e:
        db.commit()
        return (False, e)

##-------------------------------------------------------------------------
## hosts
##-------------------------------------------------------------------------

@service.jsonrpc
def host_list(hostfilter=(None, None)):
    """Returns a long list of hosts

Accepts: hostfilter=(type, value)"""
    query = (db.t_hosts.id > 0)
    query = create_hostfilter_query(hostfilter, query)

    data = db(query).select(cache=(cache.ram,120))
    return [(host.id, host.f_ipv4, host.f_ipv6, host.f_macaddr, host.f_hostname,
             host.f_netbios_name, db.auth_user[host.f_engineer].username, host.f_asset_group,
             host.f_confirmed) for host in data]

##-------------------------------------------------------------------------

@service.jsonrpc
def host_add(f_ipv4, f_ipv6, f_macaddr, f_hostname, f_netbios_name, f_engineer, f_asset_group, f_confirmed=False):
    """Adding a host

Accepts: ipv4, ipv6, macaddr, hostname, netbios name, engineer name (must exist), asset group, confirmed

Returns: (True/False, Record id or error message)
"""

    if f_ipv4 is None and f_ipv6 is None:
        return (False, "No IPv4 or IPv6 address provided.")

    if  db(db.auth_user.username == f_engineer).count() == 0:
        return (False, "Engineer not found in user database")

    try:
        record_id = db.insert(f_ipv4 = f_ipv4,
                              f_ipv6 = f_ipv6,
                              f_macaddr = f_macaddr,
                              f_hostname = f_hostname,
                              f_netbios_name = f_netbios_name,
                              f_confirmed = f_confirmed,
                              f_engineer = f_engineer,
                              f_asset_group = f_asset_group)
        db.commit()
    except Exception, e:
        db.commit()
        return (False, e)
    return (True, record_id)

##-------------------------------------------------------------------------

@service.jsonrpc
def host_del(hostrec = [], ipv4recs = [], ipv6recs = []):
    """Delete a host or group of hosts.

Accepts: dictionary of host record IDs, IPv4 or IPv6 addresses

Returns: (hostrecs deleted, ipv4 deleted, ipv6 deleted)
"""

    errors = []
    hostrec_deleted = []
    for host in hostrecs:
        try:
            del db.t_hosts[host]
            hostrec_deleted.append(host)
        except Exception, e:
            errors.append(e)
        db.commit()

    ipv4_deleted = []
    for ipv4 in ipv4recs:
        host_id = db(db.t_hosts.f_ipv4 == ipv4).select(cache=(cache.ram,120)).first()
        if host_id is not None:
            del db.t_hosts[host_id]
            ipv4_deleted.append(ipv4)
            db.commit()

    ipv6_deleted = []
    for ipv6 in ipv6recs:
        host_id = db(db.t_hosts.f_ipv6 == ipv6).select(cache=(cache.ram,120)).first()
        if host_id is not None:
            del db.t_hosts[host_id]
            ipv6_deleted.append(ipv6)
            db.commit()

    return (hostrec_deleted, ipv4_deleted, ipv6_deleted, errors)

##-------------------------------------------------------------------------

@service.jsonrpc
def host_info(hostrec):
    """Returns the detail of a host record

Accepts: Host ID/IPv4/IPv6/Hostname

Returns: Host record information
"""
    record = get_host_record(hostrec)

    if record is None:
        return (False, "Host record not found")

    return (True, record.id, record.f_ipv4, record.f_ipv6, record.f_macaddr,
            record.f_hostname, record.f_netbios_name, record.f_engineer,
            record.f_asset_group, record.f_confirmed)

##-------------------------------------------------------------------------

@service.jsonrpc
def host_details(hostrec):
    """Returns the details for htmlreport on a host"""
    record = get_host_record(hostrec)

    if record is None:
        return (False, "Not record not found")

    host = (record.id, record.f_ipv4, record.f_ipv6, record.f_macaddr,
            record.f_hostname, record.f_netbios_name, record.f_asset_group, record.f_confirmed)

    host_points = {}
    # build the host_points field which will cover:
    # the top t_host_os_ref cpe string
    os_list = db(db.t_host_os_refs.f_hosts_id == record.id).select(cache=(cache.ram,120))
    host_points['os'] = (0, 'Unknown')
    for os_rec in os_list:
        if os_rec.f_certainty > host_points['os'][0]:
            host_points['os'] = (os_rec.f_certainty, db.t_os[os_rec.f_os_id].f_title)
            host_points['os_info'] = os_rec.as_dict()

    # number of account(s) / passwords
    # the top 5 nexpid's with exploits
    # the top 5 vulnid's based on high cvss+severity
    host_points['account_cnt'] = 0
    host_points['password_cnt'] = 0
    host_points['vuln_cnt'] = 0
    host_points['vuln_exploited_cnt'] = 0
    host_points['vuln_potential_cnt'] = 0
    vulns = {}
    vuln_list = []
    services = db(db.t_services.f_hosts_id == record.id).select(cache=(cache.ram,120))
    for svc in services:
        for vuln in db(db.t_service_vulns.f_services_id == svc.id).select(cache=(cache.ram,120)):
            vulndata = db.t_vulndata[vuln.f_vulndata_id]
            vulns[vulndata.f_vulnid] = ( vulndata.f_severity, vulndata.f_cvss_score )
            vuln_list.append(vulndata)
        host_points['vuln_exploited_cnt'] += db((db.t_service_vulns.f_services_id==svc.id) & (db.t_service_vulns.f_status.like('%exploited%'))).count()
        host_points['vuln_potential_cnt'] += db((db.t_service_vulns.f_services_id==svc.id) & (db.t_service_vulns.f_status.like('%potential%'))).count()
        host_points['vuln_cnt'] += db(db.t_service_vulns.f_services_id==svc.id).count()
        host_points['account_cnt'] += db(db.t_accounts.f_services_id==svc.id).count()
        host_points['password_cnt'] += db((db.t_accounts.f_services_id==svc.id) & (db.t_accounts.f_password != None)).count()

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
    netb_record = db(db.t_netbios.f_hosts_id == record.id).select(cache=(cache.ram,120)).first() or None
    if netb_record is not None:
        host_points['netb_domain'] = netb_record.f_domain
        host_points['netb_type'] = netb_record.f_type
    else:
        netbios = None

    # services, vulnerabilities and accounts
    services = db(db.t_services.f_hosts_id==record.id).select(db.t_services.id,
                                                              db.t_services.f_proto, db.t_services.f_number, db.t_services.f_status,
                                                              db.t_services.f_name, db.t_services.f_banner, cache=(cache.ram,60))

    service_list = []
    vuln_list = []
    acct_list = []
    for svc in services:
        # service info
        atxt = []
        q = db(db.t_service_info.f_services_id == svc.id).select(cache=(cache.ram,30))
        if len(q) > 0:
            addl = []
            for svcinfo in q:
                addl.append(TR(TD(svcinfo.f_name), TD(svcinfo.f_text)))
            atxt.append(TABLE(THEAD(TR(TH(T('Name')), TH(T('Text')))), TBODY(addl)).xml())
        else:
            atxt.append("")
        atxt.append("%s/%s" % (svc.f_proto, svc.f_number)),
        atxt.append(svc.f_status),
        atxt.append(svc.f_name),
        atxt.append(svc.f_banner),
        service_list.append(atxt)

        # vulnerabilities
        for vulninfo in db(db.t_service_vulns.f_services_id == svc.id).select(cache=(cache.ram,120)):
            atxt = []
            exploit_list = []
            vulndetails = db(db.t_vulndata.id == vulninfo.f_vulndata_id).select(cache=(cache.ram, 300)).first()
            exploits = db(db.t_exploit_references.f_vulndata_id == vulninfo.f_vulndata_id).select(cache=(cache.ram,120))
            if len(exploits) > 0:
                expl_count = "Yes (%d)" % (len(exploits))
                for expl in exploits:
                    for expl_data in db(db.t_exploits.id == expl.f_exploit_id).select(db.t_exploits.f_source, db.t_exploits.f_name, db.t_exploits.f_rank, db.t_exploits.f_level):
                        exploit_list.append("%s :: %s (%s/%s)" % (expl_data.f_source[0], expl_data.f_name, expl_data.f_rank, expl_data.f_level))
            else:
                expl_count = ""

            atxt.append("%s/%s" % (svc.f_proto, svc.f_number))
            atxt.append("%s-%s" % (svc.f_number, svc.f_proto.upper()))
            atxt.append(vulndetails.f_vulnid)
            atxt.append(vulndetails.f_severity)
            atxt.append(vulndetails.f_cvss_score)
            atxt.append(cvss_metrics(vulndetails))
            atxt.append(vulninfo.f_status)
            atxt.append(expl_count)
            atxt.append(MARKMIN(vulninfo.f_proof).xml())
            atxt.append(MARKMIN(vulndetails.f_description).xml())
            atxt.append(vulndetails.f_title)
            atxt.append("<br />\n".join(exploit_list))
            vuln_list.append(atxt)

        # accounts
        for r in db(db.t_accounts.f_services_id == svc.id).select(cache=(cache.ram,30)):
            atxt=[]
            atxt.append("%s/%s" % (svc.f_proto, svc.f_number)),
            atxt.append(r.f_username)
            atxt.append(r.f_fullname)
            atxt.append(r.f_password)
            atxt.append(r.f_hash1_type)
            atxt.append(r.f_hash1)
            atxt.append(r.f_hash2_type)
            atxt.append(r.f_hash2)
            atxt.append(r.f_uid)
            atxt.append(r.f_gid)
            atxt.append(r.f_lockout)
            atxt.append(r.f_duration)
            atxt.append(r.f_source)
            atxt.append(r.f_level)
            atxt.append(r.f_description)

            acct_list.append(atxt)

    # snmp strings
    snmp_list = []
    for snmp in db(db.t_snmp.f_hosts_id==record.id).select(cache=(cache.ram,120)):
        atxt = []
        atxt.append(snmp.f_community)
        atxt.append(snmp.f_version)
        atxt.append(snmp.f_access)

        snmp_list.append(atxt)

    return dict(host=host, host_points=host_points, service_list=service_list,
                acct_list=acct_list, vuln_list=vuln_list, snmp_list=snmp_list)

##-------------------------------------------------------------------------
## services
##-------------------------------------------------------------------------

@service.jsonrpc
def service_list(svc_rec=None, host_rec=None, hostfilter=(None, None)):
    """Returns a specific service or all services

Accepts: Service id, host record (ipv4, ipv6 or id) or hostfilter

Returns: [ service_id, host_id, ipv4, ipv6, hostname, proto, number, status, name, banner, [ vuln list ...] ]
"""
    if svc_rec is not None:
        if type(svc_rec) is type(int):
            query = (db.t_services.id == svc_rec)
        else:
            return []
    elif host_rec is not None:
        host_rec = get_host_record(host_rec)
        if host_rec:
            query = (db.t_services.f_hosts_id == host_rec.id)
        else:
            return []
    else:
        query = (db.t_services.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_services')

    data = db(query).select(cache=(cache.ram,120))

    return [(svc.t_services.id, svc.t_services.f_hosts_id, svc.t_hosts.f_ipv4,
             svc.t_hosts.f_ipv6, svc.t_hosts.f_hostname, svc.t_services.f_proto,
             svc.t_services.f_number, svc.t_services.f_status, svc.t_services.f_name,
             svc.t_services.f_banner) for svc in data]

#--------------------------------------------------------------------------

@service.jsonrpc
def service_list_only(host_rec=None, hostfilter=(None, None)):
    """Returns a list of ports

Accepts: Service id, host record (ipv4, ipv6 or id) or hostfilter

Returns: [ service_id, host_id, ipv4, ipv6, hostname, proto, number, status, name, banner, [ vuln list ...] ]
"""
    if host_rec is not None:
        host_rec = get_host_record(host_rec)
        if host_rec:
            query = (db.t_services.f_hosts_id == host_rec.id)
        else:
            return []
    else:
        query = (db.t_services.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_services')

    data = db(query).select(db.t_services.f_proto, db.t_services.f_number, distinct=True, cache=(cache.ram,120))

    return ["%s/%s" % (svc.f_number, svc.f_proto) for svc in data]

#--------------------------------------------------------------------------

@service.jsonrpc
def service_info(svc_rec=None, ipaddr=None, proto=None, port=None):
    """Returns the information about a service from either a svc_record id or
ip address/port combo. If a port doesn't exist it will add it if insert=True

Returns: [ service_id, host_id, ipv4, ipv6, hostname, proto, number, status, name, banner ]
"""
    if svc_rec:
        rows = db(db.t_services.id == svc_rec).select()
        if rows is not None:
            host_rec = get_host_record(rows[0].f_hosts_id)
        else:
            return []

    else:
        host_rec = get_host_record(ipaddr)
        if host_rec:
            query = (db.t_services.f_hosts_id == host_rec.id)
        else:
            return []
        if proto:
            query &= (db.t_services.f_proto == proto)
        if port:
            query &= (db.t_services.f_number == port)

        rows = db(query).select()

    retval = []
    for row in rows:
        retval.append([
            row.id, host_rec.f_ipv4, host_rec.f_ipv6, host_rec.f_hostname,
            row.f_proto, row.f_number, row.f_status,
            row.f_name, row.f_banner
        ])

    return retval

#--------------------------------------------------------------------------

@service.jsonrpc
def service_add(ipaddr=None, proto=None, port=None, fields={}):
    """Adds a service to the database"""
    host_rec = get_host_record(ipaddr)
    if not host_rec:
        return [False, 'No host record found']
    if not proto:
        return [False, 'No protocol provided']
    if not port:
        return [False, 'No port number provided']

    query = (db.t_services.f_hosts_id == host_rec.id) & (db.t_services.f_proto == proto) & (db.t_services.f_number == port)
    if db(query).count() > 0:
        return [False, 'Service already exists']

    fields.update( {
        'f_hosts_id': host_rec.id,
        'f_number': port,
        'f_proto': proto,
    } )

    try:
        svc_rec = db.t_services.insert(**fields)
    except Exception, e:
        return [False, 'Error inserting service record: %s' % e]

    return [True, svc_rec]

#--------------------------------------------------------------------------

@service.jsonrpc
def service_del(svc_rec=None, ipaddr=None, proto=None, port=None):
    """Deletes a service to the database"""
    host_rec = get_host_record(ipaddr)
    if svc_rec:
        query = (db.t_services.id == svc_rec)
    elif host_rec:
        query = (db.t_services.f_hosts_id == host_rec.id)
        if proto:
            query &= (db.t_services.f_proto == proto)
        if port:
            query &= (db.t_services.f_number == port)

    try:
        count = db(query).delete()
        db.commit()
        return [True, '%s record(s) deleted' % (count)]
    except Exception, e:
        return [False, 'Error: %s' % (e)]

#--------------------------------------------------------------------------

@service.jsonrpc
def service_rpt_index_stats(hostfilter=(None, None)):
    """Returns the services index statistics:

Port, Service Name, Number of Hosts, Unique Vulns, Vuln count
"""

    # builds a Row() of svc_ids and vuln counts, have to match these to
    #
    count = db.t_service_vulns.f_services_id.count()
    svc_id_vulncount = {}

    svc_vuln_q = (db.t_service_vulns.f_services_id == db.t_services.id)
    svc_vuln_q = create_hostfilter_query(hostfilter, svc_vuln_q, 't_services')

    all_svc_q = (db.t_services.id > 0)
    all_svc_q = create_hostfilter_query(hostfilter, all_svc_q, 't_services')

    for d in db(svc_vuln_q).select(db.t_service_vulns.f_services_id, count, groupby=db.t_service_vulns.f_services_id):
        svc_id_vulncount.setdefault(d.t_service_vulns.f_services_id, d._extra['COUNT(t_service_vulns.f_services_id)'])

    data = {}
    for port in db(all_svc_q).select(db.t_services.f_number, db.t_services.f_proto, db.t_services.f_name, distinct=True):
        svc_q = (db.t_services.f_proto == port.f_proto) & (db.t_services.f_number == port.f_number)
        svc_q = create_hostfilter_query(hostfilter, svc_q, 't_services')
        vuln_count = 0
        host_count = 0
        for port_list in db(svc_q).select(db.t_services.id, cache=(cache.ram,120)):
            host_count += 1

        q = svc_q & (db.t_services.id == db.t_service_vulns.f_services_id)
        vuln_count += db(q).count()
        unique_vuln_count = 0
        count = db.t_services.f_hosts_id.count()
        for row in db(q).select(db.t_services.f_hosts_id, count, groupby=db.t_services.f_hosts_id):
            unique_vuln_count = row._extra['COUNT(t_services.f_hosts_id)']

        service = "%s/%s" % (port.f_number, port.f_proto)
        #data.setdefault(service, [])
        data[service] = (
            port.f_name,
            host_count,
            unique_vuln_count,
            vuln_count,
        )

    return data

#--------------------------------------------------------------------------

@service.jsonrpc
def service_report_list(service_id=None, service_port=None, hostfilter=(None, None)):
    """Returns a list of ports with IPs and banners and vulns

    XXX: THIS IS REALLY REALLY REALLY REALLY SLOW!
"""

    query = (db.t_services.id > 0)

    if service_id is not None:
        query &= (db.t_services.id == service_id)

    if service_port is not None:
        number,proto = service_port.split('/')
        query &= (db.t_services.f_number == number) & (db.t_services.f_proto == proto)

    query = create_hostfilter_query(hostfilter, query, 't_services')

    port_dict = {}
    for port in db(query).select(distinct=True, cache=(cache.ram, 120)):
        port_info = "%s/%s" % (port.t_services.f_number, port.t_services.f_proto)
        #host_rec = get_host_record(port.f_hosts_id)
        vuln_list = []
        #for vuln in port.t_service_vulns.select(db.t_service_vulns.ALL, db.t_vulndata.ALL,
        #                                        left=db.t_vulndata.on(db.t_service_vulns.f_vulndata_id==db.t_vulndata.id)):
        for vuln_rec in port.t_services.t_service_vulns.select():
            vulndata = vuln_data(vuln_rec.f_vulndata_id, full=False)
            vuln_list.append((
                vulndata[1],   # f_vulnid
                vulndata[2],   # f_title
                vulndata[3],   # f_severity
                vulndata[4],   # f_cvss_score
            ))
            #vuln_list.append((vuln.t_vulndata.f_vulnid, vuln.t_vulndata.f_title, vuln.t_vulndata.f_severity, vuln.t_vulndata.f_cvss_score))
        port_list = port_dict.setdefault(port_info, [])
        port_dict[port_info].append((port.t_hosts.f_ipv4, port.t_services.f_banner, vuln_list))

    return port_dict

#--------------------------------------------------------------------------

@service.jsonrpc
def service_vulns_list(service_rec=None, service_port=None, hostfilter=(None, None)):
    """Returns a list of vulnerablities for a service

Accepts: Service Record ID

Returns: (True/False, Service info ...)

    XXX: THIS IS REALLY REALLY REALLY REALLY SLOW!
"""

    #from datetime import datetime, timedelta
    #start = datetime.now()
    query = (db.t_service_vulns.f_services_id == db.t_services.id)
    query &= (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)

    if service_rec is not None:
        query &= (db.t_services.id == service_rec)

    if service_port is not None:
        number,proto = service_port.split('/')
        query &= (db.t_services.f_number == number) & (db.t_services.f_proto == proto)

    query = create_hostfilter_query(hostfilter, query, 't_services')

    res = db(query).select(cache=(cache.ram,120))
    #logger.debug("api.service_vulns_list select took %s seconds" % (timedelta.total_seconds(datetime.now() - start)))
    #logger.debug("query = %s" % (db._lastsql))
    #start = datetime.now()
    res = res.as_list()
    #logger.debug("api.service_vulns_list as_list took %s seconds" % (timedelta.total_seconds(datetime.now() - start)))

    return res

#--------------------------------------------------------------------------

@service.jsonrpc
def service_vuln_iptable(hostfilter=(None, None)):
    """Returns a dict of services. Contains a list of IPs with (vuln, sev)

    '0/info': { 'host_id1': [ (ipv4, ipv6, hostname), ( (vuln1, 5), (vuln2, 10) ... ) ] },
              { 'host_id2': [ (ipv4, ipv6, hostname), ( (vuln1, 5) ) ] }

"""

    service_dict = {}
    # go through each t_service_vulns identifier that is unique
    query = (db.t_service_vulns.id > 0) & (db.t_service_vulns.f_services_id == db.t_services.id)
    query = create_hostfilter_query(hostfilter, query, 't_services')

    for service in db(query).select(db.t_service_vulns.f_services_id, groupby=db.t_service_vulns.f_services_id):
        # find all the records with the service_id
        q = (db.t_service_vulns.f_services_id == service.f_services_id)
        q &= (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)

        ip_dict = {}

        # go through each
        for row in db(q).select(cache=(cache.ram,120)):
            svc_rec = db.t_services(row.t_service_vulns.f_services_id)
            port_txt = "%s/%s" % (svc_rec.f_number, svc_rec.f_proto)
            host_rec = get_host_record(svc_rec.f_hosts_id)
            ip_info = ip_dict.setdefault(host_rec.f_ipv4, [])
            if row.t_vulndata.f_vulnid not in map(lambda x: x[0], ip_info):
                ip_info.append((row.t_vulndata.f_vulnid, row.t_vulndata.f_severity, row.t_vulndata.f_cvss_score))
            ip_dict[host_rec.f_ipv4] = ip_info

        for k,v in ip_dict.iteritems():
            service_dict.setdefault(port_txt, dict())
            service_dict[port_txt][k] = v

    return service_dict

##-------------------------------------------------------------------------
## accounts
##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_list(svc_rec=None, hostfilter=(None, None), compromised=False):
    """Returns a list of accounts for a service or host

Accepts: Service id, hostfilter, compromised

Returns: [ service_id, ipv4, ipv6, hostname, account info... ]
"""

    query = (db.t_accounts.f_services_id==db.t_services.id)
    if svc_rec is not None:
        query = (db.t_accounts.f_service_id == svc_rec)
    else:
        query &= (db.t_accounts.id > 0)
    if compromised:
        query &= (db.t_accounts.f_compromised==True)
    query = create_hostfilter_query(hostfilter, query, 't_services')

    accounts = db(query).select(cache=(cache.ram,120))

    data = []
    for acct in accounts:
        data.append([acct.t_accounts.f_services_id, acct.t_hosts.f_ipv4,
                     acct.t_hosts.f_ipv6, acct.t_hosts.f_hostname,
                     acct.t_accounts.id, acct.t_accounts.f_username,
                     acct.t_accounts.f_fullname, acct.t_accounts.f_password,
                     acct.t_accounts.f_compromised, acct.t_accounts.f_hash1,
                     acct.t_accounts.f_hash1_type, acct.t_accounts.f_hash2,
                     acct.t_accounts.f_hash2_type, acct.t_accounts.f_source,
                     acct.t_accounts.f_uid, acct.t_accounts.f_gid,
                     acct.t_accounts.f_level, acct.t_accounts.f_domain,
                     acct.t_accounts.f_message, acct.t_accounts.f_lockout,
                     acct.t_accounts.f_duration, acct.t_accounts.f_active,
                     acct.t_accounts.f_description,
                     acct.t_services.f_proto, acct.t_services.f_number,
                   ])
        '''
        data.append([svc.id, hostrec.f_ipv4, hostrec.f_ipv6, hostrec.f_hostname,
                     acct.id, acct.f_username, acct.f_fullname, acct.f_password,
                     acct.f_compromised, acct.f_hash1, acct.f_hash1_type, acct.f_hash2,
                     acct.f_hash2_type, acct.f_source, acct.f_uid, acct.f_gid,
                     acct.f_level, acct.f_domain, acct.f_message, acct.f_lockout,
                     acct.f_duration, acct.f_active, acct.f_description,
                     svc.f_proto, svc.f_number,
                   ])
        '''
    return data

'''
##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_compromised(service_rec=None, host_rec=None, account_rec=None):
    """Returns the compromised accounts for a service or host"""

    data = []
    query = (db.t_accounts.f_compromised == True)

    record = get_host_record(host_rec)

    if record is not None:
        query &= (db.t_services.f_hosts_id == record.id)
    elif service_rec is not None:
        query &= (db.t_accounts.f_services_id == service_rec)
    else:
        query &= (db.t_services.id == db.t_accounts.f_services_id)

    for rec in db(query).select(cache=(cache.ram,120)):
        hostrec = db(db.t_hosts.id == rec.t_services.f_hosts_id).select(cache=(cache.ram,120)).first()
        data.append([rec.t_services.id, hostrec.f_ipv4, hostrec.f_ipv6, hostrec.f_hostname,
                     rec.t_accounts.id, rec.t_accounts.f_username, rec.t_accounts.f_fullname,
                     rec.t_accounts.f_password, rec.t_accounts.f_compromised, rec.t_accounts.f_hash1,
                     rec.t_accounts.f_hash1_type, rec.t_accounts.f_hash2, rec.t_accounts.f_hash2_type,
                     rec.t_accounts.f_source, rec.t_accounts.f_uid, rec.t_accounts.f_gid,
                     rec.t_accounts.f_level, rec.t_accounts.f_domain, rec.t_accounts.f_message,
                     rec.t_accounts.f_lockout, rec.t_accounts.f_duration, rec.t_accounts.f_active,
                     rec.t_accounts.f_description, rec.t_services.f_proto, rec.t_services.f_number,
                     ])

    return data
'''

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_add(svc_rec, records = []):
    """Adds an account to a service

Accepts: Service record id (reqd), username (reqd), other fields can be empty

Returns: True/False, Error Msg/account_id
"""
    if db(db.t_services.id == svc_rec).count() != 1:
        return (False, 'Service record ID not found')

    if len(records) == 0:
        return (False, 'No records sent to insert')

    result = []
    for rec in records:
        rec['f_services_id'] = svc_rec
        if len(rec) == 0:
            result.append((False, 'No field values sent'))
            continue

        for key in rec.keys():
            if key not in db.t_accounts.fields:
                result.append((False, '%s not a valid field' % (key)))
                continue

        try:
            recid = db.t_accounts.insert(**rec)
            result.append((True, recid))
        except Exception, e:
            result.append((False, e))
        db.commit()

    return (True, result)

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_info(account_rec=None):
    """Returns the data from an account record"""
    acct = db.t_accounts[account_rec]
    if acct is None:
        return (False, "Account record not found")

    svc_rec = db.t_services[acct.f_services_id]
    hostrec = db.t_hosts[svc_rec.f_hosts_id]

    return (True, hostrec.f_ipv4, hostrec.f_ipv6, hostrec.f_hostname,
            svc_rec.f_proto, svc_rec.f_number,
            acct.id, acct.f_username, acct.f_fullname, acct.f_password,
            acct.f_compromised, acct.f_hash1, acct.f_hash1_type, acct.f_hash2,
            acct.f_hash2_type, acct.f_source, acct.f_uid, acct.f_gid,
            acct.f_level, acct.f_domain, acct.f_message, acct.f_lockout,
            acct.f_duration, acct.f_active, acct.f_description
            )

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_update(account_rec=None, values={}):
    """Updates an account record with specific values

Accepts: Service record id (reqd), dictionary of field values

Returns: (True/False, Message)
"""
    if account_rec is None:
        return (False, 'No account ID sent')

    if len(values) == 0:
        return (False, 'No field values sent')

    for key in values.keys():
        if key not in db.t_accounts.fields:
            return (False, '%s not a valid field' % (key))

    if db.t_accounts[account_rec] == None:
        return (False, 'Account ID record not found')

    try:
        db.t_accounts[account_rec] = values
        db.commit()
        return (True, 'Account record %s updated' % (account_rec))
    except Exception, e:
        return (False, 'Error: %s' % (e))

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_del(account_rec=None):
    """Delete an account"""
    if account_rec is None:
        return (False, ['No account record id sent'])

    result = []
    if type(account_rec) == type([]):
        for rec in account_rec:
            try:
                del db.t_accounts[rec]
                result.append("%s record id deleted" % (rec))
            except Exception, e:
                result.append("%s error: %s" % (rec, e))
            db.commit()
    else:
        try:
            del db.t_accounts[account_rec]
            result.append(True, "%s record id deleted" % (rec))
        except Exception, e:
            result.append(False, "%s error: %s" % (rec, e))
        db.commit()

    return result

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_import_file(svc_id=None, host_service=None, filename=None, pw_data=None, f_type=None, add_to_evidence=False):
    """Parses an imported file into account records and adds the file to evidence
if requested.

Accepts: Service record ID, host_service, filename, content of file, add to evidence boolean

Returns: (True/False, Message or dictionary of records/account names added)
"""
    # TODO: test this
    if host_service is not None:
        # we have a host_service combo of (iprecord, (proto, port))
        host_rec = get_host_record(host_service[0])
        if host_rec is None:
            return (False, 'Unable to find host record')

        svc_rec = get_service_rec(host_rec, host_service[1][0], host_service[1][1])
        if svc_rec is not None:
            svc_id = svc_rec.id

    if db(db.t_services.id == svc_id).count() != 1:
        return (False, 'Service record ID not found')

    if filename is None:
        return (False, 'No filename provided')

    if pw_data is None:
        return (False, 'No data provided')

    if f_type is None:
        return (False, 'No password filetype provided')

    from skaldship.passwords import process_password_file, insert_or_update_acct

    account_data = process_password_file(pw_data=pw_data, file_type=f_type)
    resp_text = insert_or_update_acct(svc_id, account_data)

    if add_to_evidence is True:
        # add the password file to evidence
        db.t_evidence.insert( f_hosts_id = db.t_services[svc_id].f_hosts_id,
                              f_type = 'Password File',
                              f_text = f_type,
                              f_filename = filename,
                              f_evidence = filename,
                              f_data = pw_data)
        resp_text += "\n%s added to evidence\n" % (filename)
        db.commit()

    return (True, resp_text)

##-------------------------------------------------------------------------

@service.jsonrpc
def list_pw_types():
    """
    Returns a list of supported password file types
    """
    return settings.password_file_types

##-------------------------------------------------------------------------

@service.jsonrpc
def accounts_index_data(hostfilter=(None, None)):
    """Returns a list of IP address and account statistics.
A compromised account is when the Password is not None"""
    query = (db.t_accounts.f_services_id==db.t_services.id)
    query = create_hostfilter_query(hostfilter, query, 't_services')
    data = {}
    for acct in db(query).select(cache=(cache.ram,120)):
        ipv4 = db.t_hosts[acct.t_services.f_hosts_id].f_ipv4
        data.setdefault(ipv4, {'discovered':0, 'compromised':0})
        data[ipv4]['discovered'] += 1
        if acct.t_accounts.f_password is not None:
            data[ipv4]['compromised'] += 1

    return data

##-------------------------------------------------------------------------
## SNMP
##-------------------------------------------------------------------------

@service.jsonrpc
def snmp_list_communities():
    """Returns a list of all known SNMP community strings

Accepts: None

Returns: [ string, string, string ...]
"""
    data = []
    for snmp in db(db.t_snmp).select(db.t_snmp.f_community, distinct=True):
        data.append(snmp.f_community)

    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def snmp_list(snmpstring=None, hostfilter=(None, None)):
    """Returns a list of SNMP information for a host

Accepts: Record id, IPv4, IPv6 or Hostname - if not found return nothing

Returns: [ [ record_id, ipv4, ipv6, hostname, community, access, version ] ... ]
"""
    query = (db.t_snmp.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_snmp')

    if snmpstring is not None:
        query &= (db.t_snmp.f_community == snmpstring)

    data = []
    for snmp in db(query).select(cache=(cache.ram,120)):
        data.append([snmp.t_snmp.id, snmp.t_hosts.f_ipv4, snmp.t_hosts.f_ipv6, snmp.t_hosts.f_hostname,
                     snmp.t_snmp.f_community, snmp.t_snmp.f_access, snmp.t_snmp.f_version])

    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def snmp_rpt_table(hostfilter=(None, None)):
    """Returns an array of tuples containing (communitystring, count_of_ips_with_string, perm)"""

    query = (db.t_snmp.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_snmp')

    results={}
    for snmp in db(query).select(cache=(cache.ram,120)):
        (junk, count, perm) = results.get(snmp.t_snmp.f_community, ("", 0, "READ"))
        if perm != 'WRITE' and snmp.t_snmp.f_access == 'WRITE':
            perm = 'WRITE'
        results[snmp.t_snmp.f_community] = (snmp.t_snmp.f_community, count+1, perm)
    return results.values()

##-------------------------------------------------------------------------

@service.jsonrpc
def snmp_add(hostrec=None, f_community=None, f_access=None, f_version=None):
    """Adds an SNMP record to a host

Accepts: Record id, IPv4, IPv6 or Hostname - if not found return nothing

Returns: ( True/False, record id )
"""
    record = get_host_record(hostrec)

    if record is None:
        return (False, 'Host record not found')

    if (not f_community) or (not f_access) or (not f_version):
        return (False, 'Community, access or version not specified')

    if f_access.lower() not in ['read', 'write']:
        return (False, 'Access can only be READ or WRITE')

    if f_version.lower() not in ['v1', 'v2c', 'v3']:
        return (False, 'Version can only be v1, v2c or v3')

    recid = db.t_snmp.insert(f_hosts_id=record.id, f_community=f_community,
                             f_access=f_access.upper(), f_version=f_version.lower())
    db.commit()

    if recid > 0:
        return (True, recid)
    else:
        return (False, 'Unable to insert record into database')

##-------------------------------------------------------------------------

@service.jsonrpc
def snmp_del(snmp_rec=None):
    """Delete an SNMP record

Accepts: Single or list of SNMP record ids

Returns: ( True/False, message )
"""
    if snmp_rec is None:
        return (False, ['No record id sent'])

    result = []
    if type(snmp_rec) == type(list()):
        for rec in snmp_rec:
            try:
                del db.t_snmp[rec]
                result.append((True, "%s record deleted" % (rec)))
            except Exception, e:
                result.append((False, "%s error: %s" % (rec, e)))
            db.commit()
    else:
        try:
            del db.t_snmp[snmp_rec]
            result = (True, "%s record deleted" % (snmp_rec))
        except Exception, e:
            result = (False, "%s error: %s" % (snmp_rec, e))
        db.commit()

    return result

##-------------------------------------------------------------------------
## Vulnerabilities
##-------------------------------------------------------------------------

@service.jsonrpc
def vuln_list(host_rec = None, svc_rec = None, hostfilter=(None, None)):
    """Returns a list of Vulnerabilities known to a host, a service or
all known Vulnerabilities

Accepts: host record (id, ipv4, ipv6, hostname), service_id or None for all

Returns: [ ( vulndata ... ) ... ]

If the entire list is desired then it returns:

    [ (vulndata ... vuln_cnt, [ list_of_vuln_ips ], [ services ]) ... ]

TODO: SPEEDUP!
"""
    #vuln_start = datetime.now()
    data = []
    if host_rec is not None:
        # build query of all services and hosts using hostfilter
        svc_query = (db.t_services.f_hosts_id == host_rec)

        # pull all the services and vulnerabilities for this host
        for svc in db(svc_query).select(cache=(cache.ram,120)):
            for vuln in svc.t_services.t_service_vulns.select(cache=(cache.ram,120)):
                data.append((vuln_data(vuln.f_vulndata_id, full=True),
                             svc.t_services.f_proto,
                             svc.t_services.f_number,
                             svc.t_services.f_name,
                             ))

        #logger.debug("api.vuln_list with host_reccompleted in %s seconds" % (timedelta.total_seconds(datetime.now() - vuln_start)))
        return data

    if svc_rec is not None:
        query = (db.t_service_vulns.f_services_id == svc_rec) & (db.t_service_vulns.f_vulndata_id==db.t_vulndata.id)
        for vuln in db(query).select(cache=(cache.ram,120)):
            data.append((vuln_data(vuln.t_vulndata, full=True)))
        #logger.debug("api.vuln_list with svc_rec completed in %s seconds" % (timedelta.total_seconds(datetime.now() - vuln_start)))
    else:
        count = db.t_service_vulns.f_vulndata_id.count()
        #services = []
        query = (db.t_service_vulns.id > 0) & (db.t_service_vulns.f_services_id == db.t_services.id)
        query = create_hostfilter_query(hostfilter, query, 't_services')
        for vuln in db(query).select(db.t_service_vulns.f_vulndata_id, count, groupby=(db.t_service_vulns.f_vulndata_id), distinct=True):
            vulndata = vuln_data(vuln.t_service_vulns.f_vulndata_id, full=True)
            vulndata += tuple([str(vuln[count])])
            vulndata += tuple([vuln_ip_info(vuln_id = vuln.t_service_vulns.f_vulndata_id, ip_list_only=False, hostfilter=hostfilter)])
            data.append(vulndata)

        #logger.debug("api.vuln_list with hostfilter completed in %s seconds" % (timedelta.total_seconds(datetime.now() - vuln_start)))
    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def vuln_info(vuln_name = None, vuln_id = None):
    """Returns information about a vulnerability"""
    data = []

    query = (db.t_service_vulns.f_services_id == db.t_services.id) & (db.t_services.f_hosts_id == db.t_hosts.id)
    if vuln_name is not None:
        vuln_rec = db(db.t_vulndata.f_vulnid == vuln_name).select(cache=(cache.ram,120)).first()
        if vuln_rec is None:
            return ["Vulnerability %s not found" % (vuln_name)]

    elif vuln_id is not None:
        vuln_rec = db.t_vulndata[vuln_id]
        if vuln_rec == None:
            return ["Vulnerability ID %s not found" % (vuln_id)]

    return vuln_data(vuln_rec, full=True)

##-------------------------------------------------------------------------

@service.jsonrpc
def vuln_ip_info(vuln_name = None, vuln_id = None, ip_list_only=True, hostfilter=(None, None)):
    """Returns a list of all IP addresses with a vulnerability and their proof/status

If ip_list_only is false then adds proof and status
"""
    from gluon.contrib.markmin.markmin2html import markmin2html
    data = []

    query = (db.t_service_vulns.f_services_id == db.t_services.id)
    query = create_hostfilter_query(hostfilter, query, 't_services')
    if vuln_name is not None:
        vuln_rec = db(db.t_vulndata.f_vulnid == vuln_name).select(cache=(cache.ram, 60)).first()
        if vuln_rec is None:
            return ["Vulnerability %s not found" % (vuln_name)]
        query &= (db.t_service_vulns.f_vulndata_id == vuln_rec.id)

    elif vuln_id is not None:
        if db.t_vulndata[vuln_id] == None:
            return ["Vulnerability ID %s not found" % (vuln_id)]
        query &= (db.t_service_vulns.f_vulndata_id == vuln_id)

    for row in db(query).select(cache=(cache.ram, 60)):
        if row.t_hosts.f_ipv4 not in data and ip_list_only:
            data.append(row.t_hosts.f_ipv4, row.t_hosts.f_ipv6, row.t_hosts.f_hostname)
        else:
            data.append((row.t_hosts.f_ipv4, row.t_hosts.f_ipv6, row.t_hosts.f_hostname, markmin2html(row.t_service_vulns.f_proof), markmin2html(row.t_service_vulns.f_status)))

    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def vuln_service_list(vuln_name = None, vuln_id = None, hostfilter=(None, None)):
    """Returns a list of services and IPs vulnerability has been found on:

'vuln-id': {'port1': [ (ipv4, ipv6, hostname ),
                       (ipv4, ipv6, hostname ) ]},
           {'port2': [ (ipv4, ipv6, hostname ) ]}

"""

    vulndata = db(db.t_vulndata).select(cache=(cache.ram,120)).as_dict()
    query = (db.t_service_vulns.f_services_id == db.t_services.id)
    query = create_hostfilter_query(hostfilter, query, 't_services')

    if vuln_name is not None:
        vuln_rec = db(db.t_vulndata.f_vulnid == vuln_name).select(cache=(cache.ram,120)).first()
        if vuln_rec is None:
            return ["Vulnerability %s not found" % (vuln_name)]
        query &= (db.t_service_vulns.f_vulndata_id == vuln_rec.id)

    elif vuln_id is not None:
        if db.t_vulndata[vuln_id] == None:
            return ["Vulnerability ID %s not found" % (vuln_id)]
        query &= (db.t_service_vulns.f_vulndata_id == vuln_id)

    data = {}
    for row in db(query).select(cache=(cache.ram,120)):
        port = "%s/%s" % (row.t_services.f_number, row.t_services.f_proto)
        host_rec = get_host_record(row.t_services.f_hosts_id)
        host_list = [(host_rec.f_ipv4, host_rec.f_ipv6, host_rec.f_hostname)]
        vulnid = db.t_vulndata[row.t_service_vulns.f_vulndata_id].f_vulnid

        port_dict = data.setdefault(vulnid, {})
        hlist = port_dict.setdefault(port, [])
        if host_list not in hlist:
            hlist.append(host_list)
        else:
            hlist = host_list
        port_dict[port] = hlist
        data[vulnid] = port_dict

    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def vuln_count(svc_rec = None, host_rec = None):
    """Returns a count of vulnerabilities per service. If a service/host is provided then
adds unique count

XXX: This isn't complete
"""

    vulncount = {}

    if host_rec is not None:
        record = get_host_record(host_rec)
        if record is None:
            return []

        # pull all the services and vulnerabilities for this host
        host_vulncount = 0
        for svc in db(db.t_services.f_hosts_id == record.id).select(cache=(cache.ram,120)):
            query = (db.t_service_vulns.f_services_id == svc.id) & (db.t_service_vulns.f_vulndata_id==db.t_vulndata.id)
            host_vulncount += db(query).select(cache=(cache.ram,120)).count()

    if svc_rec is not None:
        query = (db.t_service_vulns.f_services_id == svc_rec) & (db.t_service_vulns.f_vulndata_id==db.t_vulndata.id)
        svc_vulncount = db(query).select(cache=(cache.ram,120)).count()
    else:
        vulncount = db(db.t_service_vulns).select(cache=(cache.ram,120)).count()

##-------------------------------------------------------------------------
## Operating Systems
##-------------------------------------------------------------------------

@service.jsonrpc
def os_list(hostfilter=(None, None)):
    """Returns the Operating Systems for a host or all OS records and hosts

Accepts: hostfilter

Returns: [ ( ipv4, ipv6, hostname, os records... ) ... ]
"""
    data = []
    query = (db.t_host_os_refs.f_hosts_id == db.t_hosts.id)
    query = create_hostfilter_query(hostfilter, query)

    for os_ref_rec in db(query).select(cache=(cache.ram,120)):
        os_rec = db.t_os[os_ref_rec.t_host_os_refs.f_os_id]
        data.append([os_ref_rec.t_hosts.f_ipv4,
                     os_ref_rec.t_hosts.f_ipv6,
                     os_ref_rec.t_hosts.f_hostname,
                     os_ref_rec.t_host_os_refs.f_certainty,
                     os_ref_rec.t_host_os_refs.f_class,
                     os_ref_rec.t_host_os_refs.f_family,
                     os_rec.f_cpename,
                     os_rec.f_title,
                     os_rec.f_vendor,
                     os_rec.f_product,
                     os_rec.f_version,
                     os_rec.f_update,
                     os_rec.f_edition,
                     os_rec.f_language
                     ])

    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def os_report_list(hostfilter=(None, None)):
    """Returns a list of hosts and their top operating systems"""

    os_q = (db.t_host_os_refs.f_hosts_id == db.t_hosts.id)
    host_q = create_hostfilter_query(hostfilter)

    os_recs = db(os_q).select(cache=(cache.ram,120))
    data = []
    for host_rec in db(host_q).select(cache=(cache.ram,120)):
        highest = (0, None)
        for row in os_recs.find(lambda row: row.t_hosts.id == host_rec.id):
            if row.t_host_os_refs.f_certainty > highest[0]:
                highest = (row.t_host_os_refs.f_certainty, row)

        if highest[0] > 0:
            os_rec = db.t_os(highest[1].t_host_os_refs.f_os_id)
            data.append([row.t_hosts.id,
                         row.t_hosts.f_ipv4,
                         row.t_hosts.f_ipv6,
                         row.t_hosts.f_hostname,
                         highest[1].t_host_os_refs.f_certainty,
                         highest[1].t_host_os_refs.f_class,
                         highest[1].t_host_os_refs.f_family,
                         os_rec.f_cpename,
                         os_rec.f_title,
                         os_rec.f_vendor,
                         os_rec.f_product,
                         os_rec.f_version,
                         os_rec.f_update,
                         os_rec.f_edition,
                         os_rec.f_language
                         ])
    return data

##-------------------------------------------------------------------------
## NetBIOS
##-------------------------------------------------------------------------

@service.jsonrpc
def netbios_list(hostfilter=(None, None)):
    """Returns a list of NetBIOS workgroups/domains for an IP (or all IPs)"""
    data = []
    query = (db.t_netbios.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_netbios')

    for rec in db(query).select(cache=(cache.ram,120)):
        data.append((rec.t_hosts.f_ipv4, rec.t_hosts.f_ipv6, rec.t_hosts.f_hostname,
                     rec.t_netbios.f_type, rec.t_netbios.f_advertised_names,
                     rec.t_netbios.f_domain, rec.t_netbios.f_lockout_limit,
                     rec.t_netbios.f_lockout_duration, rec.t_netbios.f_shares))
    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def netbios_rpt_table(hostfilter=(None, None)):
    """Returns a list of domains and host count"""
    data = []
    query = (db.t_netbios.id > 0)
    query = create_hostfilter_query(hostfilter, query, 't_netbios')

    count = db.t_netbios.f_domain.count()
    for rec in db(query).select(db.t_netbios.f_domain, count, groupby=db.t_netbios.f_domain, distinct=True):
        data.append((rec.t_netbios.f_domain, rec[count]))
    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def netbios_domain_members(domain=None, hostfilter=(None, None)):
    """Returns a list of domain member IP addresses"""
    data = []
    q = (db.t_netbios.f_domain == domain) & (db.t_netbios.f_hosts_id == db.t_hosts.id)
    q = create_hostfilter_query(hostfilter, q, 't_netbios')
    for rec in db(q).select(cache=(cache.ram,120)):
        data.append(rec.t_hosts.f_ipv4)
    return data

##-------------------------------------------------------------------------

@service.jsonrpc
def netbios_domain_controllers(domain=None, hostfilter=(None, None)):
    """Returns a list of domain controller IPs"""
    data = []
    q = (db.t_netbios.f_domain == domain) & (db.t_netbios.f_hosts_id == db.t_hosts.id)
    q = create_hostfilter_query(hostfilter, q, 't_netbios')
    for rec in db(q).select(cache=(cache.ram,120)):
        if rec.t_netbios.f_type == "PDC" or rec.t_netbios.f_type == "BDC":
            data.append(rec.t_hosts.f_ipv4)
    return data

##-------------------------------------------------------------------------
## DB Table Counts
##-------------------------------------------------------------------------

@service.jsonrpc
def tbl_count(tables = [], hostfilter=(None, None)):
    """Returns the record count of a database or list of dbs"""

    if type(tables) == type(list()):
        data = {}
        for table in tables:
            if table in db:
                query = db[table].id > 0
                query = create_hostfilter_query(hostfilter, query, table)
                data[table] = db(query).count()
        return data
    else:
        if tables in db:
            query = db[tables].id > 0
            query = create_hostfilter_query(hostfilter, query, tables)
            cnt = db(query).count()
            return cnt
        else:
            return 0


##-------------------------------------------------------------------------
## Scanner Import
##-------------------------------------------------------------------------

@service.jsonrpc
def scanner_import(filename=None, filetype='', background=False, asset_group=None, engineer=1, msf_workspace=None, update_hosts=True):
    """Imports a Scanner output file"""

    if not filename:
        return dict(error="No filename provided")

    if filetype.lower() not in ['nexpose', 'nmap', 'qualys']:
        return dict(error="Invalid scanner type")

    if not asset_group:
        return dict(error="No asset group defined")

    if background:
        task_id = db.scheduler_task.insert(
            status='QUEUED',
            application_name=request.application,
            task_name='scanner_import_%s' % (os.path.basename(filename)),
            function_name='scanner_import',
            vars=gluon.contrib.simplejson.dumps({
                'scanner': filetype,
                'filename': filename,
                'asset_group': asset_group,
                'engineer': engineer,
                'msf_workspace': msf_workspace,
                'ip_ignore_list': None,
                'ip_include_list': None,
                'update_hosts': update_hosts,
            }),
            enabled=True,
            start_time = request.now,
            stop_time = request.now+datetime.timedelta(hours=1),
            repeats = 1, # never repeat
            period = 60, # only do it once
            timeout = 3600, # 1 hour in length
            group_name = settings.scheduler_group_name,
            sync_output = 5,
        )
        response = "Scan file import schedule initiated"
    else:
        if filetype.lower() == 'nexpose':
            from skaldship.nexpose import process_xml
            response = process_xml(
                filename=filename,
                asset_group=asset_group,
                engineer=engineer,
                msf_workspace=msf_workspace,
                ip_ignore_list=None,
                ip_include_list=None,
                update_hosts=update_hosts,
            )
        if filetype.lower() == "nmap":
            from skaldship.nmap import process_xml
            response = process_xml(
                filename=filename,
                addnoports=form.vars.f_addnoports,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_workspace=form.vars.f_msf_workspace,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )

    return dict(response=response)
