# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Statistical functions
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from StringIO import StringIO

from gluon import current
from skaldship.hosts import create_hostfilter_query
from skaldship.general import severity_mapping

import logging
logger = logging.getLogger("web2py.app.kvasir")

def vulnlist(qstr="%", hostfilter=None):
    """
    Returns a vulnerability dictionary with counts:

    :param qstr: Vulnerability identity for .like()
    :param hostfilter: A valid hostfilter or None
    :returns dict: { 'vulnerability id': [ status, count, severity, cvss ] }
    """

    db = current.globalenv['db']
    session = current.globalenv['session']

    status = db.t_service_vulns.f_status
    svcv_id = db.t_service_vulns.id
    vulnid = db.t_vulndata.id
    f_vulnid = db.t_vulndata.f_vulnid
    sev = db.t_vulndata.f_severity
    cvss = db.t_vulndata.f_cvss_score

    hostfilter = hostfilter or session.hostfilter

    query = db.t_vulndata.f_vulnid.like(qstr)
    query &= (db.t_service_vulns.f_services_id == db.t_services.id) & (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)
    query = create_hostfilter_query(hostfilter, query, 't_services')
    #query = (db.t_service_vulns.f_vulndata_id == db.t_vulndata.id)

    vulnlist = {}
    for rec in db(query).select(status, vulnid, f_vulnid, svcv_id, sev, cvss):
        q2 = (query & ((db.t_service_vulns.f_vulndata_id == rec.t_vulndata.id) &
             (db.t_service_vulns.f_status == rec.t_service_vulns.f_status)))
        count = db(q2).count()
        vstats = vulnlist.setdefault(rec.t_vulndata.f_vulnid, list())
        if rec.t_service_vulns.f_status not in map(lambda a:a[0], vstats):
            vstats.append([rec.t_service_vulns.f_status,
                            count,
                            rec.t_vulndata.f_severity,
                            rec.t_vulndata.f_cvss_score
                         ] )
            vulnlist[rec.t_vulndata.f_vulnid] = vstats

    return vulnlist

##-------------------------------------------------------------------------

def db_statistics():
    """
    Returns a dictionary of database statistics
    """
    db = current.globalenv['db']
    cache = current.globalenv['cache']

    svulns = db.t_service_vulns
    svcs = db.t_services
    vd = db.t_vulndata
    osdb = db.t_os
    accts = db.t_accounts
    hosts = db.t_hosts

    statistics = {}
    statistics['os_count'] = db(osdb).count()
    statistics['vulndata_count'] = db(vd).count()
    statistics['accounts'] = db(accts).count()
    statistics['compromised_accounts'] = db(accts.f_compromised == True).count()
    #pwq = (((accts.f_password != None) | (accts.f_password != '')) | (accts.f_compromised == True))
    statistics['passwords'] = db(accts.f_compromised==True).count()
    statistics['joe'] = db(accts.f_username == db.t_accounts.f_password).count()
    statistics['hosts'] = db(hosts).count()
    statistics['hosts_confirmed'] = db(hosts.f_confirmed == True).count()
    statistics['hosts_unconfirmed'] = db(hosts.f_confirmed == False).count()
    statistics['hosts_accessed'] = db(hosts.f_accessed == True).count()

    # XXX: Can this be turned into a db query to speed things up? It's awfully slow
    # generate count of hosts with a vulnerability. Have to tie db.t_service_vulns to
    # a db.t_services record
    service_vulns = db(svulns).select(
        svulns.f_services_id, svulns.f_vulndata_id, svcs.id, svcs.f_hosts_id,
        left=svcs.on(svulns.f_services_id == svcs.id),
        distinct=True,
    )
    vulnhosts = []
    for service in service_vulns:
        hostid = [service.t_services.f_hosts_id]
        if hostid not in vulnhosts:
            vulnhosts.append(hostid)

    # get host count of those with a sev >= 8
    statistics['high_vuln_host_count'] = 0
    if current.globalenv['settings'].use_cvss:
        maxhostsev = vd.f_cvss_score.max()
    else:
        maxhostsev = vd.f_severity.max()
    q = (svulns.f_services_id == db.t_services.id) & (vd.id == svulns.f_vulndata_id)
    for rec in db(q).select(maxhostsev, svcs.f_hosts_id, orderby=svcs.f_hosts_id, groupby=svcs.f_hosts_id):
        if rec[maxhostsev] >= 8:
            statistics['high_vuln_host_count'] += 1

    statistics['vuln_host_count'] = len(vulnhosts)
    if statistics['hosts'] > 0:
        statistics['vuln_host_pct'] = "%.2f%%" % (float(float(len(vulnhosts)) / float(statistics['hosts'])) * 100)
    else:
        statistics['vuln_host_pct'] = "0%"

    if statistics['hosts'] > 0:
        statistics['high_vuln_host_pct'] = "%.2f%%" % (float(float(statistics['high_vuln_host_count']) / float(statistics['hosts'])) * 100)
    else:
        statistics['high_vuln_host_pct'] = "0%"

    statistics['services'] = db(svcs).count()
    statistics['service_vulns'] = db(svulns).count()
    statistics['services_with_vulns'] = len(db(svulns).select(svulns.f_services_id,groupby=svulns.f_services_id))
    if current.globalenv['settings'].use_cvss:
        statistics['services_with_high_vulns'] = db((svulns.f_vulndata_id == vd.id) & (vd.f_cvss_score >= 8)).count()
    else:
        statistics['services_with_high_vulns'] = db((svulns.f_vulndata_id == vd.id) & (vd.f_severity >= 8)).count()
    #statistics['services_with_high_vulns'] = len(db(vd.f_severity >= 8).select(
    #    svulns.f_services_id, svulns.f_vulndata_id, vd.id,
    #    left=svulns.on(vd.id == svulns.f_vulndata_id), groupby=svulns.f_services_id|svulns.f_vulndata_id|vd.id
    #))

    return statistics

##-------------------------------------------------------------------------

def adv_db_statistics():
    """
    Returns a dictionary of Advance database statistics
    """

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    statistics = {}

    #Netbios stats
    domains = []
    for rec in db(db.t_netbios).select(db.t_netbios.f_domain,distinct=True):
        if rec.f_domain:
            domains.append(rec.f_domain)
    statistics['domains'] = domains

    #Account stats
    rootquery = db((db.t_accounts.f_username=='root') & (db.t_accounts.f_compromised==True)).count()
    statistics['ROOT'] = rootquery
    adminquery=((db.t_accounts.f_username=='Administrator')|(db.t_accounts.f_uid==500)) & (db.t_accounts.f_compromised==True)
    statistics['Administrator'] = db(adminquery).count()
    userquery=(db.t_accounts.f_username!='Administrator')&(db.t_accounts.f_username!='root')&(db.t_accounts.f_uid!=500)&(db.t_accounts.f_uid!=0)
    statistics['USER'] = db(userquery  & (db.t_accounts.f_compromised==True)).count()

    #SNMP Stats
    statistics['SNMP_read'] = db(db.t_snmp.f_access=='READ').count()
    statistics['SNMP_write'] = db(db.t_snmp.f_access=='WRITE').count()
    #statistics['services_with_vulns'] = len(db(db.t_service_vulns.f_services_id).select(db.t_service_vulns.f_services_id,groupby=db.t_service_vulns.f_services_id))

    #Top services'
    #for rec in db(db.t_netbios).select(db.t_services.f_proto,distinct=True):
    #    statistics['domains'] = statistics['domains'] + ' ' + rec.f_domain

    return statistics

##-------------------------------------------------------------------------

def graphs_index():
    db = current.globalenv['db']
    cache = current.globalenv['cache']

    graph = {}

    host_by_sev = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    if current.globalenv['settings'].use_cvss:
        maxhostsev = db.t_vulndata.f_cvss_score.max()
    else:
        maxhostsev = db.t_vulndata.f_severity.max()

    q = (db.t_service_vulns.f_services_id == db.t_services.id) & (db.t_vulndata.id == db.t_service_vulns.f_vulndata_id)
    for rec in db(q).select(maxhostsev, db.t_services.f_hosts_id, orderby=db.t_services.f_hosts_id, groupby=db.t_services.f_hosts_id):
        host_by_sev[int(rec[maxhostsev])] += 1

    graph['top_host_sev_count'] = ''
    cnt = 0
    for h_rec in host_by_sev:
        graph['top_host_sev_count'] = graph['top_host_sev_count'] + "{ name: 'Sev %s', color: '%s', y: %d},\n" % (cnt, severity_mapping(cnt)[2], h_rec)
        cnt += 1
    graph['top_host_sev_count_raw'] = host_by_sev

    vuln_by_sev = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    count = db.t_vulndata.id.count()
    if current.globalenv['settings'].use_cvss:
        rows = db(db.t_vulndata.id == db.t_service_vulns.f_vulndata_id).select(
            db.t_vulndata.f_cvss_score, count, orderby=db.t_vulndata.f_cvss_score, groupby=db.t_vulndata.f_cvss_score)
    else:
        rows = db(db.t_vulndata.id == db.t_service_vulns.f_vulndata_id).select(
            db.t_vulndata.f_severity, count, orderby=db.t_vulndata.f_severity, groupby=db.t_vulndata.f_severity)
    for rec in rows:
        if current.globalenv['settings'].use_cvss:
            if rec.t_vulndata.f_cvss_score is not None:
                vuln_by_sev[int(rec.t_vulndata.f_cvss_score)] += rec[count]
            else:
                # no CVSS score in record (val: None)
                vuln_by_sev[0] += rec[count]
        else:
            if rec.t_vulndata.f_severity is not None:
                vuln_by_sev[rec.t_vulndata.f_severity] = rec[count]
            else:
                # no Severity score in record (val: None)
                vuln_by_sev[0] = rec[count]

    graph['vuln_by_sev_count'] = ''
    graph['vuln_by_sev_count_raw'] = vuln_by_sev
    cnt = 0
    for h_rec in vuln_by_sev:
        graph['vuln_by_sev_count'] += "{ name: 'Sev %s', color: '%s', y: %d},\n" % (
        cnt, severity_mapping(cnt)[2], h_rec)
        cnt += 1

    return graph

