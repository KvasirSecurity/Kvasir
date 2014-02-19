# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Statistics controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import severity_mapping
from skaldship.hosts import create_hostfilter_query
from skaldship.statistics import db_statistics, adv_db_statistics, graphs_index

import logging
logger = logging.getLogger("web2py.app.kvasir")


@auth.requires_login()
def index():
    """
    Index statistics page, shows all graphs (jqPlot) and vuln stats
    through LOAD pages.
    """
    response.title = "%s :: Statistics Home" % (settings.title)
    return dict()

@auth.requires_login()
def vulnlist():
    """
    Produces a list of vulnerabilities with severity, cvss and count.
    """
    from skaldship.statistics import vulnlist

    vulnid = request.args(0) or "%"
    vulnlist = vulnlist(query=vulnid)

    response.title = "%s :: Vulnerability Statistics" % (settings.title)
    return dict(vulnlist=vulnlist)#, statistics=statistics, adv_stats=adv_stats)

@auth.requires_login()
def passwords():
    """
    Password statistics
    """
    try:
        toplimit = int(request.args(0))
    except:
        toplimit = 15

    from collections import defaultdict

    #hash_types = db(db.t_accounts.id > 0).select(db.t_accounts.f_hash1_type, groupby=db.t_accounts.f_hash1_type).as_dict(key='f_hash1_type')
    #for htype in hash_types.keys():
    #    pass

    hash_cnt = db.t_accounts.f_hash1_type.count()
    hash_stats = db(db.t_accounts.id > 0).select(db.t_accounts.f_hash1_type, hash_cnt, groupby=db.t_accounts.f_hash1_type)

    pw_cnt = db.t_accounts.f_password.count()
    top = db(db.t_accounts.f_password != None).select(db.t_accounts.f_password, pw_cnt, groupby=db.t_accounts.f_password, orderby=~pw_cnt, limitby=(0,toplimit))

    top_sparx_table = []
    top_sparx_table.append("""
    <table>
    <title>Top 10 Passwords</title>
    <tgroup cols="2">
      <thead>
        <row>
          <entry>Password</entry>
          <entry>Count</entry>
        </row>
      </thead>

      <tbody>
""")
    for z in top:
        top_sparx_table.append("""
        <row>
            <entry>%s</entry>
            <entry>%s</entry>
        </row>
""" % (z.t_accounts.f_password, z._extra['COUNT(t_accounts.f_password)']))
    top_sparx_table.append("</tbody>\n</tgroup>\n</table>")

    from skaldship.passwords import password_class_stat
    pwlenstats = defaultdict(lambda: 0)
    pwstats = defaultdict(lambda: 0)
    passwords = db(db.t_accounts.f_compromised==True).select(db.t_accounts.f_password, cache=(cache.ram, 60))
    for (pw_lenstat, character_class, record) in password_class_stat(passwords):
        pwlenstats[pw_lenstat] += 1
        pwstats[character_class] += 1

    pwstats_sparx_table = []
    pwstats_sparx_table.append("""
    <table>
    <title>Password Type Statistics</title>
    <tgroup cols="2">
      <thead>
        <row>
          <entry>Password Type / Example</entry>
          <entry>Count</entry>
        </row>
      </thead>

      <tbody>
""")
    for z in pwstats:
        pwstats_sparx_table.append("""
        <row>
            <entry>%s</entry>
            <entry>%s</entry>
        </row>
""" % (z, pwstats[z]))
    pwstats_sparx_table.append("</tbody>\n</tgroup>\n</table>")

    response.title = "%s :: Password Statistics" % (settings.title)

    return dict(
        hash_stats=hash_stats,
        top=top,
        top_sparx_table=top_sparx_table,
        pwlenstats=pwlenstats,
        pwstats=pwstats,
        pwstats_sparx_table=pwstats_sparx_table
    )

@auth.requires_login()
def os():
    """
    Operating system statistics
    """

    hostfilter = session.hostfilter
    if hostfilter is None:
        # if no filter is set then we blank it out
        if session.hostfilter is None:
            session.hostfilter = [(None, None), False]

    q = create_hostfilter_query(session.hostfilter)

    rows = db(q).select(db.t_hosts.id, db.t_host_os_refs.f_certainty, db.t_os.f_title, db.t_os.f_vendor,
                        db.t_host_os_refs.f_family, db.t_host_os_refs.f_class,
                        left=(db.t_host_os_refs.on(db.t_hosts.id==db.t_host_os_refs.f_hosts_id),
                              db.t_os.on(db.t_os.id==db.t_host_os_refs.f_os_id)),
                        orderby=db.t_hosts.id|~db.t_host_os_refs.f_certainty, cache=(cache.ram, 60))

    seen = set()
    os_counts = {}
    vendor_counts = {}
    family_counts = {}
    class_counts = {}
    for r in rows:
        if r.t_hosts.id not in seen and not seen.add(r.t_hosts.id): # kludge way to select only rows per host with the best OS-guess
            os_title = r.t_os.f_title or 'Unknown'
            os_vendor = r.t_os.f_vendor or 'Unknown'
            os_family = r.t_host_os_refs.f_family or 'Unknown'
            os_class = r.t_host_os_refs.f_class or 'Unknown'

            # only capitalize if the first char of the string isn't already capitalized
            # this covers not destroying things like HP, IOS, etc
            #if os_vendor[0].islower(): os_vendor = os_vendor.capitalize()
            if os_family[0].islower(): os_family = os_family.capitalize()
            if os_class[0].islower(): os_class = os_class.capitalize()

            count = os_counts.setdefault(os_title, 0)
            count += 1
            os_counts[os_title] = count

            count = vendor_counts.setdefault(os_vendor, 0)
            count += 1
            vendor_counts[os_vendor] = count

            count = family_counts.setdefault(os_family, 0)
            count += 1
            family_counts[os_family] = count

            count = class_counts.setdefault(os_class, 0)
            count += 1
            class_counts[os_class] = count

    response.title = "%s :: Operating System Statistics" % (settings.title)

    return dict(
        vendor_counts=vendor_counts,
        os_counts=os_counts,
        family_counts=family_counts,
        class_counts=class_counts,
    )

@auth.requires_login()
def services():
    """
    Service statistics
    """

    t_hosts = db.t_hosts
    t_svcs = db.t_services

    hostfilter = session.hostfilter
    if hostfilter is None:
        # if no filter is set then we blank it out
        if session.hostfilter is None:
            session.hostfilter = [(None, None), False]

    q = (t_hosts.id>0)
    q = create_hostfilter_query(session.hostfilter, q, t_svcs)

    rows = db(q).select(t_svcs.f_proto, t_svcs.f_number, t_svcs.f_name, cache=(cache.ram, 60))
    port_counts = {}
    name_counts = {}
    for r in rows:
        port = "%s/%s" % (r.f_proto, r.f_number)
        sname = r.f_name

        count = port_counts.setdefault(port, 0)
        count += 1
        port_counts[port] = count

        count = name_counts.setdefault(sname, 0)
        count += 1
        name_counts[sname] = count

    response.title = "%s :: Service Statistics" % (settings.title)

    return dict(
        port_counts=port_counts,
        name_counts=name_counts,
    )

@auth.requires_login()
def graphs():
    """
    Products the main statistics and graphs
    """

    if request.vars.gtype.lower() == 'all':
        indexgraphs = graphs_index(db)


    return dict(indexgraphs = indexgraphs)

@auth.requires_login()
def basic():
    """
    Basic statistics from the default index page
    """
    statistics = db_statistics(db)
    adv_stats = adv_db_statistics(db)
    return dict(statistics=statistics, adv_stats=adv_stats)

@auth.requires_login()
def vulncloud():
    """
    Pablo's vulnerability tag cloud

    Vulnerability IDs are counted and colored via severity.
    1-3: grey
    4-5: blue
    6-7: magenta
    8-10: red

    IDs are then sized based on quantity in HTML.
    """

    if request.extension == "json":
        # build the json data
        vulncloud = {}
        vd = db.t_vulndata
        svc_vulns = db.t_service_vulns

        # grab the list of vulnerabilities

        q = (svc_vulns.f_vulndata_id == vd.id)
        if request.args(0) is not None:
            try:
                minsev = float(request.args(0))
            except:
                minsev = 8.0

            q &= (vd.f_cvss_score >= minsev)
            if settings.use_cvss:
                q &= (vd.f_cvss_score >= float(request.args(0)))
            else:
                q &= (vd.f_severity >= int(request.args(0)))

            vulns = db(q).select(
                vd.id, vd.f_vulnid, vd.f_severity, vd.f_cvss_score, cache=(cache.ram, 300)
            )
        else:
            vulns = db(vd.id > 0).select(vd.id, vd.f_vulnid, vd.f_severity, vd.f_cvss_score, cache=(cache.ram, 300))

        for row in vulns:
            count = db(db.t_service_vulns.f_vulndata_id == row.id).count()

            if count > 0:
                if settings.use_cvss:
                    severity = int(row.f_cvss_score)
                else:
                    severity = int(row.f_severity)

                vulncloud[row.f_vulnid] = vulncloud.setdefault(
                    row.f_vulnid, {'count': count, 'color': severity_mapping(severity)[2]}
                )

        cloud = []
        for k, v in vulncloud.iteritems():
            cloud.append({'tag': k, 'count': v['count'], 'color': v['color']})
        return dict(vulncloud=cloud)

    response.title = "%s :: Vulnerability Tag Cloud" % (settings.title)
    response.files.append(URL(request.application, 'static', 'js/jquery.tagcloud-2.js'))
    return dict()

    response.title = "%s :: Vulnerability Tag Cloud" % (settings.title)
    response.files.append(URL(request.application, 'static', 'js/jquery.tagcloud-2.js'))
    return dict()

@auth.requires_login()
def vulncircles():
    """
    Vulnerability Circles shows critical vulnerabilities based on a scientifically
    proven formula involving CVSS score, metrics, counts and accounts
    """
    response.title = "%s :: Vulnerability Circles" % (settings.title)
    response.files.append(URL(request.application, 'static', 'js/d3.min.js'))
    return dict()

@auth.requires_login()
def vulncircles_data():
    vulncircles = {}

    minsev = request.args(0) or 8
    if settings.use_cvss:
        rows = db(db.t_vulndata.f_cvss_score >= minsev).select(cache=(cache.ram, 300))
    else:
        rows = db(db.t_vulndata.f_severity >= minsev).select(cache=(cache.ram, 300))
    for row in rows:
        vulncount = db(db.t_service_vulns.f_vulndata_id == row.id).count()

        exploits = db(db.t_exploit_references.f_vulndata_id == row.id).select()
        for expl in exploits:
            rank = db.t_exploits[expl.f_exploit_id].f_rank
            if rank in ['Novice', 'Intermediate']:
                exploit_modifier = 5
            elif rank in ['Expert']:
                exploit_modifer = 2.5
            else:
                exploit_modifier = 1.5

            level = db.t_exploits[expl.f_exploit_id].f_level
            if level in ['normal', 'great', 'excellent']:
                exploit_modifer *= 5
            elif level in ['average', 'good']:
                exploit_modifer *= 2.5
            elif level in ['unknown', 'manual', 'low']:
                exploit_modifer *= 1.5

        expcount = len(exploits)

        # if an account is sourced from a vuln, modifier is applied
        query = (db.t_accounts.f_source == row.f_vulnid) & (db.t_accounts.f_compromised == True)
        accounts = db(query).count()
        if accounts:
            account_mod = 2
        else:
            account_mod = .1

        # cvss modifiers
        # access vector (Local, Adjacent, Network)
        if row.f_cvss_av.upper() == 'N':
            av_mod = 10
        elif row.f_cvss_av.upper() == 'A':
            av_mod = 5
        else:
            av_mod = 2

        # access complexity (High, Medium, Low)
        if row.f_cvss_ac.upper() == 'L':
            ac_mod = 10
        elif row.f_cvss_ac.upper() == 'M':
            ac_mod = 5
        else:
            ac_mod = 2

        # authentication (Multiple, Single, None)
        if row.f_cvss_au.upper() == 'N':
            au_mod = 10
        elif row.f_cvss_au.upper() == 'S':
            au_mod = 5
        else:
            au_mod = 2

        # confidentiality impact (None, Partial, Complete)
        if row.f_cvss_c.upper() == 'C':
            c_mod = 10
        elif row.f_cvss_c.upper() == 'P':
            c_mod = 5
        else:
            c_mod = 2

        # integrity impact (None, Partial, Complete)
        if row.f_cvss_i.upper() == 'C':
            i_mod = 10
        elif row.f_cvss_i.upper() == 'P':
            i_mod = 5
        else:
            i_mod = 2

        # severity setting check and calculations
        if settings.use_cvss:
            severity = float(row.f_cvss_score)
        else:
            severity = int(row.f_severity)

        diameter = int((vulncount + (expcount * 2) * exploit_modifier) *
                       (severity * (av_mod + ac_mod + au_mod + c_mod + i_mod)) * account_mod)

        if vulncount > 0:
            vulncircles[row.f_vulnid] = vulncircles.setdefault(row.f_vulnid, {
                'diameter': diameter, 'vulncount': vulncount, 'expcount': expcount,
                'severity': severity, 'title': row.f_title,
            })

    data = {}
    for (k,v) in vulncircles.iteritems():
        sev = v['severity']
        values = data.setdefault(sev, [])
        values.append({
            'name': k, 'size': v['diameter'], 'vulncount': v['vulncount'],
            'expcount': v['expcount'], 'severity': v['severity'], 'title': v['title']
        })
        data[sev] = values

    d3json = []
    for k in data.keys():
        parent = {'name': 'Sev ' + str(k), 'children': data[k]}
        d3json.append(parent)

    response.headers['Content-Type'] = 'text/json'
    import gluon.contrib.simplejson
    return gluon.contrib.simplejson.dumps(d3json)
