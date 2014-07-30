# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Abstraction layer for Hosts and DB functions
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from skaldship.log import log
import logging
from gluon import current


##-------------------------------------------------------------------------

def add_or_update(hostfields, update=False):
    """
    Add a host and return the record. If update is True and host already exists
    then the record is updated and returned
    """
    if not isinstance(hostfields, dict()):
        log(" [!] Hostfields is not a dictionary", logging.ERROR)
        return None

    host_rec = db(db.t_hosts.f_ipv4 == hostfields.get('f_ipv4'))
    if not host_rec:
        host_rec = db(db.t_hosts.f_ipv4 == hostfields.get('f_ipv6'))

    if not host_rec:
        try:
            host_id = db.t_hosts.insert(**hostfields)
            db.commit()
        except Exception, e:
            log("Error adding host: %s" % strerror(e))
            return None

        host_rec = db.t_hosts[host_id]
        log(" [*] Added host: %s" % host_title_maker(host_rec))
    else:
        if update:
            host_rec.update(**hostfields)
            log(" [*] Updated host: %s" % host_title_maker(host_rec))

    return host_rec


##-------------------------------------------------------------------------

def get_host_record(argument):
    """
    Returns a t_host record based on the argument. If argument is a ipv4/ipv6
    address look it up and return it
    """

    if argument is None:
        return None

    from gluon.validators import IS_IPADDRESS
    db = current.globalenv['db']
    cache = current.globalenv['cache']

    record = db.t_hosts(argument) or None
    if record:
        return record
    else:
        if IS_IPADDRESS(is_ipv4=True)(argument)[1] == None:
            host_rec = db(db.t_hosts.f_ipv4 == argument).select().first()
            if host_rec:
                record = db.t_hosts(host_rec['id'])
            else:
                record = None
        elif IS_IPADDRESS(is_ipv6=True)(argument)[1] == None:
            host_rec = db(db.t_hosts.f_ipv6 == request.args(0)).select().first()
            if host_rec:
                record = db.t_hosts(host_rec['id'])
            else:
                record = None
        else:
            record = None

    return record


##-------------------------------------------------------------------------

def get_or_create_record(argument, **defaults):
    """
    Returns a t_host record based on the argument. If argument is an ipv4/ipv6 address it looks it up. If it's an
    integer it returns it. If none exist and argument is an ipv4/ipv6 address it creates a new record using the
    defaults provided.

    :param argument: ip address or db.t_hosts.id
    :param defaults: dictionary of db.t_hosts fields, validated before inserting
    :returns: Row with id

    >>> get_or_create_record('2.2.2.2')
    <Row {'f_confirmed': False, 'f_followup': None, 'f_macaddr': None, 'f_longitude': None, 'f_vuln_count': 0L, 'f_asset_group': 'undefined', 'f_accessed': False, 'id': 1L, 'f_vuln_graph': '0,0,0,0,0,0,0,0,0,0', 'f_engineer': 1L, 'f_exploit_count': 0L, 'f_hostname': None, 'f_ipv6': None, 'f_ipv4': '2.2.2.2', 'f_city': None, 'f_country': None, 'f_latitude': None, 'f_netbios_name': None, 'f_service_count': 0L}>

    >>> get_or_create_record('9.9.9.9', f_engineer=9999)
    None

    >>> get_or_create_record(1)
    <Row {'f_confirmed': False, 'f_followup': None, 'f_macaddr': None, 'f_longitude': None, 'f_vuln_count': 0L, 'f_asset_group': 'undefined', 'f_accessed': False, 'id': 1L, 'f_vuln_graph': '0,0,0,0,0,0,0,0,0,0', 'f_engineer': 1L, 'f_exploit_count': 0L, 'f_hostname': None, 'f_ipv6': None, 'f_ipv4': '2.2.2.2', 'f_city': None, 'f_country': None, 'f_latitude': None, 'f_netbios_name': None, 'f_service_count': 0L}>

    >>> get_or_create_record(9999)
    None
    """
    if argument is None:
        return None

    from gluon.validators import IS_IPADDRESS
    db = current.globalenv['db']
    auth = current.globalenv['auth']

    record = get_host_record(argument)
    if not record:
        fields = {}
        for k in defaults.keys():
            if k in db.t_hosts.fields:
                fields[k] = defaults[k]

        # set defaults for assetgroup/engineer if not set
        if 'f_asset_group' not in fields:
            fields['f_asset_group'] = 'undefined'
        if 'f_engineer' not in fields:
            fields['f_engineer'] = auth.user_id or 1

        if IS_IPADDRESS(is_ipv4=True)(argument)[1] == None:
            fields['f_ipv4'] = argument
        elif IS_IPADDRESS(is_ipv6=True)(argument)[1] == None:
            fields['f_ipv6'] = argument
        else:
            # invalid ip address, clear the fields
            fields = None

        if fields:
            host_rec = db.t_hosts.validate_and_insert(**fields)
            if host_rec.errors:
                log("Error creating host record: %s" % host_rec.errors, logging.ERROR)
            else:
                db.commit()
                record = db.t_hosts(host_rec.get('id'))

    return record


##-------------------------------------------------------------------------

def create_hostfilter_query(fdata, q=None, dbname=None):
    """
    Creates or appends a hostfilter to a query variable

    hostfilter is a set of filter_type and filter_value
    db is the database scoped from the application
    q is the base query we're appending to
    dbname is used to ensure the first query adds the dbname.f_hosts_id fields
    """
    db = current.globalenv['db']
    cache = current.globalenv['cache']
    session = current.globalenv['session']

    if not isinstance(fdata, dict):
        session.hostfilter = {
            'filtertype': None,
            'content': None,
            'unconfirmed': False,
            'accessed': False,
            'followup': False,
        }

    f_type = fdata.get('filtertype', '')
    if isinstance(f_type, type(None)):
        f_type = ''
    f_value = fdata.get('content')
    unconfirmed = fdata.get('unconfirmed', False)
    accessed = fdata.get('accessed', False)
    followup = fdata.get('followup', False)

    if db is None or cache is None:
        return None

    if q is None:
        q = db.t_hosts.id > 0

    if unconfirmed:
        q &= db.t_hosts.f_confirmed != unconfirmed
    if accessed:
        q &= db.t_hosts.f_accessed == accessed
    if followup:
        q &= db.t_hosts.f_followup == followup

    if dbname is not None:
        # dbname specified, must add this to the first query
        # so we only query against the right hosts and don't
        # create this large response with 4x the results we expect

        # the following tables are one table away from hosts so need
        # to connect them to their parent first
        db_parent_map = {
            't_accounts': 't_services',
            }
        if dbname in db_parent_map.keys():
            q &= db.t_hosts.id == db[db_parent_map[dbname]].f_hosts_id
        else:
            q &= db.t_hosts.id == db[dbname].f_hosts_id

    # go through the f_types and if matched add to the query
    if f_type.lower() == "userid":
        if f_value is not None:
            try:
                f_value = int(f_value)
                user_id = db(db.auth_user.id == f_value).select(cache=(cache.ram, 120)).first()
            except ValueError:
                f_value = f_value.lower()
                user_id = db(db.auth_user.username.lower() == f_value).select(cache=(cache.ram, 120)).first()
            q &= db.t_hosts.f_engineer == user_id
    elif f_type.lower() == "assetgroup":
        if "%" in f_value:
            q &= db.t_hosts.f_asset_group.contains(f_value)
        else:
            q &= db.t_hosts.f_asset_group == f_value

    return q


##-------------------------------------------------------------------------
def host_title_maker(record):
    """
    Given a t_host record, return a string value to place
    in the HTML TITLE (via response.title) or any other text
    place. Like a form field, json output, etc.
    """

    if record is None:
        return "Unknown"

    hostinfo = []
    if record.f_ipv4:
        hostinfo.append(record.f_ipv4)
    if record.f_ipv6:
        hostinfo.append(record.f_ipv6)
    if record.f_hostname:
        hostinfo.append(record.f_hostname)

    return " :: ".join(hostinfo)


##-------------------------------------------------------------------------

def host_a_maker(record=None):
    """
    Give a host record, return a A object that will open a new window
    to that host record
    """

    from gluon.html import A, I, URL, SPAN

    if record is None:
        return A()

    if isinstance(record, type([str, int])):
        record = get_host_record(record)

    host_a = A(host_title_maker(record), _target="host_detail_%s" % (record.id),
               _href=URL('hosts', 'detail', extension='html', args=record.id))

    info_a = SPAN(A(I(_class='icon-info-sign'), _href='#', _class='withajaxpopover',
               **{'_data-load':URL('hosts', 'popover.json', args=record.id),
                  '_data-trigger':'hover', '_data-delay':"{show: 500, hide: 100}",
                  '_data-placement':'right', '_data-html':'true', '_data-container':'#popoverwrap'}
              ), _id="popoverwrap")

    return SPAN(host_a, info_a)


##-------------------------------------------------------------------------

def do_host_status(records=[], query=None, asset_group=None, hosts=[]):
    """
    Runs through the t_hosts table and updates the *_count entries.
    Can also run through a specific list of record IDs instead.
    """

    db = current.globalenv['db']
    cache = current.globalenv['cache']
    settings = current.globalenv['settings']

    # load all the vulndata from service_vulns into a dictionary
    # so we only have to query the memory variables instead of
    # the database each time. We need to collect:
    # svc_vulndata[f_service_id] = (f_vulnid, f_severity, f_cvss_score)
    svc_vulndata = {}

    rows = db(db.t_service_vulns.f_vulndata_id==db.t_vulndata.id).select(
        db.t_vulndata.id,
        db.t_vulndata.f_vulnid,
        db.t_vulndata.f_severity,
        db.t_vulndata.f_cvss_score,
        cache=(cache.ram, 60)
    )

    for r in rows:
        #exploitcount = db(db.t_exploit_references.f_vulndata_id == r.id).count()
        svc_vulndata[r.id] = (
            r.f_vulnid,
            r.f_severity,
            r.f_cvss_score,
            db(db.t_exploit_references.f_vulndata_id == r.id).count()
        )

    if asset_group:
        query = (db.t_hosts.f_asset_group==asset_group)
    if query is None:
        query = (db.t_hosts.id > 0)
    for rec in hosts:
        query &= (db.t_hosts.id == rec)
    rows = db(query).select()
    for row in rows:
        # get number of vulns and services
        # optimizing the performance by inner joins
        ser_vulns = db((db.t_services.f_hosts_id==row.id) &
                       (db.t_services.id==db.t_service_vulns.f_services_id)) \
                  .select(db.t_service_vulns.f_vulndata_id, cache=(cache.ram, 30))

        vulncount = 0
        vuln_sev = {}
        exploitcount = 0
        #servicecount = services = db(db.t_services.f_hosts_id==r.id).count()
        servicecount = db(db.t_services.f_hosts_id==row.id).count()

        # XXX: this is kind of slow and could probably be improved upon. The cache helps but maybe
        # pre-loading vulndata into memory instead of querying the database for each one? That would
        # take more memory resources but be a huge speed boost.
        #vuln_start = datetime.now()
        for svcvuln in ser_vulns:
            vulncount += 1
            vdata = svc_vulndata[svcvuln.f_vulndata_id]
            vuln_sev[vdata[0]] = ( vdata[1], vdata[2] )
            # grab the exploit count
            exploitcount += vdata[3]
        #vuln_time = timedelta.total_seconds(datetime.now() - vuln_start)
        #tot_vuln += vuln_time
        #print("Vuln processed in %s seconds" % (vuln_time))

        # breakdown of vuln severity
        # prepopulate the dictionary with 0
        sev_sum_dict = {}
        for a in range(1, 11):
            sev_sum_dict[a] = 0

        # parse through the vuln_sev dictionary and count the severity types
        # then add them to their respective sev_sum_dict entry
        for k,v in vuln_sev.iteritems():
            # take the severity and increment the sev_sum set item
            if settings.use_cvss:
                severity = int(float(v[1]))
            else:
                severity = v[0]
            count = sev_sum_dict.setdefault(severity, 0)
            count += 1
            sev_sum_dict[severity] = count

        # make the sparkline data string
        spark_list = []
        for k,v in sev_sum_dict.iteritems():
            spark_list.append(str(v))
        vuln_sum_spark = ",".join(spark_list)

        row.update_record(
            f_service_count = servicecount,
            f_vuln_count = vulncount,
            f_vuln_graph = vuln_sum_spark,
            f_exploit_count = exploitcount,
        )
        db.commit()

    return

##-------------------------------------------------------------------------

def pagination(request, curr_host):
    # Pagination! Send it the db, request and current host record, get back
    # a dictionary to put into the view.
    # TODO: Remove db, request and session for current.globalenv

    db = current.globalenv['db']
    cache = current.globalenv['cache']
    session = current.globalenv['session']

    from gluon.html import OPTION, SELECT, FORM, A, INPUT, SCRIPT

    hostlist = []
    hostprev="#"
    hostnext="#"
    hostselected=0
    hostnextstyle=hostprevstyle=""
    hostprevtitle=hostnexttitle=""
    hostindex=1
    # Create more filters here
    if request.vars.filterconfirmed is not None:
        session.hostfilterconfirmed=request.vars.filterconfirmed

    if session.hostfilterconfirmed == 'Unconfirmed [H]osts':
        query = (db.t_hosts.id > 0)
    else:
        query = (db.t_hosts.f_confirmed==False)

    query = create_hostfilter_query(session.hostfilter, query)
    for h_rec in db(query).select():
        hostlist.append(OPTION(host_title_maker(h_rec), _value=h_rec.id))
        if hostselected != 0 and hostnext == "#":
            hostnext = h_rec.id
            hostnexttitle="Go to " + host_title_maker(h_rec)
        if h_rec.id == curr_host.id:
            hostselected = hostindex
        if hostselected == 0:
            hostprev = h_rec.id
            hostprevtitle="Go to " + host_title_maker(h_rec)
        hostindex=hostindex+1

    if hostprev == "#":
        hostprevstyle="display:none"
    if hostnext == "#":
        hostnextstyle="display:none"

    pagination = {}
    pagination['previous'] = A("(p)",_id="prevhostlink" ,_class="button", _href=hostprev, _style=hostprevstyle, _title=hostprevtitle)
    pagination['next'] = A("(n)", _id="nexthostlink", _class="button", _href=hostnext, _style=hostnextstyle, _title=hostnexttitle)
    pagination['form'] = FORM(
                              SELECT(
                                hostlist, value=request.args(0), _class="chosen-select", _id="host_select",
                                _name="host_select", _onchange="window.location.href=$('#host_select').val()",
                                **{'_data-placeholder':'Choose a host'}
                              ),
                              SCRIPT('$("#host_select").select2({width: "80%"});'),
                         )
    pagination['host_number'] = "( %d/%d )" % (hostselected, len(hostlist))

    return pagination


if __name__ == '__main__':
    import doctest
    doctest.testmod()
