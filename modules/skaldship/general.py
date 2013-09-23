# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## General utility module
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""


from gluon import current
import logging
logger = logging.getLogger("web2py.app.kvasir")

#db = current.globalenv['db']
#cache = current.globalenv['cache']

##-------------------------------------------------------------------------

def utf_8_decoder(unicode_data):
    for line in unicode_data:
        yield line.decode('utf-8')

##-------------------------------------------------------------------------

def severity_mapping(sevnum='1', totype='color'):
    """
    Convert a severity number (1-10) to a name (Info, Low, Medium, High)
    or color
    """
    severitymap = [ (0, 'informational', 'grey'),
                    (1, 'Informational', 'grey'),
                    (2, 'Informational', 'grey'),
                    (3, 'Low', 'green'),
                    (4, 'Low', 'green'),
                    (5, 'Medium', 'orange'),
                    (6, 'Medium', 'orange'),
                    (7, 'Medium', 'orange'),
                    (8, 'High', 'red'),
                    (9, 'High', 'red'),
                    (10, 'High', 'red'),
                  ]
    return severitymap[int(sevnum)]

##-------------------------------------------------------------------------

def vulntype_mapping(vulntype='exploited'):
    """
    Converts a vulnerability type to a color.
    """
    vulnmap = {
        'potential': 'grey',
        'vulnerable-version': 'green',
        'vulnerable-exploited': 'orange',
        'exploited': 'red',
    }

##-------------------------------------------------------------------------

def cvss_metrics(record):
    if record is None:
        return "NO RECORD SUBMITTED"

    return "AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s" % (record.f_cvss_av,
                                                 record.f_cvss_ac,
                                                 record.f_cvss_au,
                                                 record.f_cvss_c,
                                                 record.f_cvss_i,
                                                 record.f_cvss_a)

##-------------------------------------------------------------------------

def vuln_data(vuln, html=True, full=True):
    """Returns a dict of all useful vulnerability data from a record,
    including printable cvss, references and exploits"""

    from gluon.contrib.markmin.markmin2html import markmin2html

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    if type(vuln) is type(int):
        vuln = db.t_vulndata[vuln]

    if vuln is None:
        return "NO RECORD SUBMITTED"

    if full:
        # full == True means all information including references and exploits
        refdata = []
        for ref in db(db.t_vuln_references.f_vulndata_id == vuln.id).select(cache=(cache.ram, 300)):
            refdata.append([ db.t_vuln_refs[ref.f_vuln_ref_id].f_source,
                             db.t_vuln_refs[ref.f_vuln_ref_id].f_text ])

        expdata = []
        for exp_ref in db(db.t_exploit_references.f_vulndata_id == vuln.id).select(cache=(cache.ram, 300)):
            exp = db.t_exploits[exp_ref.id]
            if exp is not None:
                expdata.append([exp.f_name,
                                exp.f_title,
                                markmin2html(exp.f_description),
                                exp.f_source,
                                exp.f_rank,
                                exp.f_level
                              ])

        return (vuln.id,
                vuln.f_vulnid,
                vuln.f_title,
                severity_mapping(vuln.f_severity),
                vuln.f_cvss_score,
                cvss_metrics(vuln),
                markmin2html(vuln.f_description),
                markmin2html(vuln.f_solution),
                vuln.f_pci_sev,
                refdata,
                expdata,
               )

    else:
        # full = False means just the header info (vulnid, title, sevs, cvss)
        return (vuln.id,
                vuln.f_vulnid,
                vuln.f_title,
                severity_mapping(vuln.f_severity),
                vuln.f_cvss_score,
                cvss_metrics(vuln),
                vuln.f_pci_sev,
               )

##-------------------------------------------------------------------------

def make_good_url(url, addition="/"):
    """Appends addition to url, ensuring the right number of slashes
    exist and the path doesn't get clobbered"""

    if url is None:
        return None

    if addition[0] == "/":
        addition = addition.lstrip('/')
    urlpath = urlsplit(url)[2]
    if urlpath[len(urlpath)-1] == '/':
        url = urljoin(url, addition)
    else:
        url = urljoin(url, '/'+addition)
    return url

##-------------------------------------------------------------------------

def encode_url_for_xml(url):
    """
    Replaces special characters that XML doesn't like to see in URLs
    """
    if type(url) is not type(str()):
        return

    url = url.replace('&', '&amp;')
    url = url.replace('<', '&lt;')
    url = url.replace('>', '&gt;')
    url = url.replace('"', '%22')
    return url

##-------------------------------------------------------------------------

def get_url(options={}):
    """Connect to options['url'] and retrieve data"""
    if options.has_key('url') is None:
        return ""
    if options.has_key('username'):
        # add basic auth header
        key = base64.b64encode(options['username']+':'+options.get('password',''))
        headers = {'Authorization': 'Basic ' + key}
    else:
        headers = None

    values = { 'desc': options.get('type', ''),
               'description': options.get('name', '') }
    data = urllib.urlencode(values)

    try:
        req = urllib2.Request(options['url'], data, headers)
        response = urllib2.urlopen(req)
    except urllib2.URLError, e:
        raise Exception(e)

    return response.read()

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
        query = (db.t_hosts)
    else:
        query = (db.t_hosts.f_confirmed==False)

    if session.hostfilter:
        hostfilter = session.hostfilter[0]
        if hostfilter is not None:
            if hostfilter[0] == "userid":
                query &= (db.t_hosts.f_engineer == hostfilter[1])
            elif hostfilter[0] == "assetgroup":
                query &= (db.t_hosts.f_asset_group.contains(hostfilter[1]))
            elif hostfilter[0] == "range":
                query &= (db.t_hosts.f_ipv4.contains(hostfilter[1]))

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
        hostprevstyle="display:none";
    if hostnext == "#":
        hostnextstyle="display:none";

    pagination = {}
    pagination['previous'] = A("(p)",_id="prevhostlink" ,_class="button", _href=hostprev, _style=hostprevstyle, _title=hostprevtitle)
    pagination['next'] = A("(n)", _id="nexthostlink", _class="button", _href=hostnext, _style=hostnextstyle, _title=hostnexttitle)
    pagination['form'] = FORM(
                              SELECT(
                                hostlist, value=request.args(0), _class="chosen-select", _id="host_select",
                                _name="host_select", _onchange="window.location.href=$('#host_select').val()",
                                **{'_data-placeholder':'Choose a host'}
                              ),
                              SCRIPT('$("#host_select").chosen({search_contains: true, enable_split_word_search: true});'),
                         )
    pagination['host_number'] = "( %d/%d )" % (hostselected, len(hostlist))

    return pagination

##-------------------------------------------------------------------------
def create_hostfilter_query(fdata=[(None, None), False], q=None, dbname=None):
    """
    Creates or appends a hostfilter to a query variable

    hostfilter is a set of filter_type and filter_value
    db is the database scoped from the application
    q is the base query we're appending to
    dbname is used to ensure the first query adds the dbname.f_hosts_id fields
    """
    from gluon.dal import Query

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    if isinstance(fdata, list):
        hostfilter = fdata[0] or (None, None)
        unconfirmed = fdata[1] or False
    else:
        hostfilter = fdata
        unconfirmed = False

    if isinstance(hostfilter, (list,tuple)):
        f_type, f_value = hostfilter
    else:
        f_type, f_value = (None, None)

    if db is None or cache is None:
        return None

    if q is None:
        q = (db.t_hosts.id > 0)

    if unconfirmed:
        q &= (db.t_hosts.f_confirmed==False)

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
            q & (db.t_hosts.id == db[db_parent_map[dbname]].f_hosts_id)
        else:
            q &= (db.t_hosts.id == db[dbname].f_hosts_id)

    # go through the f_types and if matched add to the query
    if f_type == "userid":
        if f_value is not None:
            try:
                f_value = int(f_value)
                user_id = db(db.auth_user.id == f_value).select(cache=(cache.ram,120)).first()
            except:
                f_value = f_value.lower()
                user_id = db(db.auth_user.username.lower() == f_value).select(cache=(cache.ram,120)).first()
            q = q & (db.t_hosts.f_engineer == user_id)
    elif f_type == "assetgroup":
        logger.debug("assetgroup filter: %s" % (f_value))
        if "%" in f_value:
            q &= (db.t_hosts.f_asset_group.contains(f_value))
        else:
            q &= (db.t_hosts.f_asset_group == f_value)
    elif f_type == "range":
        q = q & (db.t_hosts.f_ipv4.contains(f_value))
    elif f_type == "ipv4_list":
        if len(f_value) > 0:
            ip_q = (db.t_hosts.f_ipv4 == f_value[0])
        for host in f_value[1:]:
            ip_q |= (db.t_hosts.f_ipv4 == host)
        q = q &  ip_q
    elif f_type == "ipv6_list":
        if len(f_value) > 0:
            ip_q = (db.t_hosts.f_ipv6 == f_value[0])
        for host in f_value[1:]:
            ip_q |= (db.t_hosts.f_ipv6 == host)
        q = q & ip_q

    #logger.debug("hostfilter query = %s" % (str(q)))
    return q

##-------------------------------------------------------------------------

def is_valid_ipv6(ip=None):
    """Checks to see if a IPv6 host address is valid. Does not do networks

    >>> is_valid_ipv6('fe80::426c:8fff:fe24:f8af')
    True
    >>> is_valid_ipv6('239.0.0.1')
    False
    """
    from gluon.contrib import ipaddr

    try:
        ipaddr.IPv6Address(ip)
    except ipaddr.AddressValueError, e:
        return False

    return True

##-------------------------------------------------------------------------

def is_valid_ipv4(ip=None):
    """Checks to see if a IPv4 host address is valid. Does not do networks

    >>> is_valid_ipv4('127.0.0.1')
    True
    >>> is_valid_ipv4('abcdef')
    False
    """
    from gluon.contrib import ipaddr

    try:
        ipaddr.IPv4Address(ip)
    except ipaddr.AddressValueError, e:
        return False

    return True

##-------------------------------------------------------------------------

def get_host_record(argument):
    """
    Returns a t_host record based on the argument. If argument is a ipv4/ipv6
    address look it up and return it
    """

    if argument is None:
        return None

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    record = db.t_hosts(argument) or None
    if record:
        return record
    else:
        if is_valid_ipv4(argument):
            host_rec = db(db.t_hosts.f_ipv4 == argument).select().first()
            if host_rec:
                record = db.t_hosts(host_rec['id'])
            else:
                record = None
        elif is_valid_ipv6(argument):
            host_rec = db(db.t_hosts.f_ipv6 == request.args(0)).select().first()
            if host_rec:
                record = db.t_hosts(host_rec['id'])
            else:
                record = None
        else:
            record = None

    return record

##-------------------------------------------------------------------------

def get_oreally_404(rfolder):
    """
    Picks a random oreally image and returns the filename
    """
    import os
    from random import choice
    imgdir = os.path.join(rfolder, 'static/images/oreally')
    if os.path.isdir(imgdir):
        files = os.listdir(imgdir)
        return choice(files)

##-------------------------------------------------------------------------

def do_host_status(records=[], query=None, asset_group=None, hosts=[]):
    """
    Runs through the t_hosts table and updates the *_count entries.
    Can also run through a specific list of record IDs instead.
    """

    db = current.globalenv['db']
    cache = current.globalenv['cache']

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
            count = sev_sum_dict.setdefault(v[0], 0)
            count += 1
            sev_sum_dict[v[0]] = count

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

    info_a = A(I(_class='icon-info-sign'), _href='#', _class='withajaxpopover',
               **{'_data-load':URL('hosts', 'popover.json', args=record.id),
                  '_data-trigger':'hover', '_data-delay':"{show: 500, hide: 100}",
                  '_data-placement':'right', '_data-html':'true'}
              )

    return SPAN(host_a, info_a)

##-------------------------------------------------------------------------

def html_to_markmin(html):
    """Replace HTML with Markmin"""

    if html is None:
        return ''
    from gluon.html import markmin_serializer, TAG
    return TAG(html).flatten(markmin_serializer).lstrip(' ')

##-------------------------------------------------------------------------

def check_datadir(folder=None):
    """
    Checks to see if data/ folder and sub-folders exist. Creates them if not.
    """
    if not folder:
        return False

    import os
    datadir = os.path.join(folder, 'data')
    if not os.path.exists(datadir):
        logger.info("Creating data directories in %s..." % datadir)
        os.mkdir(datadir, 0775)

    for dirname in [
        'passwords', 'passwords/unix', 'passwords/win', 'passwords/other', 'passwords/misc',
        'db', 'db/oracle', 'db/mysql', 'db/mssql', 'db/psql', 'db/other', 'stats',
        'screenshots', 'scanfiles', 'configs', 'misc', 'rpcclient', 'session-logs', 'backups'
    ]:
        d = os.path.join(datadir, dirname)
        if not os.path.exists(d):
            os.mkdir(d, 0755)

    return True

##-------------------------------------------------------------------------

if __name__ == "__main__":
    import doctest
    doctest.testmod()
