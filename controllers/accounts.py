# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Accounts controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.hosts import get_host_record, host_title_maker, host_a_maker, create_hostfilter_query
from skaldship.passwords import process_password_file, process_cracked_file, process_mass_password, insert_or_update_acct
import re
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir

@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------
## accounts
##-------------------------------------------------------------------------

@auth.requires_signature()
@auth.requires_login()
def compromise():
    """Toggle compromised true/false"""
    compr_count = 0
    uncompr_count = 0
    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '':
                flag = db.t_accounts[z].f_compromised
                if flag:
                    db.t_accounts[z].f_compromised = False
                    uncompr_count += 1
                else:
                    db.t_accounts[z].f_compromised = False
                    compr_count += 1
        db.commit()
        cache.ram.clear('accounts_list')
        response.flash = '%s compromised / %s uncompromised' % (compr_count, uncompr_count)
        response.js = 'accounttable.fnReloadAjax();'
    return

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    if request.vars.has_key('ids'):
        for z in request.vars.ids.split('|'):
            if z is not '' or z is not None:
                db(db.t_accounts.id == z).delete()
                count += 1
        db.commit()
        msg = '%s Account(s) deleted' % (count)
        cache.ram.clear('accounts_list')
        response.js = 'accounttable.fnReloadAjax();'
    else:
        msg = "No Account IDs sent for deletion"
    response.flash = msg
    return dict(msg=msg)

@auth.requires_login()
def add():
    if request.vars.has_key('id'):
        host_id = db.t_hosts[request.vars.id] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    else:
        host_id = None

    if host_id:
        # grab services for a host
        services = db(db.t_services.f_hosts_id == host_id.id).select(cache=(cache.ram,30))
        svc_set = []
        for svc in services:
            svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)])
        db.t_accounts.f_services_id.requires = IS_IN_SET(svc_set)
        form=crud.create(db.t_accounts,message='Account added',next=URL('accounts_create', vars={'id': host_id.id}))
        db.t_accounts.f_services_id.requires = None
    else:
        form=crud.create(db.t_accounts, next='edit/[id]',message="Account added")
    cache.ram.clear('accounts_list')
    response.title = "%s :: Add Account" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def view():
    record = db.t_accounts(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Account record not found')}))
    form=crud.read(db.t_accounts,record)
    return dict(form=form)

@auth.requires_login()
def edit():
    record = db.t_accounts(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('Account record not found')}))
    service = db(db.t_services.id == record.f_services_id).select().first()
    services = db(db.t_services.f_hosts_id == service.f_hosts_id).select()
    svc_set = []
    for svc in services:
        svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)])
    db.t_accounts.f_services_id.requires = IS_IN_SET(svc_set)
    form=crud.update(db.t_accounts,record,next='edit/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    db.t_accounts.f_services_id.requires = None
    hosttitle = "%s :: %s/%s" % (host_title_maker(db.t_hosts[service.f_hosts_id]), service.f_proto, service.f_number)
    response.title = "%s :: Update Account :: %s :: %s" % (settings.title, record.f_username, hosttitle)
    return dict(form=form)

@auth.requires_login()
def accounts_grid():
    response.title = "%s :: Accounts" % (settings.title)

    query = (db.t_accounts.id > 0) & (db.t_accounts.f_services_id== db.t_services.id)
    query = create_hostfilter_query(session.hostfilter, query, 't_services')
    columns = [
        db.t_hosts.f_ipv4, db.t_hosts.f_hostname, db.t_services.f_proto, db.t_services.f_number,
        db.t_accounts.f_fullname, db.t_accounts.f_domain, db.t_accounts.f_password,
        db.t_accounts.f_hash1_type, db.t_accounts.f_hash1, db.t_accounts.f_hash2_type,
        db.t_accounts.f_hash2, db.t_accounts.f_uid, db.t_accounts.f_gid,
        db.t_accounts.f_level, db.t_accounts.f_active, db.t_accounts.f_lockout,
        db.t_accounts.f_duration, db.t_accounts.f_source, db.t_accounts.f_message,
        db.t_accounts.f_description, db.t_accounts.id,
    ]
    rows = SQLFORM.grid(query, columns, deletable=True, selectable=True, details=False, field_id=db.t_accounts.id)

    return dict(rows=rows)

@auth.requires_login()
def csv():
    """
    Download account data in CSV format
    """
    import cStringIO
    q = (db.t_accounts.f_services_id==db.t_services.id) & (db.t_services.f_hosts_id==db.t_hosts.id)
    if request.vars.has_key('type'):
        q &= ((db.t_accounts.f_hash1_type == request.vars.type) | (db.t_accounts.f_hash1_type == request.vars.type))
    if request.vars.has_key('username'):
        q &= (db.t_accounts.f_username == request.vars.username)

    accts = db(q).select(
        db.t_hosts.f_ipv4, db.t_services.f_proto, db.t_services.f_number,
        db.t_accounts.f_services_id, db.t_accounts.id, db.t_accounts.f_username,
        db.t_accounts.f_password, db.t_accounts.f_compromised,
        db.t_accounts.f_hash1, db.t_accounts.f_hash1_type,
        db.t_accounts.f_hash2, db.t_accounts.f_hash2_type,
        db.t_accounts.f_uid, db.t_accounts.f_gid, db.t_accounts.f_level,
        db.t_accounts.f_source, db.t_accounts.f_message, db.t_accounts.f_description
    )
    s = cStringIO.StringIO()
    accts.export_to_csv_file(s)
    return s.getvalue()

@auth.requires_login()
def list():
    response.title = "%s :: Accounts" % (settings.title)

    if request.extension == 'json':
        query = (db.t_accounts.id > 0) & (db.t_accounts.f_services_id== db.t_services.id)
        query = create_hostfilter_query(session.hostfilter, query, 't_services')
        if request.vars.hash_type is not None:
            query &= ((db.t_accounts.f_hash1_type == request.vars.hash_type) | (db.t_accounts.f_hash2_type == request.vars.hash_type))

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

        srch_data = request.vars.get('sSearch')
        if srch_data:
            # sSearch global search box

            # parse the search into fields (port:num proto:tcp etc)
            srch_vals = [
                ["port", db.t_services.f_number],
                ["proto", db.t_services.f_proto],
                ["user", db.t_accounts.f_username],
                ["name", db.t_accounts.f_fullname],
                ["domain", db.t_accounts.f_domain],
                ["hash", db.t_accounts.f_hash1],
                ["hash1", db.t_accounts.f_hash1],
                ["hash2", db.t_accounts.f_hash2],
                ["htype", db.t_accounts.f_hash1_type],
                ["uid", db.t_accounts.f_uid],
                ["gid", db.t_accounts.f_gid],
                ["level", db.t_accounts.f_level],
                ["source", db.t_accounts.f_source],
                ["desc", db.t_accounts.f_description],
                ["msg", db.t_accounts.f_message],
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
                    if val[0] in ['source', 'desc', 'hostname']:
                        query &= (val[1].upper().contains(res.upper()))
                    else:
                        query &= (val[1].upper() == res.upper())

            if not parsed:
                query &= db.t_accounts.f_username.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_password.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_fullname.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_domain.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_hash1.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_hash2.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_source.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_message.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_accounts.f_description.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_hosts.f_ipv4.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_hosts.f_ipv6.like("%%%s%%" % request.vars.sSearch) | \
                    db.t_hosts.f_hostname.like("%%%s%%" % request.vars.sSearch)

            #total_count = db.t_vulndata.id.count()
        if request.vars.iSortingCols == '1':
            # sorting by a column - this is a little trippy because tuples start at 0
            # and datatables starts at 1 so we have to subtract 1 from iSortCol_0
            cols = (
                db.t_accounts.f_compromised,
                db.t_hosts.f_ipv4,
                db.t_services.f_number,
                db.t_accounts.f_username,
                db.t_accounts.f_fullname,
                db.t_accounts.f_domain,
                db.t_accounts.f_password,
                db.t_accounts.f_hash1_type,
                db.t_accounts.f_hash1,
                db.t_accounts.f_hash2_type,
                db.t_accounts.f_hash2,
                db.t_accounts.f_uid,
                db.t_accounts.f_gid,
                db.t_accounts.f_level,
                db.t_accounts.f_active,
                db.t_accounts.f_lockout,
                db.t_accounts.f_source,
                db.t_accounts.f_message,
                db.t_accounts.f_description
            )

            orderby = cols[int(request.vars.iSortCol_0) ]
            if request.vars.sSortDir_0 == 'asc':
                rows=db(query).select(
                    db.t_accounts.ALL,
                    db.t_hosts.id,
                    db.t_hosts.f_ipv4,
                    db.t_hosts.f_ipv6,
                    db.t_hosts.f_hostname,
                    db.t_services.f_proto,
                    db.t_services.f_number,
                    orderby=orderby,
                    limitby=(start, limit),
                    cache=(cache.with_prefix(cache.ram, "accounts_list"), 180))
            else:
                rows=db(query).select(
                    db.t_accounts.ALL,
                    db.t_hosts.id,
                    db.t_hosts.f_ipv4,
                    db.t_hosts.f_ipv6,
                    db.t_hosts.f_hostname,
                    db.t_services.f_proto,
                    db.t_services.f_number,
                    orderby=~orderby,
                    limitby=(start, limit),
                    cache=(cache.with_prefix(cache.ram, "accounts_list"), 180))
        else:
            rows=db(query).select(
                db.t_accounts.ALL,
                db.t_hosts.id,
                db.t_hosts.f_ipv4,
                db.t_hosts.f_ipv6,
                db.t_hosts.f_hostname,
                db.t_services.f_proto,
                db.t_services.f_number,
                limitby=(start,limit),
                cache=(cache.with_prefix(cache.ram, "accounts_list"), 180))

        #rows=db(q).select(
        #    db.t_accounts.ALL,
        #    db.t_hosts.id,
        #    db.t_hosts.f_ipv4,
        #    db.t_hosts.f_ipv6,
        #    db.t_hosts.f_hostname,
        #    db.t_services.f_proto,
        #    db.t_services.f_number,
        #    #cache=(cache.ram,60)
        #)

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = {}
            if r.t_accounts.f_compromised == True:
                atxt['0'] = '<div class="acct_compromised" name="row_id" id="%s"><span class="icon-check"></span></div>' % r.t_accounts.id
            else:
                atxt['0'] = '<div class="acct_uncompromised" name="row_id" id="%s"/>' % r.t_accounts.id

            #svc = db.t_services[r.f_services_id]

            atxt['1'] = host_a_maker(r.t_hosts).xml()
            atxt['2'] = "%s/%s" % (r.t_services.f_proto, r.t_services.f_number)
            atxt['3'] = DIV(A(I(_class="icon-pencil", _style="display: inline-block;"),
                               _target="accounts_update_%s" % (r.t_accounts.id), \
                               _href=URL('edit.html', args=r.t_accounts.id), \
                               ),
                             A("%s" % (r.t_accounts.f_username), \
                               _target="_blank", _id="username", \
                               _href=URL("by_username", vars={'username':r.t_accounts.f_username}, extension="html"), \
                               )
                             ).xml()
            atxt['4'] = r.t_accounts.f_fullname
            atxt['5'] = r.t_accounts.f_domain
            atxt['6'] = r.t_accounts.f_password
            atxt['7'] = r.t_accounts.f_hash1_type
            atxt['8'] = r.t_accounts.f_hash1
            atxt['9'] = r.t_accounts.f_hash2_type
            atxt['10'] = r.t_accounts.f_hash2
            atxt['11'] = r.t_accounts.f_uid
            atxt['12'] = r.t_accounts.f_gid
            atxt['13'] = r.t_accounts.f_level
            atxt['14'] = r.t_accounts.f_active
            atxt['15'] = r.t_accounts.f_source
            atxt['16'] = r.t_accounts.f_message
            atxt['17'] = r.t_accounts.f_description
            atxt['DT_RowId'] = str(r.t_accounts.id)

            aaData.append(atxt)

        result = {
            'sEcho': request.vars.sEcho,
            'iTotalDisplayRecords': db(query).count(),
            'iTotalRecords': db(db.t_accounts).count(),
            'aaData': aaData,
            'query': db._lastsql,
        }

        return result

    rows=db(db.t_accounts).select(db.t_accounts.f_hash1_type, groupby=db.t_accounts.f_hash1_type, cache=(cache.ram, 60))
    hash_types=[]
    for r in rows:
        #if r.f_hash2_type is not None:
        #    hash_types.append("%s/%s" % (r.f_hash1_type, r.f_hash2_type))
        #else:
            hash_types.append(r.f_hash1_type)

    form = TABLE(THEAD(TR(TH(T('C'), _width="1%"),
                          TH(T('Host')),
                          TH(T('Port')),
                          TH(T('Username')),
                          TH(T('Fullname')),
                          TH(T('Domain')),
                          TH(T('Password')),
                          TH(T('Hash 1 Type')),
                          TH(T('Hash 1')),
                          TH(T('Hash 2 Type')),
                          TH(T('Hash 2')),
                          TH(T('UID')),
                          TH(T('GID')),
                          TH(T('Level')),
                          TH(T('Active')),
                          TH(T('Source')),
                          TH(T('Message')),
                          TH(T('Description')),
                          )  ),
                 _class="datatable",
                 _id="accounttable",
                 _style="width:100%")

    add = AddModal(
        db.t_accounts, 'Add', 'Add', 'Add Account',
        #fields=[],
        cmd='accounttable.fnReloadAjax();'
    )
    services = db(db.t_services.f_hosts_id > 0).select(cache=(cache.ram,30))

    svc_set = []
    for svc in services:
        svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)])
    db.t_accounts.f_services_id.requires = IS_IN_SET(svc_set)
    db.t_accounts.id.comment = add.create()

    return dict(form=form, hash_types=hash_types, add=add)

@auth.requires_login()
def check_john_pot():
    """
    Checks all passwords against the john.pot file specified by the
    user. Any hash found in the database has their cleartext assigned.

    Any entry with f_password not None is skipped.

    For NTLM it first checks NTLM. If not found it will split the
    LM into two and look up each side.

    NOTE: This does NOT call john the ripper, it only loads the POT file.

    XXX: This needs to be debugged/tested.. It was a 3am code writing binge!
    """
    import os

    if request.extension == "load":
        buttons=[]
    else:
        buttons=['submit']

    known_paths = []
    known_paths.append([0, None])
    known_paths.append([1, '/opt/metasploit_pro/apps/pro/engine/config/john.pot'])
    known_paths.append([2, '/root/.john/john.pot'])

    form = SQLFORM.factory(
        Field('potfile', 'upload', uploadfolder=os.path.join(request.folder, settings.password_upload_dir), label=T('POT File')),
        Field('common_paths', 'string', default="0", requires=IS_IN_SET(known_paths), label=T('Known paths')),
        Field('other_file', 'string', label=T('John.pot File Location')),
        buttons=buttons, _action=URL('accounts', 'check_john_pot'), _id='john_pot',
    )

    if form.errors:
        response.flash = 'Error in form'
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    elif form.accepts(request.vars, session):
        if form.vars.potfile:
            potfile = os.path.join(request.folder, settings.password_upload_dir, form.vars.potfile)
        elif form.vars.other_file:
            potfile = request.vars.other_file
        else:
            potfile = known_paths[int(form.vars.common_paths)][1]

        from skaldship.jtr import JohnPot, ntpwchk

        try:
            logger.info("Loading %s ..." % (potfile))
            potdata = JohnPot()
            potdata.load(potfile)
        except Exception, e:
            response.flash = "Error loading %s: %s" % (potfile, e)
            return dict(form=form)

        # Clear out any uncracked LM hashes:
        # db(db.t_accounts.f_password.contains("???????")).update(f_password=None, f_compromised=False)

        query = (db.t_accounts.f_hash1 <> None) & (db.t_accounts.f_password == None)
        query |= (db.t_accounts.f_password.contains('???????'))
        uncracked = db(query).select(cache=(cache.ram, 60))
        update_count = 0

        for acct in uncracked:
            # check for no password!
            if acct.f_hash1.upper() == 'AAD3B435B51404EEAAD3B435B51404EE' and acct.f_hash2.upper() == '31D6CFE0D16AE931B73C59D7E0C089C0':
                acct.update_record(f_password='', f_compromised=True)
                logger.info("Found blank LM/NTLM for %s" % (acct.f_username))
                db.commit()
                update_count += 1
                continue

            if acct.f_hash1_type == "LM":
                # we may have a LANMAN, look up the NTLM first
                pw = potdata.search("$NT$%s" % (acct.f_hash2.upper()))
                if pw is not None:
                    acct.update_record(f_password=pw, f_compromised=True)
                    logger.info("Found NTLM for %s: %s" % (acct.f_username, pw))
                    db.commit()
                    update_count += 1
                    continue
                else:
                    # skip over no password and NTLM not found
                    if acct.f_hash1 == "NO PASSWORD*********************":
                        continue
                    # No NTLM, lets split up the LM and append the $LM$
                    # and upper case the hash
                    pwhash = acct.f_hash1.upper()
                    if len(pwhash) != 32:
                        logger.warning("Error: You say you have an LM hash but it's not 32 characters: %s" % (acct.f_hash1))
                        continue
                    pw1 = potdata.search("$LM$%s" % (pwhash[0:16]))
                    if pw1 is None:
                        pw1 = "???????"
                    pw2 = potdata.search("$LM$%s" % (pwhash[16:]))
                    if pw2 is None:
                        pw2 = "???????"
                    pw = "%s%s" % (pw1, pw2)
                    msg = "Found LM for %s: %s" % (acct.f_username, pw)
                    if pw != "??????????????":
                        if "???????" in pw:
                            acct.update_record(f_password=pw, f_compromised=False)
                        else:
                            # case permute the password and check the NTLM
                            try:
                                (status, newpw) = ntpwchk(pw, acct.f_hash1, acct.f_hash2)
                            except Exception:
                                status = None
                            if status:
                                pw = newpw
                                acct.update_record(f_password=pw, f_compromised=True)
                                msg = "Permuted NTLM for %s: %s" % (acct.f_username, pw)
                        db.commit()
                        logger.info(msg)
                        update_count += 1

            else:
                # lookup everything else
                pw = potdata.search(acct.f_hash1)

                if pw is not None:
                    acct.update_record(f_password=pw, f_compromised=True)
                    db.commit()
                    logger.info("Found password for %s: %s" % (acct.f_username, pw))
                    update_count += 1

        response.flash = "%s accounts updated with passwords" % (update_count)
        cache.ram.clear('accounts_list')

    response.title = "%s :: Process john.pot File" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def by_host():
    """
    Returns a list of services + serviceinfo based upon an host identifier
    (id, ipv4, ipv6)
    """
    record = get_host_record(request.args(0))
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    response.title = "%s :: Accounts for %s" % (settings.title, host_title_maker(record))
    query = (db.t_services.f_hosts_id == record.id)

    if request.extension == "json":
        aaData = []
        rows = db(query).select(db.t_accounts.ALL, db.t_services.ALL, left=db.t_services.on(db.t_accounts.f_services_id==db.t_services.id))
        for r in rows:
            if r.t_accounts.f_compromised == True:
                comprdiv = '<div class="acct_compromised" name="row_id" id="%s"><span class="icon-check"></span></div>' % r.t_accounts.id
            else:
                comprdiv = '<div class="acct_uncompromised" name="row_id" id="%s"/>' % r.t_accounts.id

            aaData.append({
                '0': A("edit", _target="accounts_update_%s" % (r.t_accounts.id), _href=URL('accounts', 'edit', args=[r.t_accounts.id], extension='html')).xml(),
                '1': comprdiv,
                '2': A("%s/%s" % (r.t_services.f_proto, r.t_services.f_number), _target="services_edit_%s" % (r.t_services.id), _href=URL('services', 'edit', args=[r.t_services.id], extension='html')).xml(),
                '3': A(r.t_accounts.f_username, _target="accounts_username_%s" % (r.t_accounts.f_username), _href=URL('accounts', 'by_username', vars={'username': r.t_accounts.f_username}, extension='html')).xml(),
                '4': r.t_accounts.f_fullname,
                '5': r.t_accounts.f_password,
                '6': r.t_accounts.f_hash1_type,
                '7': r.t_accounts.f_hash1,
                '8': r.t_accounts.f_hash2_type,
                '9': r.t_accounts.f_hash2,
                '10': r.t_accounts.f_uid,
                '11': r.t_accounts.f_gid,
                '12': r.t_accounts.f_lockout,
                '13': r.t_accounts.f_duration,
                '14': r.t_accounts.f_source,
                '15': r.t_accounts.f_level,
                '16': r.t_accounts.f_description,
                'DT_RowId': r.t_accounts.id,
            } )

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    form = TABLE(THEAD(TR(TH(T(''), _width="5%"),
                          TH(T('Compr'), _width="5%"),
                          TH(T('Port')),
                          TH(T('Username')),
                          TH(T('Fullname')),
                          TH(T('Password')),
                          TH(T('Hash 1 Type')),
                          TH(T('Hash 1')),
                          TH(T('Hash 2 Type')),
                          TH(T('Hash 2')),
                          TH(T('UID')),
                          TH(T('GID')),
                          TH(T('Lockout')),
                          TH(T('Duration')),
                          TH(T('Source')),
                          TH(T('Level')),
                          TH(T('Description')),
                          )  ),
                 _class="datatable",
                 _id="accounttable",
                 _style="width:100%")

    add = AddModal(
        db.t_accounts, 'Add', 'Add', 'Add Account',
        #fields=[],
        cmd='accounttable.fnReloadAjax();'
    )
    services = db(db.t_services.f_hosts_id == record.id).select(cache=(cache.ram,30))
    svc_set = []
    for svc in services:
        svc_set.append([svc.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[svc.f_hosts_id]), svc.f_proto, svc.f_number)])
    db.t_accounts.f_services_id.requires = IS_IN_SET(svc_set)
    db.t_accounts.id.comment = add.create()

    return dict(form=form, host=record, add=add)

@auth.requires_login()
def by_username():

    if request.vars.get('username', 'None') != 'None':
        record = None
        response.title = "%s :: Account entries for %s" % (settings.title, request.vars.username)
        query = (db.t_accounts.f_username.like(request.vars.username))
    else:
        query = (db.t_accounts.active)

    aaData = []
    rows = db(query).select(db.t_accounts.ALL, db.t_hosts.ALL, db.t_services.ALL, left=(db.t_services.on(db.t_accounts.f_services_id==db.t_services.id), db.t_hosts.on(db.t_hosts.id == db.t_services.f_hosts_id)))
    for r in rows:
        atxt=[]
        hostrec=db.t_hosts[r.t_hosts.id]
        atxt.append(TD(A("edit", _target="accounts_update_%s" % (r.t_accounts.id), _href=URL('accounts', 'edit', args=[r.t_accounts.id], extension='html'))))
        atxt.append(TD(INPUT(_name="id", _value=str(r.t_accounts.id), _type="checkbox")))
        atxt.append(TD(A("%s" % (host_title_maker(hostrec)), _target="host_detail_%s" % (r.t_hosts.id), _href=URL('hosts', 'detail', args=[r.t_hosts.id]))))
        atxt.append(TD(A("%s/%s" % (r.t_services.f_proto, r.t_services.f_number), _target="services_edit_%s" % (r.t_services.id), _href=URL('services', 'edit',args=[r.t_services.id], extension='html'))))
        atxt.append(TD(r.t_accounts.f_username))
        atxt.append(TD(r.t_accounts.f_fullname))
        atxt.append(TD(r.t_accounts.f_password))
        atxt.append(TD(r.t_accounts.f_compromised))
        atxt.append(TD(r.t_accounts.f_hash1_type))
        atxt.append(TD(r.t_accounts.f_hash1))
        atxt.append(TD(r.t_accounts.f_hash2_type))
        atxt.append(TD(r.t_accounts.f_hash2))
        atxt.append(TD(r.t_accounts.f_uid))
        atxt.append(TD(r.t_accounts.f_gid))
        atxt.append(TD(r.t_accounts.f_lockout))
        atxt.append(TD(r.t_accounts.f_duration))
        atxt.append(TD(r.t_accounts.f_source))
        atxt.append(TD(r.t_accounts.f_level))
        atxt.append(TD(r.t_accounts.f_description))

        aaData.append(TR(atxt))

    form = TABLE(THEAD(TR(TH(T('ID'), _width="5%"),
                          TH(T(''), _width="2%"),
                          TH(T('Host')),
                          TH(T('Port')),
                          TH(T('Username')),
                          TH(T('Fullname')),
                          TH(T('Password')),
                          TH(T('Compromised')),
                          TH(T('Hash 1 Type')),
                          TH(T('Hash 1')),
                          TH(T('Hash 2 Type')),
                          TH(T('Hash 2')),
                          TH(T('UID')),
                          TH(T('GID')),
                          TH(T('Lockout')),
                          TH(T('Duration')),
                          TH(T('Source')),
                          TH(T('Level')),
                          TH(T('Description')),
                          )  ),
                 TBODY(aaData),
                 _class="datatable",
                 _id="accounttable",
                 _style="width:100%")

    return dict(form=form)

@auth.requires_login()
def duplicate_on_hosts():
    """
    Find duplicate accounts on multiple services per host
    """
    query = (db.t_accounts.f_services_id == db.t_services.id)
    query &= (db.t_services.f_hosts_id == db.t_hosts.id)

    columns = [
        db.t_hosts.f_ipv4, db.t_hosts.f_hostname, db.t_services.f_proto, db.t_services.f_number,
        db.t_accounts.f_username, db.t_accounts.f_domain, db.t_accounts.f_compromised,
        db.t_accounts.f_password, db.t_accounts.f_hash1_type, db.t_accounts.f_hash1,
        db.t_accounts.f_hash2_type, db.t_accounts.f_hash2, db.t_accounts.f_uid,
        db.t_accounts.f_gid, db.t_accounts.f_level, db.t_accounts.f_source,
        db.t_accounts.f_message, db.t_accounts.f_description, db.t_accounts.id
    ]
    rows = SQLFORM.grid(query, columns, deletable=True, selectable=True, details=False, field_id=db.t_accounts.id)
    #rows = SQLFORM.smartgrid(db.t_hosts, linked_tables = [ db.t_services, db.t_accounts ])
    return dict(rows=rows)

@auth.requires_login()
def import_file():
    """
    Import and parse password file into t_accounts
    """
    import os
    from skaldship.general import check_datadir
    check_datadir(request.folder)

    # Service_id is primary, host_id is secondary, if none then list
    # all the services
    svc_set = []
    url=URL('accounts', 'import_file')
    if request.vars.has_key('service_id'):
        try:
            record = db.t_services[request.vars.service_id]
            svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))
            url = URL('accounts', 'import_file', vars={'service_id':request.vars.service_id})
        except:
            pass
    elif request.vars.has_key('host_id'):
        try:
            host_record = get_host_record(request.vars.host_id)
            svc_records = db(db.t_services.f_hosts_id == host_record.id).select(cache=(cache.ram, 30))
            url = URL('accounts', 'import_file', vars={'host_id':request.vars.host_id})
            for record in svc_records:
                svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))
        except:
            pass

    if len(svc_set) == 0:
        # all services
        svc_records = db(db.t_services).select(cache=(cache.ram,30))
        svc_set = []
        for record in svc_records:
            svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))

    if request.extension == "load":
        buttons=[]
    else:
        buttons=['submit']

    form = SQLFORM.factory(
        Field('f_service', 'string', label=T('Host / Service'), requires=IS_IN_SET(svc_set), default=svc_set[0][0]),
        Field('f_filename', 'upload', uploadfolder=os.path.join(request.folder, settings.password_upload_dir), label=T('Password file')),
        Field('f_type', 'string', label=T('File type'), default='PWDUMP', requires=IS_IN_SET(settings.password_file_types)),
        Field('f_source', 'string', label=T('Source (if necessary)')),
        Field('f_add_to_evidence', 'boolean', label=T('Add Evidence')),
        Field('f_taskit', type='boolean', default=True, label=T('Run in background task')),
        buttons=buttons, _action=url, _id='accounts_import_form'
    )

    resp_text = ""
    accounts_added = []
    accounts_updated = []
    if form.errors:
        response.flash = 'Error in form'
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    elif form.accepts(request.vars, session):
        if form.vars.f_filename is not None:
            orig_filename = request.vars.f_filename.filename
        filename = os.path.join(request.folder, settings.password_upload_dir, form.vars.f_filename)
        if form.vars.f_taskit:
            task = scheduler.queue_task(
                accounts_import_file,
                pvars=dict(
                    filename=filename,
                    service=form.vars.f_service,
                    f_type=form.vars.f_type,
                    f_source=form.vars.f_source
                ),
                group_name=settings.scheduler_group_name,
                sync_output=5,
                timeout=300    # 5 minutes
            )
            if task.id:
                resp_text = "Submitted file for processing: %s" % (A("task " + str(task.id), _href=URL(c='tasks', f='status', args=task.id)).xml())
            else:
                resp_text = "Error submitting job: %s" % (task.errors)
        else:
            logger.info("Processing password file: %s" % (filename))
            account_data = process_password_file(
                pw_file=filename,
                file_type=request.vars.f_type,
                source=request.vars.f_source
            )
            resp_text = insert_or_update_acct(form.vars.f_service, account_data)
            logger.info(resp_text)

        if form.vars.f_add_to_evidence is True:
            # add the password file to evidence
            try:
                pwdata = open(filename, "r").readlines()
            except Exception, e:
                logger.error("Error opening %s: %s" % (filename, e))

            db.t_evidence.insert( f_hosts_id = db.t_services[form.vars.f_service].f_hosts_id,
                                  f_type = 'Password File',
                                  f_text = form.vars.f_type,
                                  f_filename = orig_filename,
                                  f_evidence = form.vars.f_filename,
                                  f_data = pwdata)
            db.commit()

    response.flash = resp_text
    response.title = "%s :: Import Password File" % (settings.title)

    if request.extension == "json":
        response.js = "accounttable.fnReloadAjax();"
        return dict()
    else:
        return dict(form=form)

@auth.requires_login()
def update_hashes_by_file():
    """
    Upload and parse a list of cracked hashes
    Supporting password file formats:
       JTR PWDUMP
       JTR Shadow
       Hash:Password
       Password:Hash
    """
    import os
    from skaldship.general import check_datadir
    check_datadir(request.folder)

    if request.extension == "load":
        buttons=[]
    else:
        buttons=['submit']

    pw_set = ('JTR PWDUMP', 'JTR Shadow', 'Hash:Password', 'Password:Hash')

    form = SQLFORM.factory(
        Field('f_filename', 'upload', uploadfolder=os.path.join(request.folder, settings.password_upload_dir), label=T('Password file')),
        Field('f_type', 'string', label=T('File type'), default='PWDUMP', requires=IS_IN_SET(pw_set)),
        Field('f_message', 'string', label=T('Message to add')),
        buttons=buttons, _action=URL('accounts', 'update_hashes_by_file'), _id='accounts_update_hashes_by_file',
    )

    resp_text = ""
    accounts_added = []
    accounts_updated = []
    if request.vars.f_filename is not None:
        orig_filename = request.vars.f_filename.filename
    if form.errors:
        response.flash = 'Error in form'
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    elif form.accepts(request.vars, session):
        filename = os.path.join(request.folder, settings.password_upload_dir, form.vars.f_filename)
        logger.info("Processing password file: %s" % (filename))
        resp_text = process_cracked_file(pw_file=filename, file_type=request.vars.f_type, message=request.vars.f_message)

    response.title = "%s :: Update Password Hashes by File" % (settings.title)
    if request.extension == "json":
        return dict()
    else:
        return dict(form=form, resp_text=resp_text)

@auth.requires_login()
def import_mass_password():
    """
    Process a mass run of medusa/hydra.. result file will have IP addresses, service and info
    """
    if request.extension == "load":
        buttons=[]
    else:
        buttons=['submit']

    from skaldship.general import check_datadir
    check_datadir(request.folder)

    form=SQLFORM.factory(
        Field('f_filename', 'upload', uploadfolder=os.path.join(request.folder, settings.password_upload_dir),
              label=T('Password file'), requires=IS_NOT_EMPTY(error_message=T('Filename required'))),
        Field('f_ftype', 'string', label=T('File Type'), default="Medusa",
              requires=IS_IN_SET(('Medusa', 'Hydra', 'Metasploit Creds CSV'))),
        Field('f_proto', 'string', label=T('Protocol'), default='tcp', requires=IS_IN_SET(('tcp', 'udp', 'info'))),
        Field('f_number', 'integer', label=T('Port Number'), requires=IS_INT_IN_RANGE(0, 65536)),
        Field('f_message', 'string', label=T('Message to add')),
        Field('f_add_hosts', 'boolean', label=T('Add Hosts'), comment=T('Add missing hosts to the database')),
        buttons=buttons, _action=URL('accounts', 'import_mass_password'), _id='import_mass_password',
    )

    if form.errors:
        response.flash = 'Error in form'
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    elif form.accepts(request.vars, session):
        if request.vars.f_filename is not None:
            orig_filename = request.vars.f_filename.filename
        filename = os.path.join(request.folder, settings.password_upload_dir, form.vars.f_filename)
        logger.info("Processing password file: %s" % (filename))
        resp_text = process_mass_password(
            pw_file=filename,
            pw_type=request.vars.f_ftype,
            message=request.vars.f_message,
            proto=request.vars.f_proto,
            portnum=request.vars.f_number,
            add_hosts=request.vars.f_add_hosts,
            user_id=auth.user.id,
        )
        response.flash = resp_text

    response.title = "%s :: Import Mass Password File" % (settings.title)
    if request.extension == "json":
        return dict()
    else:
        return dict(form=form)

@auth.requires_login()
def paste():
    """
    Import and parse password pasted to a textbox into t_accounts
    """
    from skaldship.general import check_datadir
    check_datadir(request.folder)

    # Service_id is primary, host_id is secondary, if none then list
    # all the services
    svc_set = []
    url=URL('accounts', 'paste')
    if request.vars.has_key('service_id'):
        try:
            record = db.t_services[request.vars.service_id]
            svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))
            url = URL('accounts', 'paste', vars={'service_id':request.vars.service_id})
        except:
            pass
    elif request.vars.has_key('host_id'):
        try:
            host_record = get_host_record(request.vars.host_id)
            svc_records = db(db.t_services.f_hosts_id == host_record.id).select(cache=(cache.ram, 30))
            url = URL('accounts', 'paste', vars={'host_id':request.vars.host_id})
            for record in svc_records:
                svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))
        except:
            pass

    if len(svc_set) == 0:
        # all services
        svc_records = db(db.t_services).select(cache=(cache.ram,30))
        svc_set = []
        for record in svc_records:
            svc_set.append((record.id, "%s :: %s/%s" % (host_title_maker(db.t_hosts[record.f_hosts_id]), record.f_proto, record.f_number)))

    if request.extension == "load":
        buttons=[]
    else:
        buttons=['submit']

    form = SQLFORM.factory(
        Field('f_service', 'string', label=T('Host / Service'), requires=IS_IN_SET(svc_set), default=svc_set[0][0]),
        Field('f_pwtext', 'text', label=T('Password text')),
        Field('f_type', 'string', label=T('File type'), default='PWDUMP', requires=IS_IN_SET(settings.password_file_types)),
        Field('f_source', 'string', label=T('Source (if necessary)')),
        Field('f_add_to_evidence', 'boolean', label=T('Add file to Evidence')),
        buttons=buttons, _action=url, _id='accounts_paste_form'
        #_action=url, _id='accounts_paste_form', formstyle='bootstrap_modal'
    )

    resp_text = ""
    accounts_added = []
    accounts_updated = []
    if form.errors:
        response.flash = 'Error in form'
        return TABLE(*[TR(k, v) for k, v in form.errors.items()])
    elif form.accepts(request.vars, session):
        from utils import web2py_uuid
        host_id = db.t_services[form.vars.f_service].f_hosts_id
        pwd_file_dir = os.path.join(request.folder, 'data', 'passwords', 'other')
        if not os.path.exists(pwd_file_dir):
            from gluon.fileutils import mktree
            mktree(pwd_file_dir)
        filename = "%s-pwfile-%s" % (host_id, web2py_uuid())
        full_file_path = os.path.join(request.folder, 'data/passwords/other', filename)
        of = open(full_file_path, "w")
        of.write(form.vars.f_pwtext)
        of.close()

        logger.debug("Processing password file: %s" % (full_file_path))
        account_data = process_password_file(pw_file=full_file_path, file_type=request.vars.f_type, source=request.vars.f_source)
        response.headers['web2py-component-command'] = 'accounttable.fnReloadAjax();'
        resp_text = insert_or_update_acct(form.vars.f_service, account_data)

        if form.vars.f_add_to_evidence is True:
            # add the password file to evidence
            try:
                pwdata = open(full_file_path, "r").readlines()
            except Exception, e:
                logger.error("Error opening %s: %s" % (full_file_path, e))
                resp_text += "Error opening %s: %s\n" % (full_file_path, e)

            db.t_evidence.insert( f_hosts_id = host_id,
                                  f_type = 'Password File',
                                  f_text = form.vars.f_type,
                                  f_filename = filename,
                                  f_evidence = filename,
                                  f_data = pwdata)
            resp_text += "\n%s added to evidence\n" % (filename)
            db.commit()
        # cleanup/delete the temporary file
        #tmpfile.close()

    response.flash = resp_text
    if request.extension == "json":
        return dict()
    else:
        return dict(form=form)
