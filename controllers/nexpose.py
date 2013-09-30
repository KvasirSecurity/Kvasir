# encoding: utf-8
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Nexpose controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from nxajax import NXAJAX, ScanTemplates
from skaldship.nexpose import vuln_parse
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

##-------------------------------------------------------------------------
## Purge Nexpose data from database
##-------------------------------------------------------------------------
@auth.requires_login()
def purge():
    """
    Cleans out the nexpose static tables such as:
      t_vulndata
      t_vuln_refs,
      t_vuln_references,
      t_exploits,
      t_exploit_references,
    """
    response.title = "%s :: Nexpose Database Purge" % (settings.title)
    form = SQLFORM.factory(
        Field('vulndata', type='boolean', label=T('Purge ∏Vulnerability Data')),
        Field('exploits', type='boolean', label=T('Purge Exploit Data')),
        Field('are_you_sure', type='boolean', label=T('Are you sure?')),
    )

    if form.accepts(request.vars,session):
        if not form.vars.are_you_sure:
            form.errors.are_you_sure = 'ARE YOU SURE?'
        if form.vars.vulndata:
            response.flash = 'Deleted Nexpose Vulnerability Data (and Exploit References)'
            db.t_vulndata.truncate(mode="CASCADE")
            db.t_exploit_references.truncate()
        if form.vars.exploits:
            db.t_exploits.truncate(mode="CASCADE")
            response.flash = 'Deleted Nexpose Exploit Data'
    elif form.errors:
        response.flash = 'Error in form'

    return dict(form=form)

@auth.requires_login()
def vulnlist():
    """Produces a list of Nexpose vulnids for a select/search box"""
    from lxml import etree
    from StringIO import StringIO
    from NexposeAPI import VulnData
    import os, time

    vuln_class = VulnData()
    vuln_class.user_id = auth.user.f_nexpose_user or 'nxadmin'
    vuln_class.password = auth.user.f_nexpose_pw or 'password'
    vuln_class.host = auth.user.f_nexpose_host or 'localhost'
    vuln_class.port = auth.user.f_nexpose_port or '3780'
    nx_vuln_fname = os.path.join(request.folder, 'data', 'nexpose_vuln_summary.xml')
    if os.path.exists(nx_vuln_fname):
        # check to see if we should refresh the nexpose_vuln_summary.xml file
        ctime = os.stat(nx_vuln_fname).st_ctime
        if (time.time() - ctime >= 7500):
            update_summary = True
        else:
            update_summary = False
    else:
        update_summary = True

    if update_summary:
        if vuln_class.login():
            # pull the list out
            vuln_class.populate_summary()
            fout = open(nx_vuln_fname, "wb+")
            fout.writelines(vuln_class.vulnxml)
            fout.close()

    vulnxml = etree.parse(nx_vuln_fname)
    vdata = []
    counter = 0
    for vuln in vulnxml.iterfind('.//VulnerabilitySummary[@id]'):
        vdata.append([counter, vuln.get('id')])

    return dict(data=vdata)

@auth.requires_login()
def get_nexpose_vulndata():
    """Downloads the detailed vulnerability data from Nexpose based on
    a vulnid passed to it"""
    form = SQLFORM.factory(
        Field('nexid', 'string', label=T('Nexpose ID')),
        Field('update', 'boolean', label=T('Update existing')),
    )

    if form.accepts(request, session):
        nxvulns = VulnData()
        nxvulns.user_id = auth.user.f_nexpose_user or 'nxadmin'
        nxvulns.password = auth.user.f_nexpose_pw or 'password'
        nxvulns.host = auth.user.f_nexpose_host or 'localhost'
        nxvulns.port = auth.user.f_nexpose_port or '3780'
        if nxvulns.login():
            vulndetails = nxvulns.detail(form.vars.nexid)
            (vulnfields, references) = vuln_parse(vulndetails.find('Vulnerability'), fromapi=True)

            if not vulnfields:
                response.flash = "Invalid Nexpose ID"
                return dict(form=form)

            # add the vulnerability to t_vulndata
            try:
                vulnid = db.t_vulndata.insert(**vulnfields)
                response.flash("%s added to vulndb" % (form.vars.nexid))
                db.commit()
            except Exception, e:
                if form.vars.update:
                    try:
                        row = db(db.t_vulndata.f_vulnid == vulnfields['f_vulnid']).select().first()
                        row.update_record(**vulnfields)
                        vuln_id = row.id
                        response.flash("%s updated in vulndb" % (form.vars.nexid))
                        db.commit()
                    except Exception, e:
                        msg = "Error inserting %s to vulndata: %s" % (form.vars.nexid, e)
                        response.flash(msg)
                        logger.info(msg)
                        vulnid = None
                        db.commit()
                else:
                    msg = "Error inserting %s to vulndata: %s" % (form.vars.nexid, e)
                    response.flash(msg)
                    logger.info(msg)
                    vulnid = None

            # add the references
            if vulnid is not None and references:
                for reference in references:
                    # check to see if reference exists first
                    ref_id = db(db.t_vuln_refs.f_text == reference[1])
                    if ref_id.count() == 0:
                        # add because it doesn't
                        ref_id = db.t_vuln_refs.insert(f_source=reference[0], f_text=reference[1])
                    else:
                        # pick the first reference as the ID
                        ref_id = ref_id.select().first().id

                    # make many-to-many relationship with t_vuln_data
                    res = db.t_vuln_references.insert(f_vuln_ref_id=ref_id, f_vulndata_id=vulnid)
                    db.commit()

        else:
            response.flash = "Unable to login to Nexpose"
    elif form.errors:
        response.flash = "Error in form"

    return dict(form=form)

@auth.requires_login()
def vuln_update():
    # Update t_vulndata with vulndata from Nexpose
    # Requires username/password and hostname of a Nexpose
    # https instance. User can permit overwrite (updating)
    # the data if a Vulnerability ID exists in the db.

    from lxml import etree
    from StringIO import StringIO

    response.title = "%s :: Nexpose Vulnerability Update" % (settings.title)
    form = SQLFORM.factory(
        Field('hostname', default=auth.user.f_nexpose_host or 'localhost', requires=IS_NOT_EMPTY()),
        Field('port', default=auth.user.f_nexpose_port or '3780', requires=IS_NOT_EMPTY()),
        Field('username', default=auth.user.f_nexpose_user or 'nxadmin', requires=IS_NOT_EMPTY()),
        Field('password', 'password', default=auth.user.f_nexpose_pw, requires=IS_NOT_EMPTY()),
        Field('overwrite', 'boolean', default=False, label=T('Overwrite existing entries')),
    )

    if form.accepts(request.vars):
        napi = nexpose_api.NexposeAPI()
        napi.user_id = form.vars.username
        napi.password = form.vars.password
        napi.host = form.vars.hostname
        napi.port = form.vars.port
        if napi.login():
            # print("Logged in to Nexpose API")
            vuln_class = nexpose_api.VulnData()
            vuln_class.populate_summary(napi)
            if (vuln_class.vulnerabilities) > 0:
                existing_vulnids = []
                for r in db(db.t_vulndata()).select(db.t_vulndata.f_vulnid):
                    existing_vulnids.append(r.f_vulnid)

                logger.info("Found %d vulnerabilities in the database already." % (len(existing_vulnids)))

                vulnxml = etree.parse(StringIO(vuln_class.vulnxml))
                vulns_added = 0
                vulns_updated = 0
                vulns_skipped = 0
                for vuln in vulnxml.findall('VulnerabilitySummary'):

                    if vuln.attrib['id'] in existing_vulnids and not request.vars.overwrite:
                        # skip over existing entries if we're not overwriting
                        continue

                    vulndetails = vuln_class.detail(napi, vuln.attrib['id'])

                    (vulnfields, references) = vuln_parse(vulndetails.find('Vulnerability'), fromapi=True)

                    if not vulnfields: continue

                    # add the vulnerability to t_vulndata
                    try:
                        vulnid = db.t_vulndata.insert(**vulnfields)
                        vulns_added += 1
                        db.commit()
                    except Exception, e:
                        if request.vars.overwrite:
                            try:
                                row = db(db.t_vulndata.f_vulnid == vulnfields['f_vulnid']).select().first()
                                row.update_record(**vulnfields)
                                vulnid = row.id
                                vulns_updated += 1
                                db.commit()
                            except Exception, e:
                                logger.info("Error inserting %s to vulndata: %s" % (vulnfields['f_vulnid'], e))
                                vulnid = None
                                vulns_skipped += 1
                                db.commit()
                                continue
                        else:
                            logger.info("Error inserting %s to vulndata: %s" % (vulnfields['f_vulnid'], e))
                            vulnid = None
                            vulns_skipped += 1
                            db.commit()
                            continue

                    # add the references
                    if vulnid is not None and references:
                        for reference in references:
                            # check to see if reference exists first
                            ref_id = db(db.t_vuln_refs.f_text == reference[1])
                            if ref_id.count() == 0:
                                # add because it doesn't
                                ref_id = db.t_vuln_refs.insert(f_source=reference[0], f_text=reference[1])
                            else:
                                # pick the first reference as the ID
                                ref_id = ref_id.select().first().id

                            # make many-to-many relationship with t_vuln_data
                            res = db.t_vuln_references.insert(f_vuln_ref_id=ref_id, f_vulndata_id=vulnid)
                            db.commit()

                logger.info("%d vulns added, %d updated, %d skipped" % (vulns_added, vulns_updated, vulns_skipped))
                response.flash = "Completed - (A:%s/U:%s/S:%s)" % (vulns_added, vulns_updated, vulns_skipped)
        else:
            response.flash = "Unable to login to Nexpose"

    elif form.errors:
        response.flash = 'Error in form data'

    return dict(form=form)

@auth.requires_login()
def scan_template():
    from lxml import etree
    from StringIO import StringIO

    response.title = "%s :: Nexpose Scan Templates" % (settings.title)
    formupload = SQLFORM.factory(
        Field('f_filename', 'upload', uploadfolder=os.path.join(request.folder, 'data', 'misc'), label=T('Import Nexpose Scan Template')),
             _formname='uploader')

    if formupload.accepts(request.vars, formname='uploader'):
        najax = NXAJAX(session.najaxsession)
        template_class = ScanTemplates()
        filename = os.path.join(request.folder,'data','misc',formupload.vars.f_filename)
        template_xml = etree.parse(filename, etree.XMLParser())
        imported = template_class.importtemplate(etree.tostring(template_xml), najax)
        response.flash = imported
        templates = ScanTemplates.listscantemps(True, najax)
        parse_templates = DIV(TAG(templates).elements('templateid'))
        return dict(form="", form2=formupload, html=parse_templates)

    najax = NXAJAX(session.najaxsession)
    najax.host = auth.user.f_nexpose_host
    najax.port = auth.user.f_nexpose_port
    najax.user_id = auth.user.f_nexpose_user
    najax.password = auth.user.f_nexpose_pw
    if najax.login():
        logger.info("Logged in to Nexpose API. Session cached.")
        session.najaxsession = najax.getsession()
        template_class = ScanTemplates()
        templates = template_class.listscantemps(True, najax)
        response.flash = "Loaded %s scan templates" % (templates.count('<templateid>'))
        parse_templates = DIV(TAG(templates).elements('templateid'))
        return dict(form="", form2=formupload, html=parse_templates)
    else:
        response.flash = "Unable to login to Nexpose"

    return dict(form=formlogin, form2="", html="")

@auth.requires_login()
def list_scantemplates():
    response.title = "%s :: Nexpose Scan Templates" % (settings.title)
    html = DIV(TAG(session.templates).elements('templateid'))
    return dict(html=html)

@auth.requires_login()
def import_xml_scan():
    """
    Upload/import Nexpose XML Scan file via scheduler task
    """
    from NexposeAPI import NexposeAPI, Sites, Report
    from skaldship.general import check_datadir
    import time
    import os
    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitAPI import MetasploitAPI
        msf_api = MetasploitAPI(host=auth.user.f_msf_pro_url, apikey=auth.user.f_msf_pro_key)
        working_msf_api = msf_api.login()
    except:
        working_msf_api = False

    filedir = os.path.join(request.folder, 'data', 'scanfiles')
    response.title = "%s :: Import Nexpose XML Scan Results" % (settings.title)
    fields = []

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    # check to see if nexpose is configured/active and get site listing
    nxsitelist = []
    if auth.user.f_nexpose_host is not None and auth.user.f_nexpose_user is not None:
        # see if the host is open/active first
        if auth.user.f_nexpose_host is not None:
            sites = Sites()
            sites.host = auth.user.f_nexpose_host
            sites.port = auth.user.f_nexpose_port
            try:
                if sites.login(user_id=auth.user.f_nexpose_user, password=auth.user.f_nexpose_pw):
                    sites = sites.listings()
                    nxsitelist.append( [ 0, None ] )
                    for k,v in sites.iteritems():
                        nxsitelist.append( [int(k), sites[k]['name']] )
            except Exception, e:
                pass

    if nxsitelist:
        fields.append(Field('f_nexpose_site', type='integer', label=T('Nexpose Site'), requires=IS_IN_SET(nxsitelist, zero=None)))

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('Nexpose XML File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))

    # If Metasploit available, pull a list of the workspaces and present them
    if working_msf_api:
        msf_workspaces = []
        msf_workspaces.append( "None" )
        for w in msf_api.pro_workspaces().keys():
            msf_workspaces.append(w)
        fields.append(Field('f_msf_workspace', type='string', label=T('MSF Pro Workspace'), requires=IS_EMPTY_OR(IS_IN_SET(msf_workspaces, zero=None))))

    fields.append(Field('f_include_list', type='text', label=T('Hosts to Only Include')))
    fields.append(Field('f_ignore_list', type='text', label=T('Hosts to Ignore')))
    fields.append(Field('f_update_hosts', type='boolean', label=T('Update Host Information'), default=False))
    fields.append(Field('f_taskit', type='boolean', default=auth.user.f_scheduler_tasks, label=T('Run in background task')))
    form = SQLFORM.factory(*fields, table_name='nexpose_xml')

    # form processing
    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # process a nexpose file
        if not nxsitelist:
            nexpose_site = '0'
        else:
            nexpose_site = form.vars.f_nexpose_site

        if nexpose_site != '0':
            report = Report()
            report.host = auth.user.f_nexpose_host
            report.port = auth.user.f_nexpose_port
            nx_loggedin = report.login(user_id=auth.user.f_nexpose_user, password=auth.user.f_nexpose_pw)
            if nx_loggedin:
                # have nexpose generate the adhoc report
                check_datadir(request.folder)
                filename =  os.path.join(filedir, "%s-%s.xml" % (form.vars.f_asset_group, int(time.time())))
                fout = open(filename, "w")
                fout.write(report.adhoc_generate(filterid=nexpose_site))
                fout.close()
            else:
                response.flash = "Unable to login to Nexpose"
                return dict(form=form)
        else:
            filename = form.vars.f_filename
            filename = os.path.join(filedir, form.vars.f_filename)

        # build the hosts only/exclude list
        ip_exclude = []
        data = form.vars.get('f_ignore_list')
        if data:
            ip_exclude = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals
        ip_include = []
        data = form.vars.get('f_include_list')
        if data:
            ip_include = data.split('\r\n')
            # TODO: check for ip subnet/range and break it out to individuals

        if form.vars.f_msf_workspace:
            msf_workspace = form.vars.f_msf_workspace
            if msf_workspace == "None": msf_workspace = None
        else:
            msf_workspace = None

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='nexpose',
                    filename=filename,
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    msf_workspace=msf_workspace,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
                    update_hosts=form.vars.f_update_hosts,
                ),
                group_name=settings.scheduler_group_name,
                sync_output=5,
                timeout=3600   # 1 hour
            )
            if task.id:
                redirect(URL('tasks', 'status', args=task.id))
            else:
                response.flash = "Error submitting job: %s" % (task.errors)
        else:
            from skaldship.nexpose import process_xml
            logger.info("Starting Nexpose XML Import")
            process_xml(
                filename=filename,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_workspace=msf_workspace,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            response.flash = "Nexpose XML upload complete"
            redirect(URL('default', 'index'))

    return dict(form=form)
