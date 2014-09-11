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
from skaldship.nexpose import nexpose_get_config
import logging
from skaldship.log import log
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

@auth.requires_login()
def vulnlist():
    """
    Produces a list of Nexpose vulnids for a select/search box
    """
    try:
        from lxml import etree
    except ImportError:
        try:
            from xml.etree import cElementTree as etree
        except ImportError:
            from xml.etree import ElementTree as etree

    from NexposeAPI import VulnData
    import os
    import time

    nexpose_config = nexpose_get_config()

    vuln_class = VulnData()
    vuln_class.host = nexpose_config['host']
    vuln_class.port = nexpose_config['port']

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
        if vuln_class.login(user_id=nexpose_config['user'], password=nexpose_config['password']):
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
def import_vulnid():
    """
    Downloads the detailed vulnerability data from Nexpose based on
    a vuln id passed to it
    """
    form = SQLFORM.factory(
        Field('nexid', 'string', label=T('Nexpose ID')),
        Field('nexid_list', 'text', label=T('Nexpose ID List'))
    )

    response.title = "%s :: Import Nexpose VulnID" % settings.title
    nexpose_config = nexpose_get_config()

    if form.process().accepted:
        from NexposeAPI import VulnData
        from skaldship.nexpose import vuln_parse

        nxvulns = VulnData()
        nxvulns.host = nexpose_config['host']
        nxvulns.port = nexpose_config['port']

        nexpose_ids = []
        if form.vars.nexid:
            nexpose_ids.extend([form.vars.nexid])
        if form.vars.nexid_list:
            nexpose_ids.extend(form.vars.nexid_list.split('\r\n'))

        res = nxvulns.login(user_id=nexpose_config['user'], password=nexpose_config['password'])
        if res:
            stats = {'added': 0, 'invalid':  0}
            for nexid in nexpose_ids:
                vulndetails = nxvulns.detail(nexid)
                if vulndetails is not None:
                    (vulnfields, references) = vuln_parse(vulndetails.find('Vulnerability'), fromapi=True)
                else:
                    stats['invalid'] += 1
                    continue

                # add the vulnerability to t_vulndata
                query = (db.t_vulndata.f_vulnid == nexid)
                vulnid = db.t_vulndata.update_or_insert(query, **vulnfields)
                if not vulnid:
                    row = db(query).select().first()
                    if row:
                        vulnid = row.id
                    else:
                        log(" [!] Could not find %s in database.." % nexid, logging.WARN)
                        stats['invalid'] += 1
                        continue

                db.commit()

                # add the references
                if vulnid is not None and references:
                    for reference in references:
                        # check to see if reference exists first
                        query = (db.t_vuln_refs.f_source == reference[0]) & (db.t_vuln_refs.f_text == reference[1])
                        ref_id = db.t_vuln_refs.update_or_insert(query, f_source=reference[0], f_text=reference[1])
                        if not ref_id:
                            ref_id = db(query).select().first().id

                        # make many-to-many relationship with t_vuln_data
                        db.t_vuln_references.update_or_insert(f_vuln_ref_id=ref_id, f_vulndata_id=vulnid)
                        db.commit()

                from skaldship.exploits import connect_exploits
                connect_exploits()
                log(" [-] Added Nexpose vulnerability: %s" % nexid)
                stats['added'] += 1
            response.flash = "%s added, %s skipped" % (stats['added'], stats['invalid'])
            return dict(form=form)
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

    response.title = "%s :: Nexpose Vulnerability Update" % settings.title
    form = SQLFORM.factory(
        Field('overwrite', 'boolean', default=False, label=T('Update existing')),
        Field('background', 'boolean', default=False, label=T('Run in background task'),
              requires=IS_NOT_EMPTY(error_message='Can only be run in background')
        ),
        Field('timeout', 'integer', default=144000, label=T('Timeout (in seconds)')),
        Field('do_import', 'boolean', default=False, label=T('Start the import'),
              requires=IS_NOT_EMPTY(error_message='Are you ready?')
        ),
    )

    nexpose_config = nexpose_get_config()
    if form.process().accepted:
        nexpose_server = {
            'host': nexpose_config['host'],
            'port': nexpose_config['port'],
            'user': nexpose_config['user'],
            'pw': nexpose_config['password'],
        }
        task = scheduler.queue_task(
            import_all_nexpose_vulndata,
            pvars=dict(
                overwrite=form.vars.overwrite,
                nexpose_server=nexpose_server,
            ),
            group_name=settings.scheduler_group_name,
            sync_output=5,
            repeats=1,
            timeout=form.vars.timeout,
        )
        if task.id:
            redirect(URL('tasks', 'status', args=task.id))
        else:
            response.flash = "Error submitting job: %s" % (task.errors)

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

    nexpose_config = nexpose_get_config()
    najax = NXAJAX(session.najaxsession)
    najax.host = nexpose_config['host']
    najax.port = nexpose_config['port']
    if najax.login(user_id=nexpose_config['user'], password=nexpose_config['password']):
        log("Logged in to Nexpose API. Session cached.")
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
    from skaldship.metasploit import msf_get_config
    import time
    import os
    msf_settings = msf_get_config(session)
    try:
        # check to see if we have a Metasploit RPC instance configured and talking
        from MetasploitProAPI import MetasploitProAPI
        msf_api = MetasploitProAPI(host=msf_settings['url'], apikey=msf_settings['key'])
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
    nexpose_config = nexpose_get_config()
    nxsitelist = []
    if nexpose_config['host'] is not None and nexpose_config['user'] is not None:
        # see if the host is open/active first
        if nexpose_config['host'] is not None:
            sites = Sites()
            sites.host = nexpose_config['host']
            sites.port = nexpose_config['port']
            try:
                if sites.login(user_id=nexpose_config['user'], password=nexpose_config['password']):
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
            report.host = nexpose_config['host']
            report.port = nexpose_config['port']
            nx_loggedin = report.login(user_id=nexpose_config['user'], password=nexpose_config['password'])
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
            if msf_workspace == "None":
                msf_workspace = None
        else:
            msf_workspace = None
        msf_settings = {'workspace': msf_workspace, 'url': msf_settings['url'], 'key': msf_settings['key']}

        if form.vars.f_taskit:
            task = scheduler.queue_task(
                scanner_import,
                pvars=dict(
                    scanner='nexpose',
                    filename=filename,
                    asset_group=form.vars.f_asset_group,
                    engineer=form.vars.f_engineer,
                    msf_settings=msf_settings,
                    ip_ignore_list=ip_exclude,
                    ip_include_list=ip_include,
                    update_hosts=form.vars.f_update_hosts,
                ),
                group_name=settings.scheduler_group_name,
                sync_output=5,
                timeout=settings.scheduler_timeout
            )
            if task.id:
                redirect(URL('tasks', 'status', args=task.id))
            else:
                response.flash = "Error submitting job: %s" % (task.errors)
        else:
            from skaldship.nexpose import process_xml
            log("Starting Nexpose XML Import")
            process_xml(
                filename=filename,
                asset_group=form.vars.f_asset_group,
                engineer=form.vars.f_engineer,
                msf_settings=msf_settings,
                ip_ignore_list=ip_exclude,
                ip_include_list=ip_include,
                update_hosts=form.vars.f_update_hosts,
            )
            response.flash = "Nexpose XML upload complete"
            redirect(URL('default', 'index'))

    return dict(form=form)
