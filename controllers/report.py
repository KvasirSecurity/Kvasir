# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Reporting controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.general import cvss_metrics
from skaldship.hosts import create_hostfilter_query
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return dict()

@auth.requires_login()
def spreadsheet():
    """
    Generate a Excel xlsx file of vulnerability and password statistics and charts
    """

    rows = db(db.t_hosts).select(db.t_hosts.f_asset_group, distinct=True)
    ags = [ag.f_asset_group for ag in rows]
    form=SQLFORM.factory(
        Field('ag_per_tab', 'boolean', default=False, label=T('Tab per Asset Group')),
        Field('asset_group', 'select', default=False, requires=IS_EMPTY_OR(IS_IN_SET(ags)), label=T('Specific Asset Group')),
    )
    response.title = "%s :: Excel Spreadsheet Generator" % (settings.title)
    if form.errors:
        response.flash = 'Error in form'
    elif form.process().accepted:
        if form.vars.asset_group:
            ags = [form.vars.asset_group]
        elif form.vars.ag_per_tab:
            rows = db(db.t_hosts).select(db.t_hosts.f_asset_group, distinct=True)
            ags = [ag.f_asset_group for ag in rows]
        else:
            ags = ['%']

        from skaldship.statistics import vulnlist, graphs_index
        from skaldship.general import vulntype_mapping
        import os
        from datetime import datetime
        from xlsxwriter.workbook import Workbook

        tmpfile = os.path.join(request.folder, 'data/stats/kvasir-stats-%s.xlsx' % datetime.now().strftime("%m%d%y-%H%M%S"))
        workbook = Workbook(tmpfile)
        bold = workbook.add_format({'bold': 1})

        # Create main statistics page / charts
        graphs = graphs_index()
        stat_worksheet = workbook.add_worksheet('Main Statistics')

        # Top Host Severity statistics / chart
        stat_worksheet.write('A1', 'Vuln Severity', bold)
        stat_worksheet.write('B1', 'Host Count', bold)
        row_num = 1
        col_num = 0
        for sev_cnt in graphs['top_host_sev_count_raw']:
            stat_worksheet.write_number(row_num, col_num, row_num)
            stat_worksheet.write_number(row_num, col_num+1, int(sev_cnt))
            row_num += 1

        stat_chart_host = workbook.add_chart({'type': 'column'})
        stat_chart_host.add_series({
            'categories': ["'Main Statistics'", 1, 0, row_num-1, 0],
            'values': ["'Main Statistics'", 1, 1, row_num-1, 1],
            'name': 'Host Count',
        })
        stat_chart_host.set_title({'name': 'Top Host Severities'})
        stat_chart_host.set_table({'show_keys': True})
        stat_chart_host.set_legend({'position': 'none'})
        stat_chart_host.set_x_axis({
            'min': 1,
            'max': 10,
            'name_font': {'bold': True},
        })
        stat_chart_host.set_size({'width': 768, 'height': 576})
        stat_worksheet.insert_chart('A13', stat_chart_host)

        # Vulnerability Severity statistics / chart
        stat_worksheet.write('D1', 'Vuln Severity', bold)
        stat_worksheet.write('E1', 'Vuln Count', bold)
        row_num = 1
        col_num = 3
        for sev_cnt in graphs['vuln_by_sev_count_raw']:
            stat_worksheet.write_number(row_num, col_num, row_num)
            stat_worksheet.write_number(row_num, col_num+1, int(sev_cnt))
            row_num += 1

        stat_chart_vulns = workbook.add_chart({'type': 'column'})
        stat_chart_vulns.add_series({
            'categories': ["'Main Statistics'", 1, 3, row_num-1, 3],
            'values': ["'Main Statistics'", 1, 4, row_num-1, 4],
            'name': 'Vulnerability Count',
        })
        stat_chart_vulns.set_title({'name': 'Top Vulnerability Severities'})
        stat_chart_vulns.set_table({'show_keys': True})
        stat_chart_vulns.set_legend({'position': 'none'})
        stat_chart_vulns.set_x_axis({
            'min': 1,
            'max': 10,
            'name_font': {'bold': True},
        })
        stat_chart_vulns.set_size({'width': 768, 'height': 576})
        stat_worksheet.insert_chart('G13', stat_chart_vulns)

        # Create tab(s) for vulnerability listings and charts
        for ag in ags:
            if ag == "%":
                ag = "Vulnlist"
                hostfilter = [(None, None), False]
            else:
                hostfilter = [('assetgroup', ag), False]

            vl_worksheet = workbook.add_worksheet(ag)
            vl_worksheet.write('A1', 'Vulnerability ID', bold)
            vl_worksheet.set_column(1, 0, 45)
            vl_worksheet.write('B1', 'Status', bold)
            vl_worksheet.set_column(1, 1, 20)
            vl_worksheet.write('C1', 'Count', bold)
            vl_worksheet.write('D1', 'Severity', bold)
            vl_worksheet.write('E1', 'CVSS Score', bold)

            # { 'vulnerability id': [ status, count, severity, cvss ] }
            vlist = vulnlist(hostfilter)
            vuln_count = 1
            vl_stats = {}
            for k, v in vlist.iteritems():
                col_num = 0
                for row in v:
                    (status, count, severity, cvss) = row
                    vl_worksheet.write_string(vuln_count, col_num, k)
                    vl_worksheet.write_string(vuln_count, col_num + 1, status)
                    vl_worksheet.write_number(vuln_count, col_num + 2, int(count))
                    vl_worksheet.write_number(vuln_count, col_num + 3, int(severity))
                    if cvss:
                        vl_worksheet.write_number(vuln_count, col_num + 4, float(cvss))
                    vuln_count += 1

                    # make vl_stats dictionary:
                    # { 'status': { 1: count, 2:count ... }}
                    vl_tmpstatus = vl_stats.setdefault(status, {
                        1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0
                    })
                    status_tmp = vl_tmpstatus.setdefault(severity, 0)
                    vl_tmpstatus[severity] = status_tmp + count
                    vl_stats[status] = vl_tmpstatus

            # create vulnerability severity distribution chart
            vl_chart_ws_name = "%s VulnChart" % (ag)
            vl_chart_worksheet = workbook.add_worksheet(vl_chart_ws_name)
            vl_chart_worksheet.write('A1', 'Severity', bold)
            vl_chart = workbook.add_chart({'type': 'column'})
            for k,v in vl_stats.iteritems():
                vl_chart_worksheet.write(0, col_num, k, bold)
                row_num = 1
                for k2,v2 in v.iteritems():
                    vl_chart_worksheet.write(row_num, 0, k2)
                    vl_chart_worksheet.write(row_num, 1, v2)
                    row_num += 1

                vl_chart.add_series({
                    'categories': ["'%s'" % (vl_chart_ws_name), 1, 0, row_num-1, 0],
                    'values': ["'%s'" % (vl_chart_ws_name), 1, col_num, row_num-1, col_num],
                    'name': k,
                    'color': vulntype_mapping(k)
                })
                col_num += 1

            # if multiple account groups, change title accordingly
            if ag == "Vulnlist":
                vl_chart.set_title({'name': 'Vulnerability Severity Distribution'})
            else:
                vl_chart.set_title({'name': 'Vulnerability Severity Distribution: %s' % (ag)})

            vl_chart.set_table({'show_keys': True})
            vl_chart.set_legend({'position': 'none'})
            vl_chart.set_x_axis({
                'min': 1,
                'max': 10,
                'name_font': {'bold': True},
            })
            vl_chart.set_size({'width': 960, 'height': 576})

            vl_chart_worksheet.insert_chart('A13', vl_chart)

        # Top 15 passwords and UNIX / Windows distribution and compromised pie charts
        password_worksheet = workbook.add_worksheet('Passwords')
        pw_cnt = db.t_accounts.f_password.count()
        top15 = db(db.t_accounts.f_password != None).select(db.t_accounts.f_password, pw_cnt, groupby=db.t_accounts.f_password, orderby=~pw_cnt, limitby=(0,15))
        password_worksheet.write('A1', 'Password', bold)
        password_worksheet.write('B1', 'Count', bold)
        row_num = 1
        for row in top15:
            password_worksheet.write(row_num, 0, row.t_accounts.f_password)
            password_worksheet.write(row_num, 1, row._extra['COUNT(t_accounts.f_password)'])
            row_num += 1

        # all done!
        workbook.close()
        redirect(URL('default', 'data_dir/stats'))

    return dict(form=form)

@auth.requires_login()
def customer_xml():
    """
    Generates an XML file suitable for Customer usage
    """

    from lxml import etree

    # grab the filter type and value if provided or from the session
    if session.hostfilter is None:
        f_type  = request.vars.f_type or None
        f_value = request.vars.f_value or None
    else:
        f_type  = session.hostfilter[0]
        f_value = session.hostfilter[1]

    location_attribute = '{%s}noNameSpaceSchemaLocation' % "http://www.w3.org/2001/XMLSchema-instance"
    kvasir_results_xml = etree.Element('KvasirResults', attrib={ location_attribute: 'kvasir.xsd', })

    summary_xml = etree.SubElement(kvasir_results_xml, 'summary')
    customer = etree.SubElement(summary_xml, 'customer')
    customer.text = settings.customer or 'CUSTOMER NAME'
    assessment = etree.SubElement(summary_xml, 'assessment')
    assessment.set('type', settings.assessment_type)
    start_date = etree.SubElement(assessment, 'start-date')
    start_date.text = settings.start_date or 'START DATE'
    end_date = etree.SubElement(assessment, 'end-date')
    end_date.text = settings.end_date or 'END DATE'

    hosts_xml = etree.SubElement(kvasir_results_xml, 'hosts')
    os_xml = etree.SubElement(kvasir_results_xml, 'os_records')
    vulns_xml = etree.SubElement(kvasir_results_xml, 'vulns')

    # this is a little hack to ensure a record is either blank or None
    # use it as "if variable not in notin:"
    notin = [ None, '' ]
    unknown_cpeid_counter = 0

    # go through each host, adding the os, services and vulns accordingly
    query = create_hostfilter_query([(f_type, f_value), False])
    for host_rec in db(query).select():
        host_xml = etree.SubElement(hosts_xml, 'host')
        host_xml.set('ipv4', host_rec.f_ipv4)
        host_xml.set('assetgroup', host_rec.f_asset_group)
        if host_rec.f_ipv6:
            host_xml.set('ipv6', host_rec.f_ipv6)
        if host_rec.f_macaddr:
            host_xml.set('macaddr', host_rec.f_macaddr)
        if host_rec.f_hostname:
            host_xml.set('hostname', host_rec.f_hostname.decode('utf-8'))
        if host_rec.f_netbios_name:
            host_xml.set('netbios', host_rec.f_netbios_name.decode('utf-8'))

        # build the os information using the highest certainty record
        highest = (0, None)
        for os_rec in db(db.t_host_os_refs.f_hosts_id == host_rec.id).select():
            if os_rec.f_certainty > highest[0]:
                highest = (os_rec.f_certainty, os_rec)

        if highest[0] > 0:
            # add os element to the host
            record = highest[1]
            os = etree.SubElement(host_xml, 'os')
            os.set('certainty', str(highest[0]))
            if record.f_class not in notin:
                os.set('class', record.f_class)
            if record.f_family not in notin:
                os.set('family', record.f_family)

            # since some os records may not have a cpe id we'll mask them with
            # using their title, replacing spaces with underscores
            t_os_rec = db.t_os[record.f_os_id]
            if t_os_rec.f_cpename in notin:
                cpeid = t_os_rec.f_title.replace(' ', '_')
            else:
                cpeid = t_os_rec.f_cpename

            os.set('id', cpeid)

            # if the id isn't in os_records, add it
            if len(os_xml.findall('.//os[@id="%s"]' % (os.get('id', None)))) < 1:
                os_info_xml = etree.SubElement(os_xml, 'os')
                os_rec = db.t_os[highest[1].f_os_id]
                os_info_xml.set('id', cpeid)
                os_info_xml.set('title', os_rec.f_title)

                if os_rec.f_vendor not in notin:
                    vendor = etree.SubElement(os_info_xml, 'vendor')
                    vendor.text = os_rec.f_vendor

                if os_rec.f_product not in notin:
                    product = etree.SubElement(os_info_xml, 'product')
                    product.text = os_rec.f_product

                if os_rec.f_version not in notin:
                    version = etree.SubElement(os_info_xml, 'version')
                    version.text = os_rec.f_version

                if os_rec.f_update not in notin:
                    update = etree.SubElement(os_info_xml, 'update')
                    update.text = os_rec.f_update

                if os_rec.f_edition not in notin:
                    edition = etree.SubElement(os_info_xml, 'edition')
                    edition.text = os_rec.f_edition

                if os_rec.f_language not in notin:
                    language = etree.SubElement(os_info_xml, 'language')
                    language.text = os_rec.f_language

        # snmp strings
        snmp_recs = db(db.t_snmp.f_hosts_id == host_rec.id).select()
        if len(snmp_recs) > 0:
            snmp_top_xml = etree.SubElement(hosts_xml, 'snmps')
            for record in snmp_recs:
                snmp_xml = etree.SubElement(snmp_top_xml, 'snmp')
                if record.f_community not in notin:
                    snmp_xml.set('community', record.f_community.decode('utf-8'))
                    snmp_xml.set('version', record.f_version)
                    snmp_xml.set('access', record.f_access)

        # netbios information
        netb_record = db(db.t_netbios.f_hosts_id == host_rec.id).select().first() or None
        if netb_record:
            netbios_xml = etree.SubElement(hosts_xml, 'netbios')
            if netb_record.f_type not in notin:
                netbios_xml.set('type', netb_record.f_type)
            if netb_record.f_domain not in notin:
                netbios_xml.set('domain', netb_record.f_domain.decode('utf-8'))
            if netb_record.f_lockout_limit not in notin:
                netbios_xml.set('lockout_limit', str(netb_record.f_lockout_limit))
            if netb_record.f_lockout_duration not in notin:
                netbios_xml.set('lockout_duration', str(netb_record.f_lockout_duration))

            if netb_record.f_advertised_names is not None:
                adv_names_xml = etree.SubElement(netbios_xml, 'advertised_names')
                for name in netb_record.f_advertised_names:
                    name_xml = etree.SubElement(adv_names_xml, 'name')
                    name.text = name.decode('utf-8')

        # build the services and vulnerabilities
        services_xml = etree.SubElement(host_xml, 'services')
        for svc_rec in db(db.t_services.f_hosts_id == host_rec.id).select():
            service_xml = etree.SubElement(services_xml, 'service')
            service_xml.set('proto', svc_rec.f_proto)
            service_xml.set('number', svc_rec.f_number)

            if svc_rec.f_name not in notin:
                name = etree.SubElement(service_xml, 'name')
                name.text = svc_rec.f_name.decode('utf-8')

            if svc_rec.f_banner not in notin:
                banner = etree.SubElement(service_xml, 'banner')
                banner.text = svc_rec.f_banner.decode('utf-8')

            # service configuration records
            svc_info_recs = db(db.t_service_info.f_services_id == svc_rec.id).select()
            if len(svc_info_recs) > 0:
                config_xml = etree.SubElement(service_xml, 'configuration')
                for info_rec in svc_info_recs:
                    rec_xml = etree.SubElement(config_xml, 'config')
                    if info_rec.f_name not in notin:
                        rec_xml.set('name', info_rec.f_name)
                        if info_rec.f_text not in notin:
                            rec_xml.text = info_rec.f_text.decode('utf-8')

            # vulnerabilities
            svc_vuln_recs = db(db.t_service_vulns.f_services_id == svc_rec.id).select()
            if len(svc_vuln_recs) > 0:
                svc_vulns_xml = etree.SubElement(service_xml, 'vulns')
                for vuln_rec in svc_vuln_recs:
                    vuln_xml = etree.SubElement(svc_vulns_xml, 'vuln')
                    vuln_xml.set('status', vuln_rec.f_status)
                    vuln_xml.set('id', db.t_vulndata[vuln_rec.f_vulndata_id].f_vulnid)
                    proof = etree.SubElement(vuln_xml, 'proof')
                    proof.text = etree.CDATA(unicode(MARKMIN(vuln_rec.f_proof).xml(), 'utf-8'))

                    # search for the nexpose id in vulns_xml
                    if len(vuln_xml.findall('.//vuln[@id="%s"]' % vuln_xml.get('id', None))) < 1:
                        new_vuln_xml = etree.SubElement(vulns_xml, 'vuln')
                        vulndata = db.t_vulndata[vuln_rec.f_vulndata_id]
                        new_vuln_xml.set('id', vulndata.f_vulnid)
                        new_vuln_xml.set('title', vulndata.f_title)
                        new_vuln_xml.set('severity', str(vulndata.f_severity))
                        new_vuln_xml.set('pci_sev', str(vulndata.f_pci_sev))
                        new_vuln_xml.set('cvss_score', vulndata.f_cvss_score)
                        new_vuln_xml.set('cvss_metric', cvss_metrics(vulndata))
                        description = etree.SubElement(new_vuln_xml, 'description')
                        description.text = etree.CDATA(unicode(MARKMIN(vulndata.f_description).xml(), 'utf-8'))
                        solution = etree.SubElement(new_vuln_xml, 'solution')
                        solution.text = etree.CDATA(unicode(MARKMIN(vulndata.f_solution).xml(), 'utf-8'))

                        # find vulnerability references and add them
                        vuln_refs = db(db.t_vuln_references.f_vulndata_id == vulndata.id).select()
                        if len(vuln_refs) > 0:
                            refs_xml = etree.SubElement(new_vuln_xml, 'references')
                            for ref_rec in vuln_refs:
                                record = db.t_vuln_refs[ref_rec.f_vuln_ref_id]
                                ref_xml = etree.SubElement(refs_xml, 'reference')
                                ref_xml.set('source', record.f_source)
                                ref_xml.text = record.f_text.decode('utf-8')

            # accounts
            accounts = db(db.t_accounts.f_services_id == svc_rec.id).select()
            if len(accounts) > 0:
                accounts_xml = etree.SubElement(service_xml, 'accounts')
                for acct_rec in accounts:
                    acct_xml = etree.SubElement(accounts_xml, 'account')

                    if acct_rec.f_username not in notin:
                        elem = etree.SubElement(acct_xml, 'username')
                        elem.text = acct_rec.f_username.decode('utf-8')

                    if acct_rec.f_fullname not in notin:
                        elem = etree.SubElement(acct_xml, 'fullname')
                        elem.text = acct_rec.f_fullname.decode('utf-8')

                    if acct_rec.f_password not in notin:
                        elem = etree.SubElement(acct_xml, 'password')
                        elem.text = acct_rec.f_password.decode('utf-8')

                    if acct_rec.f_hash1 not in notin:
                        elem = etree.SubElement(acct_xml, 'hash1')
                        elem.text = acct_rec.f_hash1

                    if acct_rec.f_hash1_type not in notin:
                        elem = etree.SubElement(acct_xml, 'hash1_type')
                        elem.text = acct_rec.f_hash1_type

                    if acct_rec.f_hash2 not in notin:
                        elem = etree.SubElement(acct_xml, 'hash2')
                        elem.text = acct_rec.f_hash2

                    if acct_rec.f_hash2_type not in notin:
                        elem = etree.SubElement(acct_xml, 'hash2_type')
                        elem.text = acct_rec.f_hash2_type

                    if acct_rec.f_uid not in notin:
                        elem = etree.SubElement(acct_xml, 'uid')
                        elem.text = acct_rec.f_uid

                    if acct_rec.f_gid not in notin:
                        elem = etree.SubElement(acct_xml, 'gid')
                        elem.text = acct_rec.f_gid

                    if acct_rec.f_level not in notin:
                        elem = etree.SubElement(acct_xml, 'level')
                        elem.text = acct_rec.f_level

                    if acct_rec.f_domain not in notin:
                        elem = etree.SubElement(acct_xml, 'domain')
                        elem.text = acct_rec.f_domain.decode('utf-8')

                    if acct_rec.f_description not in notin:
                        elem = etree.SubElement(acct_xml, 'description')
                        elem.text = acct_rec.f_description.decode('utf-8')

    result = etree.tostring(kvasir_results_xml, pretty_print=True, encoding=unicode)
    return result
