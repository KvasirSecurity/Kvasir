_a = request.application

response.logo = A(B('KVASIR'), _class="brand")
response.title = settings.title
response.subtitle = settings.subtitle
response.meta.author = '%s <%s>' % (settings.author, settings.author_email)
response.meta.keywords = settings.keywords
response.meta.description = settings.description

response.menu = [
    (T('Home'), False, URL(_a,'default','index'), []),
    # (A(I(_class='icon-home icon-white'), T('Home'), _href=URL('default', 'index')), False, []),
    (T('All Hosts'), False, URL(_a,'hosts','list'), []),
    # (A(I(_class='icon-th-list icon-white'), T('All Hosts'), _href=URL('hosts', 'list')), False, []),
    (T('Host Data'), False, '',
     [
         (T('Add Host'), False, URL(_a,'hosts','add'), []),
         (T('Services'), False, '',
          [
              (T('List All'), False, URL(_a,'services','list'), []),
              (T('All w/ Vulns'), False, URL(_a,'vulns','service_vulns_list'), []),
              (T('IPs w/ Port'), False, URL(_a,'services','hosts_with_port'), []),
              (T('Add'), False, URL(_a,'services','add'), []),
          ]),
         (T('Accounts'), False, '',
          [
              (T('List'), False, URL(_a,'accounts', 'list'), []),
              (T('Add'), False, URL(_a,'accounts', 'add'), []),
              (T('Import File'), False, URL(_a,'accounts', 'import_file'), []),
              (T('Mass Import'), False, URL(_a,'accounts', 'import_mass_password'), []),
              (T('Process crack file'), False, URL(_a,'accounts', 'update_hashes_by_file'), []),
              (T('Process john.pot'), False, URL(_a,'accounts', 'check_john_pot'), []),
          ]),
         (T('NetBIOS'), False, '',
          [
              (T('Domain Details'), False, URL(_a,'netbios','domain_detail'), []),
              (T('List'), False, URL(_a,'netbios','index'), []),
              (T('Add'), False, URL(_a,'netbios','add'), []),
          ]),
         (T('OS'), False, '',
          [
              (T('List'), False, URL(_a,'os','list'), []),
              (T('Add '), False, URL(_a,'os','add'), []),
              (T('List OS Refs'), False, URL(_a,'os','refs_list'), []),
              (T('Add OS Ref'), False, URL(_a,'os','refs_add'), []),
          ]),
         (T('Other'), False, '',
          [
              (T('List Evidence'), False, URL(_a,'evidence','list'), []),
              (T('List Notes'), False, URL(_a,'notes','list'), []),
              (T('List SNMP'), False, URL(_a,'snmp','list'), []),
              (T('CSV Hostname Update'), False, URL(_a,'hosts','csv_hostupdate'), []),
          ]),
     ]),

    (T('Tasks'), False, URL(_a,'tasks','index'), []),

    (T('Metasploit'), False, '',
     [
         (T('Mass Jobs'), False, '',
         [
            (T('Bruteforce'), False, URL(_a, 'metasploit', 'bruteforce'), []),
            (T('Exploit'), False, URL(_a, 'metasploit', 'exploit'), []),
         ]),
         (T('Imports'), False, '',
         [
             (T('PWDUMP Files'), False, URL(_a, 'metasploit', 'import_pwdump'), []),
             (T('Screenshots'), False, URL(_a, 'metasploit', 'import_screenshots'), []),
             (T('Report XML'), False, URL(_a, 'metasploit', 'import_report_xml'), []),
         ]),
         (T('Send Accounts'), False, URL(_a, 'metasploit', 'send_accounts'), []),
         (T('Send Scan XML Files'), False, URL(_a, 'metasploit', 'send_scanxml'), []),
         (T('API Settings'), False, URL(_a, 'metasploit', 'api_settings'), []),
         #(T('Tasks'), False, URL(_a, 'metasploit', 'task_list'), []),
     ]),
    (T('Other'), False, '',
     [
         (T('Browse Data Directory'), False, URL(_a, 'default', 'data_dir'), []),
         (T('Customer XML'),URL(_a,'report','customer_xml.xml')==URL(),URL(_a,'report','customer_xml.xml'),[]),
         (T('Stats XLS'),URL(_a,'report','spreadsheet')==URL(),URL(_a,'report','spreadsheet'),[]),
         (T('Wiki'),URL(_a,'default','wiki')==URL(),URL(_a,'default','wiki'),[]),
         (T('Update DB Fields'),URL(_a,'default','update_dynamic_fields')==URL(),URL(_a,'default','update_dynamic_fields'),[]),
         (T('IP Calculator'), False, URL(_a, 'default', 'ip_calc'), []),
     ]),
    (T('Statistics'), False, '',
    [
        (T('Vulnlist'), False, URL(_a,'stats','vulnlist'), []),
        (T('Passwords'), False, URL(_a,'stats','passwords'), []),
        (T('OS'), False, URL(_a,'stats','os'), []),
        (T('Services'), False, URL(_a,'stats','services'), []),
        (T('VulnCircles'), False, URL(_a,'stats','vulncircles'), []),
    ]),
    (T('Import'), False ,'',
     [
         (T('Nexpose XML'), False, URL(_a,'nexpose','import_xml_scan'), []),
         (T('nMap XML'), False, URL(_a,'nmap','import_xml_scan'), []),
         (T('Nessus XML'), False, URL(_a,'nessus','import_xml_scan'), []),
         (T('Metasploit XML'), False, URL(_a, 'metasploit', 'import_report_xml'), []),
         (T('ShodanHQ'), False, URL(_a, 'shodanhq', 'import_report'), []),
     ]),
    (T('Administration'), False, '',
     [
         (T('Nexpose'), False, '',
          [
              (T('Install/Update VulnData'),URL(_a,'nexpose','vuln_update')==URL(),URL(_a,'nexpose','vuln_update'),[]),
              #(T('Import Scan Template '),URL(_a,'nexpose','scan_template')==URL(),URL(_a,'nexpose','scan_template'),[]),
              (T('Import VulnID'), False, URL(_a, 'nexpose', 'import_vulnid'), []),
              (T('Import Exploit XML'),URL(_a,'exploits','import_nexpose_xml')==URL(),URL(_a,'exploits','import_nexpose_xml'),[]),
              (T('Purge Nexpose Data'),URL(_a,'nexpose','purge')==URL(),URL(_a,'nexpose','purge'),[]),
          ]),
         (T('VulnDB'), False, '',
          [
              (T('List Vulnerabilities'), False, URL(_a,'vulns','vulndata_list'),[]),
              (T('Add Vulnerability'), False, URL(_a,'vulns','vulndata_add'),[]),
              (T('List References'), False, URL(_a,'vulns','vuln_references_list'),[]),
              (T('List Exploits'), False, URL(_a,'exploits','list'),[]),
              (T('Connect Vulns/Exploits'), False, URL(_a,'exploits','connect_exploits'), []),
              (T('Import Nexpose Exploits'), False, URL(_a,'exploits','import_nexpose_xml'),[]),
              (T('Import CANVAS Exploits'), False, URL(_a,'exploits','import_canvas_xml'),[]),
          ]),
         (T('CPE Database'), False, '',
          [
              (T('Import CPE Data'), False, URL(_a,'cpe','import_cpe_xml'), []),
              (T('List OS DB'), False, URL(_a,'cpe','os_list'), []),
              (T('Add OS'), False, URL(_a,'cpe','os_add'), []),
              #(T('List Application DB'), False, URL(_a,'cpe','apps_list'), []),
              #(T('Add Application'), False, URL(_a,'cpe','apps_add'), []),
              #(T('List Hardware DB'), False, URL(_a,'cpe','hardware_list'), []),
              #(T('Add Hardware'), False, URL(_a,'cpe','hardware_add'), []),
              (T('Purge CPE DB'), False, URL(_a,'cpe','purge'), []),
          ]),
         (T('Last Resort'), False, '',
          [
              (T('CSV Backup'), False, URL(_a,'default','database_backup'),[]),
              (T('CSV Restore'), False, URL(_a,'default','database_restore'),[]),
              (T('Purge Data'), URL(_a,'default','purge_data')==URL(),URL(_a,'default','purge_data'),[]),
          ]),
     ]),
]
