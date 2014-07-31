# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Metasploit Utilities for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from gluon import current
from skaldship.log import log
import logging
from skaldship.hosts import get_host_record, do_host_status



##-------------------------------------------------------------------------

def msf_get_config(session={}):
    """
    Returns a dict of metasploit configuration settings based on yaml or session
    """

    msf_config = current.globalenv['settings']['kvasir_config'].get('metasploit') or {}
    config = {}
    config['key'] = session.get('msf_key', msf_config.get('api_key'))
    config['url'] = session.get('msf_url', msf_config.get('url', 'https://localhost:3790'))

    config['ws_num'] = session.get('msf_workspace_num', 1)
    config['workspace'] = session.get('msf_workspace', 'default')
    config['user'] = session.get('msf_user', None)

    return config


##-------------------------------------------------------------------------

def process_pwdump_loot(loot_list=[], msf=None):
    """
    Takes an array of loot records in loot_list, downloads the pwdump file and
    adds the users.
    """
    from skaldship.passwords import process_password_file, insert_or_update_acct

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    logging.debug('loot_list = %s' % (loot_list))
    data = []
    for loot_id in loot_list:
        loot = msf.loot_download(loot_id)
        if loot['ltype'] not in ['host.windows.pwdump', 'windows.hashes']:
            logging.error("Loot is not a pwdump, it is a %s" % loot['ltype'])
            continue
        else:
            # process the pwdump file
            pw_data = loot['data'].split('\n')
            accounts = process_password_file(
                pw_data=pw_data,
                file_type='PWDUMP',
                source='Metasploit',
            )

            # find the info/0 service id for the host
            host_id = get_host_record(loot['host'])
            query = (db.t_services.f_number == '0') & (db.t_services.f_proto == 'info') & (db.t_services.f_hosts_id == host_id)
            svc_id = db(query).select().first()
            if svc_id is None:
                # info/0 not found.. add it!
                svc_id = db.t_services.insert(f_proto="info", f_number="0", f_status="info", f_hosts_id=host_id)
                db.commit()

            # insert or update the account records
            resp_text = insert_or_update_acct(svc_id.id, accounts)
            logging.info("Added pwdump records for host: %s" % (loot['host']))
            data.append({ loot['host']: resp_text })

    return data

##-------------------------------------------------------------------------

def process_screenshot_loot(loot_list=[], msf=None):
    """
    Takes an array of loot records in loot_list, downloads the screenshot and
    adds it to the database
    """

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    loot_count = 0
    for loot_id in loot_list:
        loot = msf.loot_download(loot_id)
        ip = loot_dict[loot_id]
        if loot['ltype'] != 'host.windows.screenshot':
            logging.error(" [!] %s/%s is not a screenshot, it is a %s" % (ip, loot['name'], loot['ltype']))
        else:
            record = get_host_record(ip)
            if not record:
                logging.error(" [!] Cannot find record for %s" % (ip))
                continue

            db.t_evidence.update_or_insert(
                f_hosts_id = record.id,
                f_filename = "%s-msfpro-%s.png" % (ip, loot['name']),
                f_evidence = "%s-msfpro-%s.png" % (ip, loot['name']),
                f_data = loot['data'],
                f_type = 'Screenshot',
                f_text = 'From MetasploitPRO'
            )
            db.commit()
            loot_count += 1

    return loot_count

##-------------------------------------------------------------------------

def process_loot_files(loot_list=[]):
    """
    Processes locally stored (to web2py) MSF password loot files into the
    account database.

    Args:
        loot_list: an array of [filename, settings.password_file_types, port, host_id]

    Returns:
        An array of [filename, result text]
    """
    from skaldship.passwords import process_password_file, insert_or_update_acct
    import os
    db = current.globalenv['db']

    data = []
    for loot in loot_list:
        if isinstance(loot, []):
            (filename, file_type, port) = loot
        else:
            logger.error("Invalid loot sent: %s" % (loot))
            continue

        try:
            (proto, number) = port.split('/')
        except AttributeError, e:
            logger.error("Invalid port sent: %s", port)

        try:
            pw_data = open(filename, "rb").readlines().split('\n')
        except IOError, e:
            logger.error("Error opening %s: %s" % (filename, e))

        accounts = process_password_file(
            pw_data=pw_data,
            file_type=file_type,
            source='Metasploit',
        )

        # find the info/0 service id for the host
        host_id = get_host_record(loot['host'])
        query = (db.t_services.f_number == number) & (db.t_services.f_proto == proto) & (db.t_services.f_hosts_id == host_id)
        svc_id = db(query).select().first()
        if svc_id is None:
            # info/0 not found.. add it!
            svc_id = db.t_services.insert(f_proto=proto, f_number=number, f_hosts_id=host_id)
            db.commit()

        # insert or update the account records
        resp_text = insert_or_update_acct(svc_id.id, accounts)
        logging.info("Added loot accounts for host: %s" % ())
        data.append({ loot['host']: resp_text })

##-------------------------------------------------------------------------

def process_report_xml(
    filename=None,
    ip_ignore_list=None,
    ip_include_list=None,
    engineer=1,
    asset_group="Metasploit Import",
    update_hosts=True,
    ):
    """
    Processes a Metasploit XML Export for the following data and adds to the db:

    - Hosts and services
    - Credentials

    Generate the XML report by using db_export -t xml filename.xml or through WebUI

    TODO: Auto-exploits successful exploit attempts if matching CVE/VulnDB entry found
    """
    from gluon.validators import IS_IPADDRESS
    from skaldship.passwords import lookup_hash
    from skaldship.hosts import get_host_record, get_or_create_record
    from skaldship.services import Services
    services = Services()

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    try:
        from lxml import etree
    except ImportError:
        try:
            import xml.etree.cElementTree as etree
        except ImportError:
            try:
                import xml.etree.ElementTree as etree
            except:
                raise Exception("Unable to find valid ElementTree module.")

    # build the hosts only/exclude list
    ip_exclude = []
    if ip_ignore_list:
        ip_exclude = ip_ignore_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals
    ip_only = []
    if ip_include_list:
        ip_only = ip_include_list.split('\r\n')
        # TODO: check for ip subnet/range and break it out to individuals

    log(" [*] Processing Metasploit Pro report file: %s" % (filename))

    try:
        xml = etree.parse(filename)
    except etree.ParseError, e:
        raise Exception(" [!] Invalid XML file (%s): %s " % (filename, e))

    root = xml.getroot()

    # parse the hosts now
    hosts = root.findall("hosts/host")
    log(" [-] Parsing %d hosts" % (len(hosts)))
    stats = {}
    stats['hosts_added'] = 0
    stats['hosts_skipped'] = 0
    stats['hosts_updated'] = 0
    stats['services_added'] = 0
    stats['services_updated'] = 0
    stats['accounts_added'] = 0
    stats['accounts_updated'] = 0

    for host in hosts:
        didwhat = "Unknown"
        if host.findtext('state') != "alive":
            stats['hosts_skipped'] += 1
            continue

        hostfields = {}
        ipaddr = host.findtext('address')

        if len(ip_only) > 0 and ipaddr not in ip_only:
            log(" [-] Node is not in the only list... skipping")
            stats['hosts_skipped'] += 1
            continue

        if IS_IPADDRESS()(ipaddr)[1] is not None:
            logger.error("Invalid IP Address in report: %s" % ipaddr)
            log(" [!] Invalid IP Address in report: %s" % ipaddr)
            continue

        macaddr = host.findtext('mac')
        if macaddr:
            hostfields['f_macaddr'] = macaddr

        hostname = host.findtext('name')
        if hostname:
            hostfields['f_hostname'] = hostname

        # check to see if IP exists in DB already
        hostfields['f_asset_group'] = asset_group
        hostfields['f_engineer'] = engineer

        if update_hosts:
            # update or add, doesn't matter which
            host_rec = get_or_create_record(ipaddr, **hostfields)
            stats['hosts_added'] += 1
        else:
            # weird logic.. get a host record, if it doesn't exist create it otherwise skip because update_hosts=False
            host_rec = get_host_record(ipaddr)
            if not host_rec:
                host_rec = get_or_create_record(ipaddr, **hostfields)
                stats['hosts_added'] += 1
                log(" [-] Adding IP: %s" % (ipaddr))
            else:
                stats['hosts_skipped'] += 1
                log(" [-] Skipped IP: %s" % (ipaddr))
                continue

        # add the <info> and <comments> as a note to the host
        info_note = host.findtext('info') or None
        if info_note and info_note.startswith('Domain controller for '):
            db.t_netbios.update_or_insert(
                f_hosts_id=host_rec.id,
                f_type="PDC",
                f_domain=info_note[22:].upper()
            )
        elif info_note:
            db.t_host_notes.update_or_insert(
                f_hosts_id=host_rec.id,
                f_note=info_note,
            )
        db.commit()
        for comment in host.findall('comments/comment'):
            db.t_host_notes.update_or_insert(
                f_hosts_id=host_rec.id,
                f_note=comment.text,
            )

        # process the services, adding any new
        for svc in host.findall('services/service'):
            svc_fields = {
                'f_number': svc.findtext('port'),
                'f_proto': svc.findtext('proto'),
                'f_status': svc.findtext('state'),
                'f_name': svc.findtext('name') or '',
                'f_banner': svc.findtext('info') or '',
                'f_hosts_id': host_rec.id,
            }

            if svc_fields['f_name'] in ['http', 'https']:
                svc_fields['f_name'] = svc_fields['f_name'].upper()

            svc_rec = services.get_record(create_or_update=True, **svc_fields)

        for cred in host.findall('creds/cred'):
            # handle credential data
            f_password = None
            f_compromised = False

            cred_type = cred.findtext('ptype')
            if cred_type == "smb_hash":
                # add smb hashes to info/0 service
                svc_fields = {
                    'f_number': '0',
                    'f_proto': 'info',
                    'f_hosts_id': host_rec.id,
                }
                svc_rec = services.get_record(create_or_update=True, **svc_fields)

                pwhash = cred.findtext('pass')
                f_password = lookup_hash(pwhash)
                (lm, nt) = pwhash.split(':')
                user = cred.findtext('user')
                query = (db.t_accounts.f_services_id == svc_rec.id) & (db.t_accounts.f_username.upper() == user.upper())
                acct_row = db(query).select().first()
                if acct_row:
                    # we have an account already, lets see if the hashes are in there
                    h1 = acct_row.f_hash1
                    if isinstance(h1, str):
                        if acct_row.f_hash1.upper() != lm.upper():
                            acct_row.f_hash1=lm.upper()
                            acct_row.f_hash1_type = "LM"
                            acct_row.f_hash2=nt.upper()
                            acct_row.f_hash2_type = "NT"
                            if f_password:
                                acct_row.f_compromised = True
                                acct_row.f_password = f_password
                            if not acct_row.f_source:
                                acct_row.f_source = "Metasploit Import"
                            acct_row.update_record()
                            db.commit()
                            stats['accounts_updated'] += 1
                            didwhat = "Updated"
                else:
                    # add a new account record
                    if f_password:
                        f_compromised = True
                    else:
                        f_compromised = False
                    acct_data = dict(
                        f_services_id=svc_rec.id,
                        f_username=user,
                        f_password=f_password,
                        f_compromised=f_compromised,
                        f_hash1=lm.upper(),
                        f_hash1_type='LM',
                        f_hash2=nt.upper(),
                        f_hash2_type='NT',
                        f_source="Metasploit Import"
                    )
                    acct_id = db.t_accounts.insert(**acct_data)
                    db.commit()
                    stats['accounts_added'] += 1
                    didwhat = "Added"

            elif cred_type == 'smb_challenge':
                # add smb challenge hashes to info/0 service
                svc_fields = {
                    'f_number': '0',
                    'f_proto': 'info',
                    'f_hosts_id': host_rec.id,
                }
                svc_rec = services.get_record(create_or_update=True, **svc_fields)

                user = cred.findtext('user')
                query = (db.t_accounts.f_services_id == svc_rec.id) & (db.t_accounts.f_username.upper() == user.upper())
                acct_row = db(query).select().first()
                if acct_row:
                    # we have an account already, lets see if the hashes are in there
                    h1 = acct_row.f_hash1
                    if isinstance(h1, str):
                        if acct_row.f_hash1.upper() != lm.upper():
                            acct_row.f_password = f_password
                            acct_row.f_hash1 = pwhash.upper()
                            acct_row.f_hash1_type = 'NTCHALLENGE'
                            acct_row.f_domain = cred.findtext('proof')
                            if not acct_row.f_source:
                                acct_row.f_source = "Metasploit Capture"
                            acct_row.update_record()
                            db.commit()
                            stats['accounts_updated'] += 1
                            didwhat = "Updated"
                else:
                    # new account record
                    f_password = lookup_hash(pwhash)
                    if f_password:
                        f_compromised = True
                    else:
                        f_compromised = False
                    acct_data = dict(
                        f_services_id=svc_rec.id,
                        f_username=user,
                        f_password=f_password,
                        f_compromised=f_compromised,
                        f_hash1=pwhash.upper(),
                        f_hash1_type='NTCHALLENGE',
                        f_source="Metasploit Capture"
                    )
                    acct_id = db.t_accounts.insert(**acct_data)
                    db.commit()
                    stats['accounts_added'] += 1
                    didwhat = "Added"

            elif cred_type == 'rakp_hmac_sha1_hash':
                # IPMI 2.0 RAKP Remote SHA1 Hashes

                f_hash1 = cred.findtext('pass')
                f_hash1_type = cred.findtext('ptype')
                user = cred.findtext('user')
                svcname = cred.findtext('sname')

                query = (db.t_accounts.f_services_id == svc_rec.id) & (db.t_accounts.f_username.upper() == user.upper())
                acct_row = db(query).select().first()
                f_source = "Metasploit Import"
                if acct_row:
                    # we have an account already, lets see if the hashes are in there
                    if acct_row.f_hash1 != f_hash1:
                        acct_row.f_hash1 = f_hash1
                        acct_row.f_hash1_type = f_hash1_type
                        if not acct_row.f_source:
                            acct_row.f_source = f_source
                        acct_row.update_record()
                        db.commit()
                        stats['accounts_updated'] += 1
                        didwhat = "Updated"
                else:
                    # new account record
                    acct_data = dict(
                        f_services_id=svc_rec.id,
                        f_username=user,
                        f_hash1=f_hash1,
                        f_hash1_type=f_hash1_type,
                        f_source=f_source,
                        f_compromised=True
                    )
                    acct_id = db.t_accounts.insert(**acct_data)
                    db.commit()
                    stats['accounts_added'] += 1
                    didwhat = "Added"

            else:
                # for cred_type == 'password' or 'exploit':
                # add regular password
                if svc_fields['f_number'] == '445':
                    svc_fields['f_proto'] = 'info'
                    svc_fields['f_number'] = '0'

                svc_rec = services.get_record(create_or_update=True, **svc_fields)

                f_password = cred.findtext('pass')
                if f_password == "*BLANK PASSWORD*":
                    f_password = ''

                user = cred.findtext('user')
                svcname = cred.findtext('sname')

                # do some case mangling for known variations we want in all upper case
                if svcname == "vnc":
                    user = "vnc"

                query = (db.t_accounts.f_services_id == svc_rec.id) & (db.t_accounts.f_username.upper() == user.upper())
                acct_row = db(query).select().first()
                f_source = cred.findtext('type')
                if f_source == 'captured':
                    f_source = "Metasploit Capture"
                else:
                    f_source = "Metasploit Import"
                if acct_row:
                    # we have an account already, lets see if the hashes are in there
                    if acct_row.f_password != f_password:
                        acct_row.f_password = f_password
                        acct_row.f_compromised = True
                        if not acct_row.f_source:
                            acct_row.f_source = f_source
                        acct_row.update_record()
                        db.commit()
                        stats['accounts_updated'] += 1
                        didwhat = "Updated"
                else:
                    # new account record
                    acct_data = dict(
                        f_services_id=svc_rec.id,
                        f_username=user,
                        f_password=f_password,
                        f_source=f_source,
                        f_compromised=True
                    )
                    acct_id = db.t_accounts.insert(**acct_data)
                    db.commit()
                    stats['accounts_added'] += 1
                    didwhat = "Added"

            log(" [-] Account %s: (%s) %s" % (didwhat, ipaddr, user))

    do_host_status()

    msg = " [*] Import complete: hosts: (%s/A, %s/U, %s/S) - services: (%s/A, %s/U), creds: (%s/A, %s/U)"\
        % (
            stats['hosts_added'],
            stats['hosts_updated'],
            stats['hosts_skipped'],
            stats['services_added'],
            stats['services_updated'],
            stats['accounts_added'],
            stats['accounts_updated']
        )

    log(msg)
    return msg
