# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir Scheduler functions
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Scheduler functions for long running processes
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

import os
from skaldship.hosts import get_host_record
from gluon.scheduler import Scheduler

import logging

logger = logging.getLogger("web2py.app.kvasir")

##----------------------------------------------------------------------------

def launch_terminal(record=None, launch_cmd=None):
    """
    Opens a terminal on the Web Server. This only works if the
    web2py server is running on the user's workstation.

    The command to execute is stored in the user's settings db
    under auth_user.f_launch_cmd. Variables translated:

       _IP_      -- The current IP Address (v4 by default, v6 if exists)
       _LOGFILE_ -- Session logfile name (we prepend the path)

    If an IPv6 address is used then ':' is changed to '_'

    Example:

    xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e script _LOGFILE_
    """

    record = get_host_record(record)

    # only execute launch on requests from localhost!
    if request.env['remote_addr'] != '127.0.0.1':
        logger.error("Can only launch from localhost! remote_addr = %s" % (request.env['remote_addr']))
        return "Can only launch from localhost"

    if record is None:
        return "No record found"

    import string, os, subprocess
    import time

    # if no launch command use the default
    if not launch_cmd:
        launch_cmd = "xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e 'script _LOGFILE_'"

    # check ip address
    if record.f_ipv6 is None or len(record.f_ipv6) == 0:
        ip = record.f_ipv4
        logip = record.f_ipv4
    else:
        ip = record.f_ipv6
        logip = record.f_ipv6.replace(":", "_")

    logdir = "session-logs"
    logfilename = "%s-%s.log" % (logip, time.strftime("%Y%m%d%H%M%S", time.localtime(time.time())))
    logfile = os.path.join(logdir, logfilename)
    launch_cmd = launch_cmd.replace("_IP_", ip)
    launch_cmd = launch_cmd.replace("_LOGFILE_", logfile)

    from skaldship.general import check_datadir
    # Check to see if data directories exist, create otherwise
    check_datadir(request.folder)
    datadir = os.path.join(request.folder, "data")

    # chdir to datadir!
    launch_cmd = launch_cmd.replace("_DATADIR_", datadir)
    os.chdir(datadir)

    # set environment variables
    os.environ['IP'] = ip
    os.environ['HOSTNAME'] = record.f_hostname or ""
    os.environ['DATADIR'] = datadir

    try:
        logger.info("Spawning: %s\n" % (launch_cmd))
        print("Spawning: %s" % (launch_cmd))
        subprocess.Popen(launch_cmd, shell=True)#, stdout=None, stdin=None, stderr=None)
    except Exception, e:
        logger.error("Error spawning launch cmd (%s): %s\n" % (launch_cmd, e))
        print("Error spawning launch cmd (%s): %s\n" % (launch_cmd, e))

    return False

##----------------------------------------------------------------------------

def run_scanner(
        scanner=None,
        asset_group=None,
        engineer=None,
        target_list=None,
        blacklist=None,
        scan_options=None,
        addnoports=False,
        update_hosts=False,
        **kwargs
):
    '''
    Schedule handler to process nmap scan
    '''
    from skaldship.log import log

    if not isinstance(scanner, str):
        return False
    scanner = scanner.upper()
    logger.info(" [*] Processing Nmap scan ")
    if scanner == 'NMAP':
        from skaldship.nmap import run_scan

        nmap_xml_file = run_scan(
            blacklist=blacklist,
            target_list=target_list,
            scan_options=scan_options,
        )

        if nmap_xml_file:
            from skaldship.nmap import process_xml
            log("Processing nmap xml file: %s" % (nmap_xml_file))
            process_xml(
                filename=nmap_xml_file,
                addnoports=addnoports,
                asset_group=asset_group,
                engineer=engineer,
                msf_settings={},
                ip_ignore_list=None,
                ip_include_list=None,
                update_hosts=update_hosts,
            )
            logger.info('Removing temporary XML file: %s: \n' % nmap_xml_file)
            try:
                os.remove(nmap_xml_file)
            except OSError as e:
                logger.error('%s ' % e.strerror)
                print e.errno
                print e.filename
                print e.strerror

##----------------------------------------------------------------------------

def canvas_exploit_xml(filename=None):
    """
    Process ImmunitySec CANVAS Exploits.xml file into the database
    """
    from skaldship.canvas import process_exploits
    from skaldship.exploits import connect_exploits

    process_exploits(filename)
    connect_exploits()
    return True

##----------------------------------------------------------------------------

def nexpose_exploit_xml(filename=None):
    """
    Process Nexpose exploits.xml file into the database
    """
    from skaldship.nexpose import process_exploits
    from skaldship.exploits import connect_exploits

    process_exploits(filename)
    connect_exploits()
    return True

##----------------------------------------------------------------------------

def scanner_import(
        scanner=None,
        filename=None,
        addnoports=False,
        asset_group=None,
        engineer=None,
        msf_settings={},
        ip_ignore_list=None,
        ip_include_list=None,
        update_hosts=False,
        **kwargs
):
    """
    Imports a Scanner XML file to Kvasir
    """
    if not isinstance(scanner, str):
        return False

    scanner = scanner.upper()
    if scanner == 'NMAP':
        from skaldship.nmap import process_xml

        logger.info("Processing nmap file: %s" % (filename))
        process_xml(
            filename=filename,
            addnoports=addnoports,
            asset_group=asset_group,
            engineer=engineer,
            msf_settings=msf_settings,
            ip_ignore_list=ip_ignore_list,
            ip_include_list=ip_include_list,
            update_hosts=update_hosts,
        )
    elif scanner == 'NEXPOSE':
        from skaldship.nexpose import process_xml

        logger.info("Processing Nexpose file: %s" % (filename))
        process_xml(
            filename=filename,
            asset_group=asset_group,
            engineer=engineer,
            msf_settings=msf_settings,
            ip_ignore_list=ip_ignore_list,
            ip_include_list=ip_include_list,
            update_hosts=update_hosts,
        )
    elif scanner == 'NESSUS':
        from skaldship.nessus import process_xml

        logger.info("Processing Nessus file: %s" % (filename))
        process_xml(
            filename=filename,
            asset_group=asset_group,
            engineer=engineer,
            msf_settings=msf_settings,
            ip_ignore_list=ip_ignore_list,
            ip_include_list=ip_include_list,
            update_hosts=update_hosts,
        )
    elif scanner == 'METASPLOIT':
        from skaldship.metasploit import process_report_xml

        logger.info("Processing Metasploit Pro file: %s" % filename)
        process_report_xml(
            filename=filename,
            asset_group=asset_group,
            engineer=engineer,
            ip_ignore_list=ip_ignore_list,
            ip_include_list=ip_include_list,
            update_hosts=update_hosts,
        )
    elif scanner == 'SHODANHQ':
        from skaldship.shodanhq import process_report

        logger.info("Processing ShodanHQ file: %s" % (filename))
        process_report(
            filename=filename,
            host_list=kwargs.get('hosts') or [],
            query=kwargs.get('query') or None,
            asset_group=asset_group,
            engineer=engineer,
            ip_ignore_list=ip_ignore_list,
            ip_include_list=ip_include_list,
            update_hosts=update_hosts,
        )
    return True

##----------------------------------------------------------------------------

def do_host_status(records=[], query=None, asset_group=None, hosts=[]):
    """
    Runs through the t_hosts table and updates the *_count entries.
    Can also run through a specific list of record IDs instead.
    """
    from skaldship.hosts import do_host_status

    do_host_status(records=records, query=query, asset_group=asset_group, hosts=hosts)
    return True

##------------------------------------------------------------------------

def accounts_import_file(filename=None, service=['info', '0'], f_type=None, f_source=None):
    """
    Processes an Imported password file to the accounts table
    """

    print("Processing password file: %s" % (filename))
    from skaldship.passwords import process_password_file, insert_or_update_acct

    account_data = process_password_file(pw_file=filename, file_type=f_type, source=f_source)
    resp_text = insert_or_update_acct(service, account_data)
    print(resp_text)
    return True

##------------------------------------------------------------------------

def cpe_import_xml(filename=None, download=False, wipe=False):
    """
    Process the CPE data through an uploaded file or have it download directly
    from the MITRE webserver
    """
    from skaldship.cpe import process_xml

    process_xml(filename, download, wipe)
    return True

##------------------------------------------------------------------------

def webshot(service=None):
    """
    Grab a screenshot of a URL and import it to the evidence db.
    """
    from skaldship.valkyries.webimaging import do_screenshot

    do_screenshot(service)
    return True

##-------------------------------------------------------

def import_all_nexpose_vulndata(overwrite=False, nexpose_server={}):
    """
    Import all vulnerability data from Nexpose
    """
    from skaldship.nexpose import import_all_vulndata

    import_all_vulndata(overwrite=overwrite, nexpose_server=nexpose_server)
    return True

##-------------------------------------------------------

scheduler = Scheduler(
    db=db,
    migrate=settings.migrate,
    group_names=[settings.scheduler_group_name],
)
