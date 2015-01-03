# encoding: utf-8

__version__ = "1.0"

"""
##-----------------------------------------------#
## Kvasir Skaldship VNC Screenshot Valkyrie
##
## Grab screenshots of VNC desktops using vncsnapshot
## http://sourceforge.net/projects/vncsnapshot/
##
## patches are required to get vncsnapshot to work in 64bit OS
## https://launchpadlibrarian.net/85079370/vncsnapshot_1.2a-5ubuntu1.diff.gz
## for debian/ubuntu do "apt-get install vncsnapshot"
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##-----------------------------------------------#
"""

#from skaldship.general import get_host_record
from subprocess import call
from skaldship.log import log
import logging

##----------------------------------------------------------------------------


def grab_screenshot(host=None, port=5900, outfile=None, vncsnapshot='vncsnapshot'):
    """
    Capture a JPEG image of a VNC Desktop using vncsnapshot

    @args:
        host: Host address
        port: Port address (5900, 5901, 5902, etc)
        outfile: Output filename, will overwrite but not remove failures

    @output:
        [True/False, jpeg image data]
    """
    import os
    from gluon import current
    from sys import platform

    if not outfile:
        raise Exception("No output filename provided")

    try:
        os.stat(vncsnapshot)
    except OSError:
        vncsnapshot = "/usr/local/bin/vncsnapshot"
        try:
            os.stat(vncsnapshot)
        except OSError:
            logging.error("Unable to locate vncsnapshot binary")
            return [False, None]

    folder = current.globalenv['request'].folder
    if platform in ["linux", "linux2"]:
        cmd = ["/usr/bin/timeout", "-k", "2", "10"]
    elif platform in ["darwin", "freebsd"]:
        cmd = [os.path.join(folder, 'private/timeout3'), "-t", "10"]
    else:
        cmd = []

    port = int(port)
    port -= 5900
    cmd.extend([vncsnapshot, '-compresslevel', '9', "%s:%s" % (host, port), outfile])
    #log("calling: %s" % str(cmd), logging.DEBUG)
    call(cmd)

    try:
        f = file(outfile)
        imgdata = f.read()
        f.close()
        result = True
    except:
        result = False
        imgdata = None

    return [result, imgdata]

##----------------------------------------------------------------------------


def do_screenshot(services=None):
    """
    Grab a screenshot and import it to the evidence db.
    """

    from gluon.dal import Row
    from gluon import current
    import os
    from skaldship.general import check_datadir
    from multiprocessing import Process

    db = current.globalenv['db']
    settings = current.globalenv['settings']

    if isinstance(services, int):
        services = [services]

    service_rows = []
    if isinstance(services, list):
        for svc in services:
            service_rows.append(db.t_services[svc])

    if isinstance(services, Row):
        service_rows = [services]

    good_count = 0
    invalid_count = 0

    for svc_rec in service_rows:
        if not isinstance(svc_rec, Row):
            invalid_count += 1
            continue

        ipaddr = svc_rec.f_hosts_id.f_ipaddr
        port = svc_rec.f_number
        check_datadir(current.globalenv['request'].folder)
        folder = os.path.join(current.globalenv['request'].folder, "data/screenshots")
        filename = "%s-%st-vnc_screenshot.png" % (ipaddr.replace(':', '_'), port)

        res = grab_screenshot(ipaddr, port, os.path.join(folder, filename))
        if res[0]:
            query = (db.t_evidence.f_hosts_id == svc_rec.f_hosts_id) & (db.t_evidence.f_filename == filename)
            db.t_evidence.update_or_insert(
                query, f_filename=filename, f_hosts_id=svc_rec.f_hosts_id, f_data=res[1],
                f_evidence=filename, f_type="Screenshot", f_text="VNC Screenshot - %s:%s" % (ipaddr, port))
            db.commit()
            print(" [-] VNC screenshot obtained: %s:%s" % (ipaddr, port))
            good_count += 1
        else:
            print(" [!] VNC screenshot failed: %s:%s" % (ipaddr, port))
            invalid_count += 1

    return [good_count, invalid_count]

##----------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from hashlib import md5

    if len(sys.argv) <= 2:
        sys.exit("Usage: %s <host> <port> <filename>" % (sys.argv[0]))

    host = sys.argv[1]
    port = sys.argv[2]
    outfile = sys.argv[3]

    result = grab_screenshot(host, port, outfile)
    imgresult = result[1]

    print "Result = %s" % result[0]

    try:
        f = file(outfile)
        imgdata = f.read()
        f.close()
    except Exception, e:
        sys.exit("Error processing outfile: %s" % (e))

    m1 = md5()
    m1.update(imgresult)
    print "imgresult md5 = %s" % m1.hexdigest()

    m2 = md5()
    m2.update(imgdata)
    print "  imgdata md5 = %s" % m2.hexdigest()

    if m1.digest() == m2.digest():
        print "Images matched. Everything worked!"
    else:
        print "Images don't match. Something borked."
