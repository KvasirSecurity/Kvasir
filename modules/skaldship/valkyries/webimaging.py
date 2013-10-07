# encoding: utf-8

__version__ = "1.0"

"""
##-----------------------------------------------#
## Kvasir Skaldship WebImaging Valkyrie
##
## Grab screenshots of websites using phantomjs
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##-----------------------------------------------#
"""

from gluon import current
#from skaldship.general import get_host_record
from subprocess import call
import os
import urllib
import logging
logger = logging.getLogger("web2py.app.kvasir")

##----------------------------------------------------------------------------


def grab_screenshot(url=None, outfile=None, phantomjs="/usr/bin/phantomjs"):
    """
    Capture a PNG image of a URL using phantomjs

    @args:
        url: Website URL to retrieve
        outfile: Output filename, will overwrite but not remove failures
        phantomjs: Full path to phantomjs binary

    @output:
        [True/False, png image data]
    """
    db = current.globalenv['db']

    if not outfile:
        raise Exception("No output filename provided")

    try:
        os.stat(phantomjs)
    except OSError:
        phantomjs = "/usr/local/bin/phantomjs"
        try:
            os.stat(phantomjs)
        except OSError:
            logging.error("Unable to locate phantomjs binary")
            return [False, None]

    # encode the url to make sure it passes cleanly to phantomjs
    url = urllib.quote(url, safe='/:')
    folder = current.globalenv['request'].folder
    from sys import platform
    if platform in ["linux", "linux2"]:
        timeout = ["/usr/bin/timeout", "-k", "2", "5"]
    elif platform in ["darwin", "freebsd"]:
        timeout = ["%sprivate/timeout3" % folder, "-t" "5"]
    else:
        timeout = []
    phantom = timeout + [phantomjs, "--ignore-ssl-errors=true", "%/smodules/skaldship/valkyries/webimaging.js" % (folder), url, outfile]
    logging.debug("calling: %s" % str(phantom))
    call(phantom)
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
    Grab a screenshot of a URL and import it to the evidence db.
    """

    from gluon.dal import Row
    from skaldship.general import check_datadir

    db = current.globalenv['db']

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

        # go with ipv6 if defined, else pick the ipv4 address
        ipaddr = svc_rec.f_hosts_id.f_ipv6 or svc_rec.f_hosts_id.f_ipv4
        port = "%s%s" % (svc_rec.f_number, svc_rec.f_proto[0])
        check_datadir(current.globalenv['request'].folder)
        folder = os.path.join(current.globalenv['request'].folder, "data/screenshots")
        filename = "%s-%s-webshot.png" % (ipaddr.replace(':', '_'), port)

        if svc_rec.f_name in ['http', 'https', 'HTTP', 'HTTPS']:
            scheme = svc_rec.f_name.lower()
        else:
            scheme = 'http'
        url = "%s://%s:%s/" % (scheme, ipaddr, svc_rec.f_number)

        res = grab_screenshot(url, os.path.join(folder, filename))
        if res[0]:
            query = (db.t_evidence.f_hosts_id == svc_rec.f_hosts_id) & (db.t_evidence.f_filename == filename)
            db.t_evidence.update_or_insert(
                query, f_filename=filename, f_hosts_id=svc_rec.f_hosts_id, f_data=res[1],
                f_evidence=filename, f_type="Screenshot", f_text="Web Screenshot - %s" % (url))
            db.commit()
            print(" [-] Web screenshot obtained: %s" % (url))
            good_count += 1
        else:
            print(" [!] Web screenshot failed: %s" % (url))
            invalid_count += 1

    return [good_count, invalid_count]

##----------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from hashlib import md5

    if len(sys.argv) <= 2:
        sys.exit("Usage: %s <url> <filename>" % (sys.argv[0]))

    url = sys.argv[1]
    outfile = sys.argv[2]

    result = grab_screenshot(url, outfile)
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
