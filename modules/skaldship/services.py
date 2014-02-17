# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Services utility module
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##
##--------------------------------------#
"""

from gluon import current
from skaldship.log import log


##-------------------------------------------------------------------------
class Services:
    """
    Kvasir Services class. Provides basic functions to add, update, return service data
    """
    def __init__(self):
        self.db = current.globalenv['db']
        self.svc_db = self.db.t_services
        self.services = {}      # cached dict of services


    ##---------------------------------------------------------------------
    def _get_record(self, proto, port, svcname, host_id):
        """
        Returns a unique single record based on specific data
        """
        if not proto or not port or not host_id:
            return None

        query = (self.svc_db.f_proto==proto) & (self.svc_db.f_number==port) & (self.svc_db.f_hosts_id == host_id)
        record = self.db(query).select().first()
        if record.id not in self.services:
            self.services[record.id] = record

        return record


    ##---------------------------------------------------------------------
    def _update_or_insert(self, proto, port, svcname, host_id):
        """
        Our own update_or_insert routine
        """
        if not proto or not port or not host_id:
            return None

        svc_id = self.svc_db.update_or_insert(
            f_proto=proto, f_number=port, f_status=svcname, f_hosts_id=host_id
        )
        self.db.commit()
        if not svc_id:
            record = self._get_record(proto, port, svcname, host_id)
            if record:
                return record.id
            else:
                return None

        return svc_id


    ##---------------------------------------------------------------------
    def get_id(self, proto, port, svcname, host_id, create_or_update=False):
        """
        Returns the record identifier of a service based upon strict criteria.
        """

        if create_or_update:
            return self._update_or_insert(proto, port, svcname, host_id)

        record = self._get_record(proto, port, svcname, host_id)
        if record:
            return record.id

        return None


##-------------------------------------------------------------------------
def pagination_services(request, curr_service):
    # Pagination! Send it the db, request and current host record, get back
    # a dictionary to put into the view.

    db = current.globalenv['db']
    #cache = current.globalenv['cache']

    from gluon.html import OPTION, SELECT, FORM, A
    from skaldship.general import host_title_maker

    servicelist = []
    serviceprev = "#"
    servicenext = "#"
    serviceselected = 0
    servicenextstyle = serviceprevstyle = ""
    serviceprevtitle = servicenexttitle = ""
    serviceindex = 1
    servicecount = 0
    query = db.t_services.f_hosts_id == db.t_hosts.id

    """
    # Create more filters here
    if request.vars.filterconfirmed is not None:
        session.servicefilterconfirmed=request.vars.filterconfirmed

    if session.servicefilterconfirmed == 'Unconfirmed [H]osts':
        query=db.t_services
    else:
        query=db.t_services.f_confirmed==False

    """
    for h_rec in db(query).select(orderby=db.t_hosts.id):
        hostrecord = h_rec.t_hosts
        servicelist.append(OPTION(host_title_maker(hostrecord) + " - " + service_title_maker(h_rec.t_services), _value=h_rec.t_services.id))
        if serviceselected != 0 and servicenext == "#":
            servicenext = h_rec.t_services.id
            servicenexttitle = "Go to " + host_title_maker(hostrecord) + " - " + service_title_maker(h_rec.t_services)
        if h_rec.t_services.id == curr_service.id:
            serviceselected = serviceindex
        if serviceselected == 0:
            serviceprev = h_rec.t_services.id
            serviceprevtitle = "Go to " + host_title_maker(hostrecord) + " - " + service_title_maker(h_rec.t_services)
        if h_rec.t_services.f_hosts_id == curr_service.f_hosts_id:
            serviceindex += 1
            servicecount += 1

    if serviceprev == "#":
        serviceprevstyle = "display:none"
    if servicenext == "#":
        servicenextstyle = "display:none"

    pagination = {}
    pagination['form'] = FORM(A("<<(p)",_id="prevservicelink" ,_class="button", _href=serviceprev, _style=serviceprevstyle, _title=serviceprevtitle), "    ",
                              SELECT(servicelist, value=request.args(0), _class="autowidth", _id="service_select", _name="service_select", _onchange="window.location.href=$('#service_select').val()"), "  ", A("(n)>>", _id="nextservicelink", _class="button", _href=servicenext, _style=servicenextstyle, _title=servicenexttitle),_method='get')

    pagination['service_number'] = "( %d/%d )" % (serviceselected, servicecount)

    return pagination

##-------------------------------------------------------------------------


def get_service_record(host_rec=None, proto=None, pnum=None):
    """
    Returns a service record ID based on a host_record and proto/number

    XXX: This is not used yet
    """
    if host_rec is None:
        return None

    db = current.globalenv['db']

    query = (db.t_services.f_proto == proto)
    query &= (db.t_services.f_number == pnum)
    return host_rec.t_services(query).select().first()

##-------------------------------------------------------------------------


def service_title_maker(record):
    """
    Given a t_service record, return a string value to place
    in the HTML TITLE (via response.title) or any other text
    place. Like a form field, json output, etc.

    XXX: This is not used yet
    """

    if record is None or not hasattr(record, 'f_proto'):
        return "Unknown"

    serviceinfo = "%s/%s" % (record['f_proto'], record['f_number'])

    return serviceinfo
