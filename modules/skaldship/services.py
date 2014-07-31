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
import logging


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
    @property
    def all(self):
        """
        All known services
        :return: self.services
        """
        return self.services


    ##---------------------------------------------------------------------
    def _get_record(self, **fields):
        """
        Obtain a record from specified fields. Requires f_proto, f_number and f_hosts_id

        :param fields: Matching db.t_services fields (f_proto, f_number, etc)
        :returns: t_services record
        """
        if not fields['f_proto'] or not fields['f_number'] or not fields['f_hosts_id']:
            log("No protocol, number or hosts_id sent", logging.ERROR)
            return None

        query = (self.svc_db.f_proto == fields['f_proto']) &\
                (self.svc_db.f_number == fields['f_number']) &\
                (self.svc_db.f_hosts_id == fields['f_hosts_id'])
        record = self.db(query).select().first()

        if record and record.id not in self.services:
            self.services[record.id] = record

        return record


    ##---------------------------------------------------------------------
    def _update_or_insert(self, **fields):
        """
        Our own update_or_insert routine

        :param fields: Matching db.t_services fields (f_proto, f_number, etc)
        :returns: t_services record id
        """
        if not fields['f_proto'] or not fields['f_number'] or not fields['f_hosts_id']:
            log("No protocol, number or hosts_id sent", logging.ERROR)
            return None

        svc_id = self.svc_db.update_or_insert(**fields)
        if not svc_id:
            # update_or_insert will not return an id if a record is updated.
            record = self._get_record(**fields)
            if record:
                svc_id = record.id

        return svc_id


    ##---------------------------------------------------------------------
    def get_record(self, create_or_update=False, **fields):
        """
        Get a t_services record from fields criteria.

        :param create_or_update: Boolean to create/update if criteria for record not found.
        :param fields: Matching db.t_service fields (f_proto, f_number, etc)
        :returns: t_services record or None
        """
        if create_or_update:
            svc_id = self._update_or_insert(**fields)
            record = self.db.t_services[svc_id]
        else:
            record = self._get_record(**fields)

        return record


##-------------------------------------------------------------------------
def service_title_maker(record):
    """
    Given a t_service record, return a string value to place
    in the HTML TITLE (via response.title) or any other text
    place. Like a form field, json output, etc.

    :param record: A db.t_services record
    :returns serviceinfo: A port/number string result
    """

    if record is None or not hasattr(record, 'f_proto'):
        return "Unknown"

    serviceinfo = "%s/%s" % (record['f_proto'], record['f_number'])

    return serviceinfo
