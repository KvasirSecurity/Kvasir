# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir Support Table Definitions
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

#########################################
## Event log
db.define_table('t_event_log',
    Field('id', 'id'),
    Field('f_text', 'string', label=T('Message')),
    Field('f_seen', 'boolean', default=False, label=T('Seen')),
    Field('f_ack', 'boolean', default=False, label=T('Acknowledged')),
    auth.signature,
    format='%(f_text)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

#########################################
## +5 bag of holding things
db.define_table('t_errata',
    Field('id', 'id'),
    Field('f_key', 'string', label=T('Key'), requires=IS_NOT_EMPTY()),
    Field('f_value', 'string', label=T('Value'), requires=IS_NOT_EMPTY()),
    auth.signature,
    format='%(f_value)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
