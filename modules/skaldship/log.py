# -*- coding: utf-8 -*-

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## Logging / print functions for Kvasir
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

import inspect
import logging
logger = logging.getLogger("web2py.app.kvasir")


def log(message, level=logging.INFO, *args, **kwargs):
    """
    If we're in a scheduler task then print the message out to stdout
    so it will be picked up. Otherwise use the current logger module
    and send with the specified level
    """
    try:
        from gluon import current
        if 'W2P_TASK' in current.globalenv:
            print(message)
    except ImportError:
        pass

    # find the calling function
    try:
        callfunc = inspect.stack()[1][3]
    except:
        callfunc = 'unknown'

    try:
        callmod = inspect.getmodule(inspect.stack()[1]).__name__
    except:
        callmod = 'unknown'

    msg = logging.makeLogRecord({
        'name': logger.name,
        'msg': message,
        'levelno': level,
        'levelname': logging.getLevelName(level),
        'funcName': callfunc,
        'module': callmod,
    })

    logger.handle(msg)
