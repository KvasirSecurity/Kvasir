# -*- coding: utf-8 -*-

if 0:
    import db

from gluon import sanitizer
from gluon.custom_import import track_changes; track_changes(True)

###########
# GLOBALS!

HTTP_PORTS = [
    "80",
    "88",
    "8080",
    "8081",
    "9091",
    "8888",
    "5800",
    "5801",
    "5802",
    "2301",
]

HTTPS_PORTS = [
    "443",
    "8443",
    "2381",
]

###########
# Widgets!

def autocomplete_bootstrap(f,v):
    """
    Autocomplete widget using boostrap typeahead
    """
    import uuid
    d_id = "autocomplete-bs-" + str(uuid.uuid4())[:8]
    wrapper = DIV(_id=d_id)
    inp_id = "autocomplete-input-bs-" + str(uuid.uuid4())[:8]
    rows = f._db(f._table['id']>0).select(f,distinct=True)
    #itms = rows.as_list()
    itms = [XML(t.values()[0], sanitize=True).xml() for t in rows]
    #inp = SQLFORM.widgets.string.widget(f, v, _id=inp_id, **{'_data-provide': 'typeahead', '_data-source': itms, '_data-items': 8})
    inp = SQLFORM.widgets.string.widget(f, v, _id=inp_id, _autocomplete="off", **{"_data-provide":"typeahead"})
    itms_var = "autocomplete_bs_data_" + str(uuid.uuid4())[:8]
    scr = SCRIPT('$(document).ready(function() {var %s=%s; jQuery("#%s").typeahead({source: %s});});' % (itms_var, str(itms), inp_id, itms_var))
    wrapper.append(inp)
    wrapper.append(scr)
    return wrapper
