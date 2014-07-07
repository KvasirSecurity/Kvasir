# encoding: utf-8

"""
##--------------------------------------#
## Kvasir
##
## hping2 Utilities for Kvasir
##
## Author: Jan Rude
##--------------------------------------#
"""

import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir

@auth.requires_login()
def import_scan():
    """
    Upload/import hping2 Scan file via scheduler task
    """
    import time
    from skaldship.general import check_datadir

    filedir = os.path.join(request.folder,'data','scanfiles')
    check_datadir(request.folder)
    response.title = "%s :: Import hping2 Scan Results" % (settings.title)

    fields = []

    # buld the dropdown user list
    users = db(db.auth_user).select()
    userlist = []
    for user in users:
        userlist.append( [ user.id, user.username ] )

    fields.append(Field('f_filename', 'upload', uploadfolder=filedir, label=T('hping2 File')))
    fields.append(Field('f_engineer', type='integer', label=T('Engineer'), default=auth.user.id, requires=IS_IN_SET(userlist)))
    fields.append(Field('f_asset_group', type='string', label=T('Asset Group'), requires=IS_NOT_EMPTY()))
    form = SQLFORM.factory(*fields, table_name='hping2')

    if form.errors:
        response.flash = 'Error in form'
    elif form.accepts(request.vars, session):
        # process a hping2 file
        filename = form.vars.f_filename
        filename = os.path.join(filedir, form.vars.f_filename)

        from skaldship.hping2 import process_file
        print("Starting hping2 Import")
        process_file(
            filename=filename,
            asset_group=form.vars.f_asset_group,
            engineer=form.vars.f_engineer,
        )
        response.flash = "hping2 upload complete"
        redirect(URL('default', 'index'))

    return dict(form=form)

##-------------------------------------------------------------------------