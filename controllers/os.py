# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## OS controller
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from skaldship.hosts import get_host_record, host_title_maker, host_a_maker
import logging
logger = logging.getLogger("web2py.app.kvasir")
crud.settings.formstyle = formstyle_bootstrap_kvasir


@auth.requires_login()
def index():
    return redirect(URL('list'))

##-------------------------------------------------------------------------
## t_os - this is the local engagement copy of CPE OS
##-------------------------------------------------------------------------

@auth.requires_login()
def add():
    response.title = "%s :: Add OS to Engagement" % (settings.title)
    form=crud.create(db.t_os,next='os_edit/[id]')
    return dict(form=form)

@auth.requires_login()
def read():
    record = db.t_os(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('OS record not found')}))
    response.title = "%s :: Engagement OS Entry Detail :: %s" % (settings.title, record.f_title)
    form=crud.read(db.t_os,record)
    return dict(form=form)

@auth.requires_login()
def edit():
    record = db.t_os(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('OS record not found')}))
    response.title = "%s :: Update Engagement OS :: %s" % (settings.title, record.f_title)
    form=crud.update(db.t_os,record,next='edit/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    return dict(form=form)

@auth.requires_login()
def list():
    response.title = "%s :: Engagement OS Table" % (settings.title)
    if request.extension == 'json':
        query = db.t_os
        rows=db(query)(db.t_os).select()

        aaData = []
        # datatable formatting is specific
        for r in rows:
            atxt = {}
            atxt['0'] = A('edit', _target="os_update_%s" % (r.id), _href="edit/%s" % (r.id)).xml()
            atxt['1'] = r.f_cpename
            atxt['2'] = r.f_title
            atxt['3'] = r.f_vendor
            atxt['4'] = r.f_product
            atxt['5'] = r.f_version
            atxt['6'] = r.f_update
            atxt['7'] = r.f_edition
            atxt['8'] = r.f_language
            atxt['DT_RowId'] = r.id

            aaData.append(atxt)

        totalrecords = db(db.t_os).count()

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': totalrecords,
                   'aaData': aaData,
                   }

        return result
    else:
        add = AddModal(
            db.t_os, 'Add Manual', 'Add Manual', 'Add Manual OS',
            #fields=[],
            cmd='ostable.fnReloadAjax();'
        )
        db.t_os.id.comment = add.create()

        return dict(add=add)

@auth.requires_signature()
@auth.requires_login()
def delete():
    count = 0
    for r in request.vars.ids.split('|'):
        if r is not None:
            db(db.t_os.id == r).delete()
            count += 1
    db.commit()
    response.flash = "%s OS record(s) deleted" % (count)
    response.headers['web2py-component-command'] = "ostable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    #response.js = "hosttable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"

    return dict()

##-------------------------------------------------------------------------
## references
##-------------------------------------------------------------------------

@auth.requires_login()
def refs_add():
    if request.vars.has_key('id'):
        host_id = db.t_hosts[request.vars.id] or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv4'):
        host_id = db(db.t_hosts.f_ipv4 == request.vars.ipv4) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    elif request.vars.has_key('ipv6'):
        host_id = db(db.t_hosts.f_ipv6 == request.vars.ipv6) or redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))
    else:
        host_id = None

    if host_id:
        db.t_host_os_refs.f_hosts_id.default = host_id.id
        db.t_host_os_refs.f_certainty.default = "1.0"
        form=crud.create(db.t_host_os_refs, next=URL('os_refs_create', vars={'id': host_id.id}),
                         message="OS added")
        db.t_host_os_refs.f_hosts_id.default = None
        db.t_host_os_refs.f_certainty.default = None
    else:
        form=crud.create(db.t_host_os_refs,next='os_refs_edit/[id]', message="OS added")

    response.title = "%s :: Connect OS to a Host" % (settings.title)
    return dict(form=form)

@auth.requires_login()
def refs_edit():
    record = db.t_host_os_refs(request.args(0)) or redirect(URL('default', 'error', vars={'msg': T('OS Reference record not found')}))
    form=crud.update(db.t_host_os_refs,record,next='refs_edit/[id]',
                     ondelete=lambda form: redirect(URL('refs_list')))
    response.title = "%s :: OS for Host %s" % (settings.title, host_title_maker(db.t_hosts(record.f_hosts_id)))
    return dict(form=form)

@auth.requires_login()
def refs_list():
    #class VirtFields(object):
    #    def hostinfo(self):
    #        return host_title_maker(self.t_host_os_refs.f_hosts_id)
    #    def osinfo(self):
    #        return "%s :: %s" % (self.t_host_os_refs.f_os_id.f_cpename, self.t_host_os_refs.f_os_id.f_title)
    #db.t_host_os_refs.virtualfields.append(VirtFields())
    if request.extension == "json":
        rows=db(db.t_host_os_refs.f_os_id == db.t_os.id).select()
        aaData = []
        for row in rows:
            atxt = {}
            atxt['0'] =  A("edit", _target="os_refs_update_%s" % (row.t_host_os_refs.id), _href=URL('refs_edit',extension='html',args=row.t_host_os_refs.id)).xml()
            atxt['1'] = row.t_host_os_refs.f_certainty
            atxt['2'] = row.t_host_os_refs.f_class
            atxt['3'] = row.t_host_os_refs.f_family
            atxt['4'] = host_a_maker(row.t_host_os_refs.f_hosts_id).xml()
            atxt['5'] = "%s :: %s" % (row.t_os.f_cpename, row.t_os.f_title)
            atxt['DT_RowId'] = row.t_host_os_refs.id
            aaData.append(atxt)

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    response.title = "%s :: OS/Host References" % (settings.title)
    form = TABLE(THEAD(TR(TH(T(''), _width="5%"),
                          TH(T('Certainty')),
                          TH(T('Class')),
                          TH(T('Family')),
                          TH(T('Host')),
                          TH(T('OS')),
                          )  ),
                 TFOOT(TR(TH(), TH(), TH(), TH(), TH(), TH())),
                 _class="datatable",
                 _id="ostable",
                 _style="width:100%")

    add_ref = AddModal(
        db.t_host_os_refs, 'Link OS', 'Link OS', 'Link OS Reference',
        #fields=[],
        cmd='ostable.fnReloadAjax();'
    )
    db.t_host_os_refs.id.comment = add_ref.create()

    add_os = AddModal(
        db.t_os, 'Add Non-CPE to OS DB', 'Add Non-CPE to OS DB', 'Add Non-CPE to OS DB',
        #fields=[],
        )
    db.t_os.id.comment = add_os.create()

    return dict(form=form, add_ref=add_ref, add_os=add_os)

@auth.requires_signature()
@auth.requires_login()
def refs_delete():
    count = 0
    for r in request.vars.ids.split('|'):
        if db(db.t_host_os_refs.id == r).delete():
            count += 1
    db.commit()
    response.flash = "%s OS Record(s) deleted" % (count)
    response.headers['web2py-component-command'] = "ostable.fnReloadAjax(); jQuery('.datatable tr.DTTT_selected').removeClass('DTTT_selected');"
    return

@auth.requires_login()
def refs_by_host():
    """
    Returns a list of OS records based upon an host identifier
    (id, ipv4, ipv6)
    """
    if request.args(0) is None: redirect(URL('default', 'error', vars={'msg': T('No host record sent')}))

    record = get_host_record(request.args(0))

    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    response.title = "%s :: OS Records for %s" % (settings.title, host_title_maker(record))
    oslist = db(db.t_host_os_refs.f_hosts_id==record.id).select()

    aaData = []
    if request.extension == "json":
        for osdetail in oslist:
            osinfo = db.t_os(osdetail['f_os_id'])
            # datatables json requires aaData to be specificly formatted
            atxt = {}
            atxt['0'] = A('edit', _target="oswindow_%s" % (osdetail.id), _href=URL('refs_edit', args=[osdetail.id], extension='html')).xml()
            atxt['1'] = osdetail.f_family
            atxt['2'] = osdetail.f_class
            atxt['3'] = osdetail.f_certainty
            atxt['4'] = osinfo.f_cpename
            atxt['5'] = osinfo.f_title
            atxt['DT_RowId'] = osdetail.id

            aaData.append(atxt)

        result = { 'sEcho': request.vars.sEcho,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    form = TABLE(THEAD(TR(TH(T(''), _width="5%"),
                          TH(T('Family')),
                          TH(T('Class')),
                          TH(T('Certainty')),
                          TH(T('CPE Name')),
                          TH(T('Title')),
                          )  ),
                 _class="datatable",
                 _id="ostable",
                 _style="width:100%")

    add_os_refs = AddModal(
        db.t_host_os_refs, 'Add', 'Add', 'Add OS',
        fields=['f_certainty', 'f_class', 'f_family', 'f_os_id'],
        cmd='ostable.fnReloadAjax();'
    )
    db.t_host_os_refs.f_hosts_id.default = record.id
    db.t_host_os_refs.id.comment = add_os_refs.create()

    add_non_cpe = AddModal(
        db.t_os, 'Add Non-CPE OS', 'Add Non-CPE OS', 'Add Non-CPE OS',
        #fields=[],
        #cmd='ostable.fnReloadAjax();'
    )
    db.t_os.id.comment = add_non_cpe.create()

    return dict(form=form, host=record, add_os_refs=add_os_refs, add_non_cpe=add_non_cpe)

@auth.requires_login()
def mass_assign():
    """
    Upload a CSV file that mass-assigns OS records to Hosts. If a CPE record is provided, look it up in the DB.
    If not lookup the vendor and product in the DB

    File format:

     ipaddress,cpe,family,vendor,product,certainty,osclass

    """
    response.title = "%s :: Mass OS Update" % (settings.title)
    form = SQLFORM.factory(
        Field('osfile', 'upload', uploadfolder=os.path.join(request.folder, 'data', 'misc'), label=T('OS CSV File')),
    )

    if form.accepts(request.vars,session):
        filename = os.path.join(request.folder,'data/misc',form.vars.osfile)
        import csv
        from skaldship.cpe import lookup_cpe
        #from skaldship.general import
        counter = 0
        with open(filename, "rb") as f:
            for row in csv.reader(f):
                host_id = get_host_record(row[0])
                if not host_id:
                    print "[%s] - Record not found" % (row[0])
                    continue

                cpe = row[1]
                family = row[2]
                vendor = row[3]
                product = row[4]
                certainty = row[5]
                osclass = row[6]
                os_id = None
                if cpe:
                    # we have a cpe entry from xml! hooray!
                    cpe_name = cpe.replace('cpe:/o:', '')
                    os_id = lookup_cpe(cpe_name)
                #else:
                    # no cpe attribute in xml, go through our messsy lookup
                #    os_id = guess_cpe_os(os_rec)

                if os_id:
                    db.t_host_os_refs.insert(f_certainty=certainty,
                                             f_family=family,
                                             f_class=osclass,
                                             f_hosts_id=host_id,
                                             f_os_id=os_id)
                    db.commit()
                    counter += 1
                else:
                    logger.error("OS not found: %s" % (row))
        response.flash = "%s Hosts updated with new OS records" % (counter)

    elif form.errors:
        response.flash = 'Error in form'

    return dict(form=form)
