#-*- encoding:utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
##
## Formstyles for Forms and Modals
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#

from gluon.html import A, DIV, H3, BUTTON, I, SCRIPT
from gluon.sqlhtml import SQLFORM
from gluon.compileapp import LOAD
from gluon.http import HTTP
from gluon import current


##-------------------------------------------------------------------------

def formstyle_bootstrap_modal(form, fields, **kwargs):
    """"
    Bootstrap format modal form layout
    """
    span = kwargs.get('span') or 'span8'
    select_attributes = kwargs.get('select_attributes', '')
    form.add_class('form-horizontal')
    parent = FIELDSET()
    for id, label, controls, help in fields:
        _controls = DIV(controls, _class='controls')
        # submit unflag by default
        _submit = False

        if isinstance(controls, INPUT):
            controls.add_class(span)
            if controls['_type'] == 'submit':
                # flag submit button
                _submit = True
                controls['_class'] = 'btn btn-primary'
            if controls['_type'] == 'file':
                controls['_class'] = 'input-file'

        # For password fields, which are wrapped in a CAT object.
        if isinstance(controls, CAT) and isinstance(controls[0], INPUT):
            controls[0].add_class(span)

        if isinstance(controls, SELECT):
            controls.add_class(span)

        if isinstance(controls, TEXTAREA):
            controls.add_class(span)

        if isinstance(label, LABEL):
            label['_class'] = 'control-label'
            if help:
                label.append(I(_class="icon-question-sign", _rel="tooltip", **{ '_data-content':help }))

        if _submit:
            # submit button has unwrapped label and controls, different class
            parent.append(DIV(label, BUTTON("Close", _class="btn", **{'_data-dismiss':'modal', '_aria-hidden':True}), controls, _class='modal-footer', _id=id))
            # unflag submit (possible side effect)
            _submit = False
        else:
            # unwrapped label
            _class = 'control-group'
            parent.append(DIV(label, _controls, _class=_class, _id=id))

    # append tooltip and chosen field attributes
    if 'id' not in form.attributes:
        form.attributes['_id'] = "%s-id" % (str(form.table))
    script_data = """$(document).ready(function() {{
    $("[rel=tooltip]").popover({{
        placement: 'right',
        trigger: 'hover',
    }});
    $('#{0:s} select').select2({{{1:s}}});
    {2:s}
}});""".format(form.attributes['_id'], select_attributes, kwargs.get('script', ''))
    parent.append(SCRIPT(script_data))
    return parent
SQLFORM.formstyles['bootstrap-modal'] = formstyle_bootstrap_modal

##-------------------------------------------------------------------------

def formstyle_bootstrap_kvasir(form, fields, **kwargs):
    """
    Bootstrap format form layout for Kvasir
    """
    span = kwargs.get('span') or 'span8'
    select_attributes = kwargs.get('select_attributes', '')
    form.add_class('form-horizontal')
    parent = FIELDSET()
    for id, label, controls, help in fields:
        # wrappers
        _controls = DIV(controls, _class='controls')
        # submit unflag by default
        _submit = False

        if isinstance(controls, INPUT):
            controls.add_class('span8')
            if controls['_type'] == 'submit':
                # flag submit button
                _submit = True
                controls['_class'] = 'btn btn-primary'
            if controls['_type'] == 'file':
                controls['_class'] = 'input-file'

        # For password fields, which are wrapped in a CAT object.
        if isinstance(controls, CAT) and isinstance(controls[0], INPUT):
            controls[0].add_class(span)

        if isinstance(controls, SELECT):
            controls.add_class(span)

        if isinstance(controls, TEXTAREA):
            controls.add_class(span)

        if isinstance(label, LABEL):
            label['_class'] = 'control-label'
            if help:
                label.append(I(_class="icon-question-sign", _rel="tooltip", **{ '_data-content':help }))

        if _submit:
            # submit button has unwrapped label and controls, different class
            parent.append(DIV(label, controls, _class='form-actions', _id=id))
            # unflag submit (possible side effect)
            _submit = False
        else:
            # unwrapped label
            parent.append(DIV(label, _controls, _class='control-group', _id=id))

    # append tooltip and select2 field attributes
    if '_id' not in form.attributes:
        form.attributes['_id'] = "%s-id" % (str(form.table))
    script_data = """$(document).ready(function() {{
    $("[rel=tooltip]").popover({{
        placement: 'right',
        trigger: 'hover',
    }});
    $('#{0:s} select').select2({{{1:s}}});
    {2:s}
}});""".format(form.attributes['_id'], select_attributes, kwargs.get('script', ''))
    parent.append(SCRIPT(script_data))
    return parent
SQLFORM.formstyles['bootstrap_kvasir'] = formstyle_bootstrap_kvasir
# overwrite the "default" table3cols with default bootstrap
SQLFORM.formstyles.table3cols = SQLFORM.formstyles.bootstrap_kvasir

##-------------------------------------------------------------------------

class AddModal(object):
    """
    AddModal provides a modular method for creating "Add ..." bootstrap modals
    and relevant FORM data.

    Usage in controller:
        add = AddModal(
            db.db_name, 'Add', 'Add', 'Add Thing',
            #fields=[],
            cmd='table.fnReloadAjax();'
        )
        #db.t_services.f_hosts_id.default = record.id
        db.db_name.id.comment = add.create()

    Usage in HTML:
        {{=XML(add.formModal())}}    // Generates the modal HTML
        {{=XML(add.btn_show())}}     // Generates the A(..) object
    """
    def __init__(self, table, value, title_btn, title_modal, fields=None, flash="Record created", cmd="", errormsg="Error in form", **kwargs):
        self.table = table
        self.value = value
        self.title_btn = title_btn
        self.title_modal = title_modal
        self.fields = fields
        self.flash = flash
        self.cmd = cmd
        self.errormsg = errormsg
        self.kwargs = kwargs
        self.key = str(self.table).replace('.', '_')
        self.modal_id = 'modal_%s' % self.key
        self._target = "c_" + self.key
        self.request = current.request
        self.response = current.response
        self.session = current.session
        self.script = kwargs.get('script')

    def btn_show(self, icon="icon-plus", btn_role="button", btn_class="btn btn-small"):
        """
        Generates an A() button object. By default a btn class and icon object are created
        but sending obj.btn_show(btn_role="", btn_class="", icon="") will clear all that.
        """
        btn_show_modal = A(I(_class=icon),
                           ' ', self.value,
                           **{"_role": btn_role,
                           "_class": btn_class,
                           "_data-toggle": "modal",
                           "_href": "#%s" % self.modal_id,
                           "_title": self.title_btn})
        return btn_show_modal

    def div_modal(self, content_modal):
        div_modal = DIV(
                        DIV(
                            # BUTTON("x", _type="button", _class="close", **{'data-dismiss':"modal", 'aria-hidden':"true"}),
                            BUTTON("x", **{"_type":"button", "_class": "close", "_data-dismiss": "modal", "_aria-hidden": "true"}),
                            H3(self.title_modal, _id="myModalLabel"),
                               _class="modal-header"),
                        DIV(content_modal, _class="modal-body", _id="host-modal"),
                        SCRIPT("$('#%s').on('show', function () { $(this).find('.modal-body').css({'overflow-y':'scroll', 'width':'auto', 'height':'auto'});});" % self.modal_id),
                        **{"_id": "%s" % self.modal_id,
                           "_class": "modal bigModal hide face",
                           "_tabindex": "-1",
                           "_role": "dialog",
                           "_data-keyboard": "false",
                           "_aria-hidden": "true",
                           "_aria-labelledby": "myModalLabel"}
                    )
        return div_modal

    def create(self):
        if self.request.get_vars._ajax_add == str(self.table):
            raise HTTP(200, self.checkForm(self.table))
        return self.btn_show()

    def formModal(self):
        return self.div_modal(LOAD(self.request.controller,
                                   self.request.function,
                                   args=self.request.args,
                                   vars=dict(_ajax_add=self.table),
                                   target=self._target,
                                   ajax=True)
                                  )

    def checkForm(self, table):
        formnamemodal = "formmodal_%s" % self.key
        form = SQLFORM(table, formname=formnamemodal, _class="form-horizontal", formstyle='bootstrap-modal', fields=self.fields, kwargs=self.kwargs)
        if self.script:
            form.append(SCRIPT(self.script))
        if form.process().accepted:
            command = "jQuery('#%s').modal('hide');" % (self.modal_id)
            command += self.cmd
            self.response.flash = self.flash
            self.response.js = command
        elif form.errors:
            self.response.flash = self.errormsg

        return form
