/*
 * Kvasir Javascript functions
 */

/*
    # extends jQuery to make GetUrlVar(s) which will pull the GET variables from window.location.href
    #
    # Use: $.getUrlVars();    // gets all variables and returns an array
    #      $.getUrlVar('var') // returns only one variable name
    #
*/

$.extend({
    getUrlVars: function(){
        var vars = [], hash;
        var hashes = window.location.href.slice(window.location.href.indexOf('?') + 1).split('&');
        for(var i = 0; i < hashes.length; i++)
        {
            hash = hashes[i].split('=');
            vars.push(hash[0]);
            vars[hash[0]] = hash[1];
        }
        return vars;
    },
    getUrlVar: function(name){
        return $.getUrlVars()[name];
    }
});

function isArray(obj) {
    return obj.constructor == Array;
}

function ajax_form_submit(object, target) {
    /* Submits a form object through jquery.form.js and handling all the web2py features */
    jQuery(object).ajaxSubmit({
        'beforeSend':function(xhr) {
            xhr.setRequestHeader('web2py-component-location', document.location);
            xhr.setRequestHeader('web2py-component-element', target);
        },
        'success':function(responseText, statusText, xhr, $form) {
            var html=responseText;
            var content=xhr.getResponseHeader('web2py-component-content');
            var command=xhr.getResponseHeader('web2py-component-command');
            var flash=xhr.getResponseHeader('web2py-component-flash');
            var t = jQuery('#'+target);
            if(content=='prepend') t.prepend(html);
            else if(content=='append') t.append(html);
            else if(content!='hide') t.html(html);
            //web2py_trap_form(action,target);
            jQuery.web2py.trap_link(target);
            jQuery.web2py.ajax_init('#'+target);
            if(command)
            eval(decodeURIComponent(command));
            if(flash)
                jQuery('.flash').html(decodeURIComponent(flash));
        }
    });
}

/*  Goal: Display a tooltip/popover where the content is fetched from the
          application the first time only.

    How:  Fetch the appropriate content and register the tooltip/popover the first time
          the mouse enters a DOM element with class "withajaxpopover".  Remove the
          class from the element so we don't do that the next time the mouse enters.
          However, that doesn't show the tooltip/popover for the first time
          (because the mouse is already entered when the tooltip is registered).
          So we have to show/hide it ourselves.

    http://stackoverflow.com/a/13849716
*/
$(function() {
  $('body').on('hover', '.withajaxpopover', function(event){
      if (event.type === 'mouseenter') {
          var el=$(this);
          $.get(el.attr('data-load'),function(d){
              el.removeClass('withajaxpopover');
              el.popover({trigger: 'hover',
                          title: d.title,
                          content: d.content}).popover('show');
          });
      }  else {
          $(this).popover('hide');
      }
  });
});
