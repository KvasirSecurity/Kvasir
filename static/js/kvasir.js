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
                          content: d.content});
              el.popover('show');
          });
      }  else {
          $(this).popover('hide');
      }
  });
});

/* API method to get paging information */
$.fn.dataTableExt.oApi.fnPagingInfo = function ( oSettings )
{
    return {
        "iStart":         oSettings._iDisplayStart,
        "iEnd":           oSettings.fnDisplayEnd(),
        "iLength":        oSettings._iDisplayLength,
        "iTotal":         oSettings.fnRecordsTotal(),
        "iFilteredTotal": oSettings.fnRecordsDisplay(),
        "iPage":          oSettings._iDisplayLength === -1 ?
            0 : Math.ceil( oSettings._iDisplayStart / oSettings._iDisplayLength ),
        "iTotalPages":    oSettings._iDisplayLength === -1 ?
            0 : Math.ceil( oSettings.fnRecordsDisplay() / oSettings._iDisplayLength )
    };
}

/* Bootstrap style pagination control */
$.extend( $.fn.dataTableExt.oPagination, {
    "bootstrap": {
        "fnInit": function( oSettings, nPaging, fnDraw ) {
            var oLang = oSettings.oLanguage.oPaginate;
            var fnClickHandler = function ( e ) {
                e.preventDefault();
                if ( oSettings.oApi._fnPageChange(oSettings, e.data.action) ) {
                    fnDraw( oSettings );
                }
            };

            $(nPaging).addClass('pagination').append(
                '<ul>'+
                    '<li class="prev disabled"><a href="#">&larr; '+oLang.sPrevious+'</a></li>'+
                    '<li class="next disabled"><a href="#">'+oLang.sNext+' &rarr; </a></li>'+
                '</ul>'
            );
            var els = $('a', nPaging);
            $(els[0]).bind( 'click.DT', { action: "previous" }, fnClickHandler );
            $(els[1]).bind( 'click.DT', { action: "next" }, fnClickHandler );
        },

        "fnUpdate": function ( oSettings, fnDraw ) {
            var iListLength = 5;
            var oPaging = oSettings.oInstance.fnPagingInfo();
            var an = oSettings.aanFeatures.p;
            var i, j, sClass, iStart, iEnd, iHalf=Math.floor(iListLength/2);

            if ( oPaging.iTotalPages < iListLength) {
                iStart = 1;
                iEnd = oPaging.iTotalPages;
            }
            else if ( oPaging.iPage <= iHalf ) {
                iStart = 1;
                iEnd = iListLength;
            } else if ( oPaging.iPage >= (oPaging.iTotalPages-iHalf) ) {
                iStart = oPaging.iTotalPages - iListLength + 1;
                iEnd = oPaging.iTotalPages;
            } else {
                iStart = oPaging.iPage - iHalf + 1;
                iEnd = iStart + iListLength - 1;
            }

            for ( i=0, iLen=an.length ; i<iLen ; i++ ) {
                // Remove the middle elements
                $('li:gt(0)', an[i]).filter(':not(:last)').remove();

                // Add the new list items and their event handlers
                for ( j=iStart ; j<=iEnd ; j++ ) {
                    sClass = (j==oPaging.iPage+1) ? 'class="active"' : '';
                    $('<li '+sClass+'><a href="#">'+j+'</a></li>')
                        .insertBefore( $('li:last', an[i])[0] )
                        .bind('click', function (e) {
                            e.preventDefault();
                            oSettings._iDisplayStart = (parseInt($('a', this).text(),10)-1) * oPaging.iLength;
                            fnDraw( oSettings );
                        } );
                }

                // Add / remove disabled classes from the static elements
                if ( oPaging.iPage === 0 ) {
                    $('li:first', an[i]).addClass('disabled');
                } else {
                    $('li:first', an[i]).removeClass('disabled');
                }

                if ( oPaging.iPage === oPaging.iTotalPages-1 || oPaging.iTotalPages === 0 ) {
                    $('li:last', an[i]).addClass('disabled');
                } else {
                    $('li:last', an[i]).removeClass('disabled');
                }
            }
        }
    }
} );
