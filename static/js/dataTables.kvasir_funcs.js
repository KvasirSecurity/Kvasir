/*******************************************
    * fnReloadAjax
    *
    * Example call to load a new file *
    * oTable.fnReloadAjax( 'media/examples_support/json_source2.txt' );
    *
    * Example call to reload from original file
    * oTable.fnReloadAjax();
    *******************************************/

$.fn.dataTableExt.oApi.fnReloadAjax = function ( oSettings, sNewSource, fnCallback, bStandingRedraw )
{
    if ( typeof sNewSource != 'undefined' && sNewSource != null )
    {
        oSettings.sAjaxSource = sNewSource;
    }
    this.oApi._fnProcessingDisplay( oSettings, true );
    var that = this;
    var iStart = oSettings._iDisplayStart;

    oSettings.fnServerData( oSettings.sAjaxSource, [], function(json) {
        /* Clear the old information from the table */
        that.oApi._fnClearTable( oSettings );

    /* Got the data - add it to the table */
    for ( var i=0 ; i<json.aaData.length ; i++ )
    {
        that.oApi._fnAddData( oSettings, json.aaData[i] );
    }

    oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
    that.fnDraw();

    if ( typeof bStandingRedraw != 'undefined' && bStandingRedraw === true )
    {
        oSettings._iDisplayStart = iStart;
        that.fnDraw( false );
    }

    that.oApi._fnProcessingDisplay( oSettings, false );

    /* Callback user function - for event handlers etc */
    if ( typeof fnCallback == 'function' && fnCallback != null )
    {
        fnCallback( oSettings );
    }
}, oSettings );
}

/*******************************************
    * ip-address column type
    *
    *  "aoColumnDefs": [
    *     { "sType": "ip-address", "aTargets": [ 2 ] },
    *  ],
    *******************************************/

jQuery.fn.dataTableExt.aTypes.push(
    function ( sData )
    {
        if (/^\d{1,3}[\.]\d{1,3}[\.]\d{1,3}[\.]\d{1,3}$/.test(sData)) {
            return 'ip-address';
        }
        return null;
    }
);

jQuery.fn.dataTableExt.oSort['ip-address-asc']  = function(a,b) {
    var m = a.split("."), x = "";
    var n = b.split("."), y = "";
    for(var i = 0; i < m.length; i++) {
        var item = m[i];
        if(item.length == 1) {
            x += "00" + item;
        } else if(item.length == 2) {
            x += "0" + item;
        } else {
            x += item;
        }
    }
    for(var i = 0; i < n.length; i++) {
        var item = n[i];
        if(item.length == 1) {
            y += "00" + item;
        } else if(item.length == 2) {
            y += "0" + item;
        } else {
            y += item;
        }
    }
    return ((x < y) ? -1 : ((x > y) ? 1 : 0));
};

jQuery.fn.dataTableExt.oSort['ip-address-desc']  = function(a,b) {
    var m = a.split("."), x = "";
    var n = b.split("."), y = "";
    for(var i = 0; i < m.length; i++) {
        var item = m[i];
        if(item.length == 1) {
            x += "00" + item;
        } else if (item.length == 2) {
            x += "0" + item;
        } else {
            x += item;
        }
    }
    for(var i = 0; i < n.length; i++) {
        var item = n[i];
        if(item.length == 1) {
            y += "00" + item;
        } else if (item.length == 2) {
            y += "0" + item;
        } else {
            y += item;
        }
    }
    return ((x < y) ? 1 : ((x > y) ? -1 : 0));
};

/*******************************************
    * numbers with HTML
    *
    *  "aoColumnDefs": [
    *     { "sType": "num-html", "aTargets": [ 2 ] },
    *  ],
    *******************************************/

jQuery.fn.dataTableExt.aTypes.push( function ( sData )
{
    if (!sData) {    // check to see if sData is undefined
        return null;
    }

    // Check to see if sData is an array, if so then convert
    // to string and process
    if (isArray(sData)) {
        sData = sData.toString();
    }

    sData = typeof sData.replace == 'function' ?
        sData.replace( /<.*?>/g, "" ) : sData;

    var sValidFirstChars = "0123456789-";
    var sValidChars = "0123456789.";
    var Char;
    var bDecimal = false;

    /* Check for a valid first char (no period and allow negatives) */
    if (! isNaN(sData)) {
        return null;
    }

    Char = sData.charAt(0);
    if (sValidFirstChars.indexOf(Char) == -1)
    {
        return null;
    }

    /* Check all the other characters are valid */
    for ( var i=1 ; i<sData.length ; i++ )
    {
        Char = sData.charAt(i);
        if (sValidChars.indexOf(Char) == -1)
        {
            return null;
        }

    /* Only allowed one decimal place... */
    if ( Char == "." )
    {
        if ( bDecimal )
        {
            return null;
        }
        bDecimal = true;
    }
}

    return 'num-html';
} );

jQuery.fn.dataTableExt.oSort['num-html-asc']  = function(a,b) {
    var x = a.replace( /<.*?>/g, "" );
    var y = b.replace( /<.*?>/g, "" );
    x = parseFloat( x );
    y = parseFloat( y );
    return ((x < y) ? -1 : ((x > y) ?  1 : 0));
};

jQuery.fn.dataTableExt.oSort['num-html-desc'] = function(a,b) {
    var x = a.replace( /<.*?>/g, "" );
    var y = b.replace( /<.*?>/g, "" );
    x = parseFloat( x );
    y = parseFloat( y );
    return ((x < y) ?  1 : ((x > y) ? -1 : 0));
};

/*******************************************
    * Numbers only (strips non-numeric)
    *
    *  "aoColumnDefs": [
    *     { "sSortDataType": "formatted-num", "aTargets": [ 6 ] },
    *  ],
    *******************************************/

jQuery.fn.dataTableExt.oSort['formatted-num-asc'] = function(x,y){
    x = x.replace(/[^\d\-\.\/]/g,'');
    y = y.replace(/[^\d\-\.\/]/g,'');
    if(x.indexOf('/')>=0)x = eval(x);
    if(y.indexOf('/')>=0)y = eval(y);
    return x/1 - y/1;
}
jQuery.fn.dataTableExt.oSort['formatted-num-desc'] = function(x,y){
    x = x.replace(/[^\d\-\.\/]/g,'');
    y = y.replace(/[^\d\-\.\/]/g,'');
    if(x.indexOf('/')>=0)x = eval(x);
    if(y.indexOf('/')>=0)y = eval(y);
    return y/1 - x/1;
}

/*********************************************
    * Return filtered nodes only
    *********************************************/

$.fn.dataTableExt.oApi.fnGetFilteredNodes = function ( oSettings )
{
    var anRows = [];
    for ( var i=0, iLen=oSettings.aiDisplay.length ; i<iLen ; i++ )
    {
        var nRow = oSettings.aoData[ oSettings.aiDisplay[i] ].nTr;
        anRows.push( nRow );
    }
    return anRows;
};

/***********************************************
    * Returns an array of values from a column
    ***********************************************/

$.fn.dataTableExt.oApi.fnGetColumnData = function ( oSettings, iColumn, bUnique, bFiltered, bIgnoreEmpty ) {
    // check that we have a column id
    if ( typeof iColumn == "undefined" ) return new Array();

    // by default we only wany unique data
    if ( typeof bUnique == "undefined" ) bUnique = true;

    // by default we do want to only look at filtered data
    if ( typeof bFiltered == "undefined" ) bFiltered = true;

    // by default we do not wany to include empty values
    if ( typeof bIgnoreEmpty == "undefined" ) bIgnoreEmpty = true;

    // list of rows which we're going to loop through
    var aiRows;

    // use only filtered rows
    if (bFiltered == true) aiRows = oSettings.aiDisplay;
    // use all rows
    else aiRows = oSettings.aiDisplayMaster; // all row numbers

    // set up data array
    var asResultData = new Array();

    for (var i=0,c=aiRows.length; i<c; i++) {
        iRow = aiRows[i];
        var aData = this.fnGetData(iRow);
        var sValue = aData[iColumn];

    // ignore empty values?
    if (bIgnoreEmpty == true && sValue.length == 0) continue;

    // ignore unique values?
    else if (bUnique == true && jQuery.inArray(sValue, asResultData) > -1) continue;

    // else push the value onto the result data array
    else asResultData.push(sValue);
}

    return asResultData;
};

/***********************************************************
    * Creates a <select> box from passed values
    ***********************************************************/

function fnCreateSelect( aData )
{
    var r='<select><option value=""></option>', i, iLen=aData.length;
    for ( i=0 ; i<iLen ; i++ )
    {
        r += '<option value="'+aData[i]+'">'+aData[i]+'</option>';
    }
    return r+'</select>';
}

/*
    * Function: fnGetDisplayNodes
    * Purpose:  Return an array with the TR nodes used for displaying the table
    * Returns:  array node: TR elements
    *           or
    *           node (if iRow specified)
    * Inputs:   object:oSettings - automatically added by DataTables
    *           int:iRow - optional - if present then the array returned will be the node for
    *             the row with the index 'iRow'
    */
$.fn.dataTableExt.oApi.fnGetDisplayNodes = function ( oSettings, iRow )
{
    var anRows = [];
    if ( oSettings.aiDisplay.length !== 0 )
    {
        if ( typeof iRow != 'undefined' )
        {
            return oSettings.aoData[ oSettings.aiDisplay[iRow] ].nTr;
        }
        else
        {
            for ( var j=oSettings._iDisplayStart ; j<oSettings._iDisplayEnd ; j++ )
            {
                var nRow = oSettings.aoData[ oSettings.aiDisplay[j] ].nTr;
                anRows.push( nRow );
            }
        }
    }
    return anRows;
};

/****************************************
 * Handle JSON errors in Datatables
 * http://datatables.net/forums/discussion/7325/processing-notice-and-ajax-error-handling/p1
 ****************************************/

function handleDTAjaxError( xhr, textStatus, error ) {
    if ( textStatus === 'timeout' ) {
        alert( 'The server took too long to send the data.' );
    }
    else {
        alert( 'Kvasir failed on the data load, check your Javascript console for the ticket.' );
    }
    //myDataTable.fnProcessingIndicator( false );
}

jQuery.fn.dataTableExt.oApi.fnSetFilteringDelay = function ( oSettings, iDelay ) {
    var _that = this;

    if ( iDelay === undefined ) {
        iDelay = 250;
    }

    this.each( function ( i ) {
        $.fn.dataTableExt.iApiIndex = i;
        var
            $this = this,
            oTimerId = null,
            sPreviousSearch = null,
            anControl = $( 'input', _that.fnSettings().aanFeatures.f );

            anControl.unbind( 'keyup' ).bind( 'keyup', function() {
            var $$this = $this;

            if (sPreviousSearch === null || sPreviousSearch != anControl.val()) {
                window.clearTimeout(oTimerId);
                sPreviousSearch = anControl.val();
                oTimerId = window.setTimeout(function() {
                    $.fn.dataTableExt.iApiIndex = i;
                    _that.fnFilter( anControl.val() );
                }, iDelay);
            }
        });

        return this;
    } );
    return this;
};
