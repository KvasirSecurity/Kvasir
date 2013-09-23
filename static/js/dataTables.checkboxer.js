/*******************
 Checkboxer functions for dataTables.
 *******************/

/* Grab selected dataTables TR entries from a datatable
   Returns an array of html objects */
function dt_checkboxer_fnGetSelected(oTableLocal)
{
    var aReturn = new Array();
    var aTrs = oTableLocal.fnGetDisplayNodes();

    for ( var i=0 ; i<aTrs.length ; i++ )
    {
        if ( $(aTrs[i]).hasClass('row_selected') ) {
            aReturn.push( aTrs[i] );
        }
    }
    return aReturn;
}

/* Return a list of selected table items */
function dt_checkboxer_fnGetRowIDs(oTableLocal)
{
    var selected = dt_checkboxer_fnGetSelected(oTableLocal);
    var selector = '#' + oTableLocal + 'div[name="row_id"]';
    var rowids = $(selected).find(selector).map(function() { return $(this).attr('id'); }).get();
    //var idreq='';
    //rowids.forEach(function(data) { idreq = idreq + '/' + data });
    return rowids
}

/* Takes an array of selected boxes and returns a string of the data values */
function dt_checkboxer_make_idReq(selected)
{
    var idreq='';
    if (!isArray(selected)) {
        return ""
    }
    selected.forEach( function(data) {
        idreq = idreq+"|"+data['value'];
    });
    /* removes the initial | from idreq */
    return idreq.substr(1);
}

/* Takes a dataTable variable, retrieves the selected rows and returns
   a string of DT_RowIds based on DataTable RowIds */
function dt_checkboxer_select_DT_RowIds(oTableLocal)
{
    var selected = oTableLocal._('tr.row_selected', {'filter':'applied'});
    var idreq='';
    selected.forEach( function(data) {
        if (data['DT_RowId'])
            idreq = idreq + "|" + data['DT_RowId'];
    });
    return idreq.substr(1);
}

/* Takes a dataTable variable, retrieves the selected rows and returns
   a string of DT_RowIds based on tr id fields. Id must be first entry */
function dt_checkboxer_select_DT_TRIds(oTableLocal)
{
    var selected = oTableLocal._('tr.row_selected', {'filter':'applied'});
    var idreq='';
    selected.forEach( function(data) {
        var id = $(data[0]).attr('id');
        if (id)
            idreq = idreq + "|" + id;
    });
    return idreq.substr(1);
}
