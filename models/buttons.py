# Template helpers

import os

def button(href, label):
  return A(SPAN(label),_class='button',_href=href)
  
def sp_button(href, label):
  return A(SPAN(label),_class='button special',_href=href)
  
def helpicon():
  return IMG(_src=URL(request.application, 'static', 'images/help.png'), _alt='help')
  
def searchbox(elementid):
  return TAG[''](LABEL(IMG(_src=URL(request.application, 'static', 'images/search.png'), _alt=T('filter')), _class='icon', _for=elementid), ' ', INPUT(_id=elementid, _type='text', _size=12))
