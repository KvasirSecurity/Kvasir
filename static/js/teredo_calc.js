/* This code is ripped from http://silmor.de/ipaddrcalc.html
 * © Konrad Rosenbaum, 2012
 * konrad@silmor.de
 * licensed under GPLv3
 */

// //////////////////////////////////////////////
// generic functions

function dec2hex(val)
{
  var str="";
  var minus=false;
  if(val<0){minus=true;val*=-1;}
  val=Math.floor(val);
  while(val>0){
    var v=val%16;
    val/=16;val=Math.floor(val);
    switch(v){
      case 10:v="A";break;
      case 11:v="B";break;
      case 12:v="C";break;
      case 13:v="D";break;
      case 14:v="E";break;
      case 15:v="F";break;
    }
    str=v + str;
  }
  if(str=="")str="0";
  if(minus)str="-"+str;
  return str;
}

//convert ipv6 string to array
function parseIp6(str)
{
  //init
  var ar=new Array;
  for(var i=0;i<8;i++)ar[i]=0;
  //check for trivial IPs
  if(str=="::")return ar;
  //parse
  var sar=str.split(':');
  var slen=sar.length;
  if(slen>8)slen=8;
  var j=0;
  for(var i=0;i<slen;i++){
    //this is a "::", switch to end-run mode
    if(i && sar[i]==""){j=9-slen+i;continue;}
    ar[j]=parseInt("0x0"+sar[i]);
    j++;
  }

  return ar;
}

//convert ipv6 array to string
function ip6toString(ar)
{
  //init
  var str="";
  //find longest stretch of zeroes
  var zs=-1,zsf=-1;
  var zl=0,zlf=0;
  var md=0;
  for(var i=0;i<8;i++){
    if(md){
      if(ar[i]==0)zl++;
      else md=0;
    }else{
      if(ar[i]==0){zs=i;zl=1;md=1;}
    }
    if(zl>2 && zl>zlf){zlf=zl;zsf=zs;}
  }
  //print
  for(var i=0;i<8;i++){
    if(i==zsf){
      str+=":";
      i+=zlf-1;
      if(i>=7)str+=":";
      continue;
    }
    if(i)str+=":";
    str+=dec2hex(ar[i]);
  }
//   alert("printv6 str="+str+" zsf="+zsf+" zlf="+zlf);
  return str;
}

//create a mask from a prefix
function ip6prefixToMask(prf)
{
  var ar=new Array;
  for(var i=0;i<8;i++){
    if(prf>=16)ar[i]=0xffff;
    else switch(prf){
      case 1:ar[i]=0x8000;break;
      case 2:ar[i]=0xc000;break;
      case 3:ar[i]=0xe000;break;
      case 4:ar[i]=0xf000;break;
      case 5:ar[i]=0xf800;break;
      case 6:ar[i]=0xfc00;break;
      case 7:ar[i]=0xfe00;break;
      case 8:ar[i]=0xff00;break;
      case 9:ar[i]=0xff80;break;
      case 10:ar[i]=0xffc0;break;
      case 11:ar[i]=0xffe0;break;
      case 12:ar[i]=0xfff0;break;
      case 13:ar[i]=0xfff8;break;
      case 14:ar[i]=0xfffc;break;
      case 15:ar[i]=0xfffe;break;
      default:ar[i]=0;break;
    }
    prf-=16;
  }
  return ar;
}

function ip6mask(ip,prf)
{
  if(typeof(prf)=="number")prf=ip6prefixToMask(prf);
  var ip2=new Array;
  for(var i=0;i<8;i++)ip2[i] = ip[i] & prf[i];
  return ip2;
}




// ///////////////////////////////////////////////////////
// IPv4 to IPv6 translation functions

function teredocalc()
{
  var tip=parseIp6(document.getElementById("teredo").value);
  var prefix=ip6toString(ip6mask(tip,ip6prefixToMask(32)))+"/32";
  if(tip[0]!=0x2001 || tip[1]!=0)prefix+=" not a Teredo address!";
  document.getElementById("teredo-prefix").innerHTML=prefix;
  var ip4 = (tip[2]>>8) + "." + (tip[2]&0xff) + "." + (tip[3]>>8) + "." + (tip[3]&0xff);
  document.getElementById("teredo-server").innerHTML=ip4;
  ip4 = (tip[6]>>8^0xff) + "." + (tip[6]&0xff^0xff) + "." + (tip[7]>>8^0xff) + "." + (tip[7]&0xff^0xff);
  document.getElementById("teredo-ip").innerHTML    =ip4;
  document.getElementById("teredo-port").innerHTML  =tip[5]^0xffff;
  var flags="";
  if(tip[4]&0x8000)flags="Cone NAT";else flags="Non Cone NAT";
  flags+=" ("+tip[4]+")";
  document.getElementById("teredo-flags").innerHTML =flags;
}
