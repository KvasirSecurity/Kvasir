# encoding: utf-8

__version__ = "1.0"

"""
##--------------------------------------#
## Kvasir
##
## (c) 2010-2013 Cisco Systems, Inc.
##
## SPA password file processing module
##
## Author: Kurt Grutzmacher <kgrutzma@cisco.com>
##--------------------------------------#
"""

from collections import defaultdict
import re, string
from gluon import current
import logging
from skaldship.log import log

# Module definitions
lowercase = set(string.lowercase)
uppercase = set(string.uppercase)
digits = set(string.digits)
specialchars = set("!@#$%^&*()_+-=`~[]\\{}|;':\",./<>? ")

has_lower = lambda s: bool( lowercase & set(s))
has_upper = lambda s: bool( uppercase & set(s))
has_digit = lambda s: bool( digits & set(s))
has_special = lambda s: bool( specialchars & set(s))

CHARSET_CHECKS = [
    ('lower', "Lowercase Alpha Characters (ex: password)",
        lambda pw: re.search(r"^[a-z]+$", pw)),
    ('digits', "Digits only (ex: 123456)",
        lambda pw: re.search(r"^[0-9]+$", pw)),
    ('upper', "Upppercase Alpha Characters (ex: PASSWORD)",
        lambda pw: re.search(r"^[A-Z]+$", pw)),
    ('nonalphanum', "Non-Alphanumeric Characters (ex: #$%^@!)",
        lambda pw: re.search(r"^[^a-zA-Z0-9]+$", pw)),
    ('lowerupperalpha', "Upper and Lowercase Alpha Characters (ex: PASSword)",
        lambda pw: (has_lower(pw) and has_upper(pw) and
                    not (has_digit(pw) or has_special(pw))) ),
    ('upperalphanum', "Uppercase Alphanumeric Characters (ex: PASS123)",
        lambda pw: (has_digit(pw) and has_upper(pw) and
                    not (has_lower(pw) or has_special(pw))) ),
    ('loweralphanum', "Lowercase Alphanumeric Characters (ex: pass123)",
        lambda pw: (has_digit(pw) and has_lower(pw) and
                    not (has_upper(pw) or has_special(pw))) ),
    ('lowerspecial', "Lowercase Alphanumeric with Special Chars (ex: pass!23)",
        lambda pw: (has_digit(pw) and not has_upper(pw) and has_lower(pw) and
                    has_special(pw)) ),
    ('upperspecial', "Uppercase Alphanumeric with Special Chars (ex: PASS!23)",
        lambda pw: (has_digit(pw) and has_upper(pw) and not has_lower(pw) and
                    has_special(pw)) ),
    ('lowerspecialonly', "Lowercase with Special Chars Only (ex: pass!@#)",
        lambda pw: (not has_digit(pw) and not has_upper(pw) and has_lower(pw) and
                    has_special(pw)) ),
    ('upperspecialonly', "Uppercase with Special Chars Only (ex: PASS!@#)",
        lambda pw: (not has_digit(pw) and has_upper(pw) and not has_lower(pw) and
                    has_special(pw)) ),
    ('uprlwralphanospecial', "Alphanumeric no Special Chars (ex: Pass123)",
        lambda pw: (has_lower(pw) and has_digit(pw) and has_upper(pw) and
                    not has_special(pw)) ),
    ('complexlwralphanodigit', "LowerAlpha + SpecialChars no digits (ex: Pass!23)",
        lambda pw: (has_lower(pw) and has_special(pw) and
                    not has_digit(pw) and not has_upper(pw)) ),
    ('complexuprlwralphanodigit', "UpperLowerAlpha + SpecialChars no digits (ex: PASS!@#)",
        lambda pw: (has_upper(pw) and has_lower(pw) and has_special(pw) and
                    not has_digit(pw)) ),
    ('complex', "Alphanumeric with Special Chars (ex: Pass!@#)",
        lambda pw: (has_digit(pw) and has_upper(pw) and has_lower(pw) and
                    has_special(pw)) ),
    ('other', "Something not matching", lambda pw: True),
]


##-------------------------------------------------------------------------

def password_class_stat(passwords):
    """Scans through the password, determining which character class
    it belongs to
    """
    for pw_rec in passwords:
        character_class = "Unknown"
        password = pw_rec.f_password
        if not password or password.lower() == "no password":
            pwlenstat = "blank"
        else:
            pwlenstat = len(password)
        for slug, text, fn in CHARSET_CHECKS:
            if password and fn(password):
                character_class = text
                break
        yield (pwlenstat, character_class, password)

##-------------------------------------------------------------------------

def lookup_hash(hash_data=None):
    """
    Looks up a hash in the database
    """
    if hash_data is None:
        return None

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    if len(hash_data) == 65 and hash_data[32] == ":":
        if hash_data.upper() == "AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0":
            # it's a blank password
            return ''

        # lm:nt combo.. split them out and lookup NTLM first
        # then if not found search the LM
        (lm, nt) = hash_data.split(':')

        query = ((db.t_accounts.f_hash2 == nt) | (db.t_accounts.f_hash2 == nt.upper())) & (db.t_accounts.f_password != None)
        row = db(query).select(db.t_accounts.f_password).first()
        if row is not None:
            # found an NTLM, return that otherwise build a LM lookup query
            return row.f_password
        if lm.upper() == "AAD3B435B51404EEAAD3B435B51404EE":
            # no ntlm found and lm is blank so it's unknown, return None
            return None
        query = ((db.t_accounts.f_hash1 == lm) | (db.t_accounts.f_hash1 == lm.upper())) & (db.t_accounts.f_password != None)
    else:
        query = ((db.t_accounts.f_hash1 == hash_data) | (db.t_accounts.f_hash1 == hash_data.upper())) & (db.t_accounts.f_password != None)

    row = db(query).select(db.t_accounts.f_password).first()
    if row is not None:
        return row.f_password

    return None

##-------------------------------------------------------------------------

def process_medusa(line):
    """
    Process a medusa line and return a dictionary:

    { 'ip'  : ip address
      'port': port info - can be port # or module name
      'user': username,
      'pass': password,
      'hash': ntlm hash if smbnt hash used
      'msg' : status message
    }
    """
    retval = {}

    try:
        data = line.split()
    except Exception, e:
        log("Error processing medusa line: %s -- %s" % (e, line), logging.ERROR)
        return retval

    if " ".join(data[:2]) == "ACCOUNT FOUND:":
        retval['port'] = data[2]
        retval['ip'] = data[4]
        retval['user'] = data[6]

        if retval['user'] == "Password:":
            # no username provided, adjust the field modulator cap'n
            retval['user'] = None
            retval['pass'] = data[7]
            retavl['msg'] = " ".join(data[9:])
        elif data[7] == "Password:" and data[8][0] == '[':
            # so this will break if the password starts with "[" however there's no
            # better way I can think of to detect a blank password w/o regex. Other
            # ideas are welcome! data[8] will be the response message which could be
            # [SUCCESS] or [ERROR ...] or something else..
            retval['pass'] = ""
            retval['msg'] = " ".join(data[8:])
        else:
            # Standard password and message location
            retval['pass'] = data[8]
            retval['msg'] = " ".join(data[9:])

        if len(retval['pass']) == 68 and retval['pass'][65:68] == ":::":
            # we have an ntlm hash cap'n
            retval['hash'] = ":".join(retval['pass'].split(':')[:2])
            retval['pass'] = lookup_hash(retval['hash'])
            retval['type'] = 'smb'
        else:
            retval['type'] = 'cleartext'

        if retval['msg'].startswith("[SUCCESS"):
            retval['error'] = False
        else:
            retval['error'] = True

    return retval

##-------------------------------------------------------------------------

def process_hydra(line):
    """
    Process a hydra line and return a dictionary:

    { 'ip'  : ip address
      'port': port info - can be port # or module name
      'user': username,
      'pass': password,
      'hash': ntlm hash if smbnt hash used
      'msg' : status message
    }
    """
    # line: [22][ssh] host: 1.1.1.1   login: username   password: pw1234
    retval = {}
    try:
        data = line.split()
    except Exception, e:
        log("Error processing hydra line: %s -- %s" % (e, line), logging.ERROR)
        return retval

    if data[1] == "host:":
        # these fields are always there.. sometimes password is not
        retval['port'] = data[0][1:data[0].find("]")]
        retval['ip'] = data[2]
        retval['user'] = data[4]

        if "password:" not in data:
            # no password provided, adjust the field modulator cap'n
            retval['pass'] = None
            if len(data) == 6:
                retval['msg'] = data[5]
        else:
            retval['pass'] = data[6]
            if len(data) == 8:
                retval['msg'] = data[7]

        # handle specific SMB errors:
        #if "[smb]" in data and "Error:" in data:

        if len(retval['pass']) == 68 and retval['pass'][65:68] == ":::":
            # we have an ntlm hash cap'n
            retval['hash'] = ":".join(retval['pass'].split(':')[:2])
            retval['pass'] = lookup_hash(retval['hash'])
            retval['type'] = 'smb'
        else:
            retval['type'] = 'cleartext'
            retval['hash'] = None

    retval['error'] = False
    return retval

##-------------------------------------------------------------------------

def process_msfcsv(line):
    """
    Process a metasploit creds output csv file and return a dictionary:
    { 'ip'  : ip address
      'port': port info - can be port # or module name
      'user': username,
      'pass': password,
      'hash': ntlm hash if smb_hash found
      'msg' : status message
    }
    """
    # host,port,user,pass,type,active?
    retval = {}
    hash_types = ['smb', 'rakp_hmac_sha1_hash', 'smb_challenge']
    import csv
    for data in csv.reader([line]):
        retval['ip'] = data[0]
        retval['port'] = data[1]
        retval['user'] = data[2]
        retval['pass'] = data[3]
        retval['type'] = data[4]
        retval['msg'] = 'from metasploit'
        # isactive = data[5] # unused

    #if len(retval['pass']) == 65 and retval['pass'].find(':') == 32:
    if retval['type'] in hash_types:
        # we have a hash cap'n
        retval['hash'] = retval['pass']
        retval['pass'] = lookup_hash(retval['hash'])
    else:
        retval['hash'] = None

    retval['error'] = False
    return retval

##-------------------------------------------------------------------------

def get_hashtype(pwhash):
    """
    Tries to figure out the type of hash
    """
    # man 3 crypt
    if pwhash[0:3] == "$1$":
        return "MD5"
    if pwhash[0:3] == "$2$" or pwhash[0:4] == "$2a$":
        return "Blowfish"
    if pwhash[0:3] == "$5$":
        return "SHA-256"
    if pwhash[0:3] == "$6$":
        return "SHA-512"
    else:
        return "DES"

##-------------------------------------------------------------------------

def crack_nt_hashes(hashes=[]):
    """
    Take a list of lm/nt hashes and run them through /opt/SPA/tools/jtr
    for simple wordlist, variation and the like. Should take less than
    2 minutes to process.
    TODO: crack_nt_hashes
    """

    return

##-------------------------------------------------------------------------

def insert_or_update_acct(svc_id=None, accounts={}):
    """
    Insert or updates account table in the database
    """

    if svc_id is None:
        return 'No Service ID record sent'

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    resp_text = "No accounts sent to update"
    accounts_added = []
    accounts_updated = []
    if db(db.t_services.id == svc_id).count() > 0:
        # we have a valid service, lets add/modify accounts!
        for username,acct_values in accounts.iteritems():
            # run through each account, if it already exists then check
            # to see if f_hash1 has value then don't overwrite it,
            # otherwise update the other fields
            acct_values['f_services_id'] = svc_id
            acct_values['f_username'] = username.strip('\r\n')
            if acct_values.get('f_password') is None:
                # no password has been set, lets search for the hash and copy the
                # cleartext over if it exists
                if acct_values.get('f_hash1_type') == "LM":
                    acct_values['f_password'] = lookup_hash("%s:%s" % (acct_values.get('f_hash1'), acct_values.get('f_hash2')))
                else:
                    acct_values['f_password'] = lookup_hash(acct_values.get('f_hash1'))

            q = (db.t_accounts.f_username == username) & (db.t_accounts.f_services_id == svc_id)
            acct_rec = db(q).select()
            if len(acct_rec) == 0:
                # add the record
                db.t_accounts.insert(**acct_values)
                accounts_added.append(username)
            else:
                # for existing records
                for rec in acct_rec:
                    if rec.f_hash1 is None or rec.f_hash1 == '':
                        # f_hash1 doesn't exist so update the record
                        db.t_accounts[rec.id] = acct_values
                        resp_text += "Updated %s<br/>" % (username)
                    elif rec.f_hash1 == acct_values['f_hash1']:
                        # f_hash1 exists and is the same so update everything else
                        acct_values.pop('f_hash1')
                        acct_values.pop('f_hash1_type')
                        if acct_values.has_key('f_hash2'):
                            # check for f_hash2
                            if rec.f_hash2 == acct_values['f_hash2']:
                                acct_values.pop('f_hash2')
                                acct_values.pop('f_hash2_type')
                        db.t_accounts[rec.id] = acct_values
                        accounts_updated.append(username)
                    else:
                        log("%s has a different hash1 value. Nothing done. (orig: %s) (pwfile: %s)" % (username, rec.f_hash1, acct_values['f_hash1']), logging.ERROR)
                db.commit()
            resp_text = "Accounts added: %s\nAccounts Updated: %s\n" % (" ".join(accounts_added), " ".join(accounts_updated))
    else:
        resp_text = 'Invalid Service ID sent'

    log(resp_text, logging.DEBUG)
    return resp_text

##-------------------------------------------------------------------------

def process_cracked_file(pw_file=None, file_type=None, message=""):
    """
    Process a file of cracked passwords and update the cleartext with
    the new results.
    """
    import fileinput

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    if pw_file is not None:
        try:
            fIN = fileinput.input(files=pw_file)
        except IOError, e:
            log("Error opening %s: %s" % (pw_file, e), logging.ERROR)
            return "Error opening %s: %s" % (pw_file, e)

    accounts = {}
    if file_type == "JTR PWDUMP":
        log("Processing JTR PWDUMP Result file...")
        for line in fIN:
            if line == "\n": continue
            if line.count(":") != 6: continue
            try:
                (username, password, lm, nt) = line.split(':')[0:4]
                accounts[nt] = password
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "JTR Shadow":
        pass

    elif file_type == "Hash:Password":
        for line in fIN:
            if line == "\n": continue
            if line.count(":") <= 0: continue
            try:
                line = line.strip('\n')
                (enchash, cleartext) = line.split(':', 1)
                accounts[enchash] = cleartext
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Password:Hash":
        for line in fIN:
            if line == "\n": continue
            if line.count(":") <= 0: continue
            try:
                line = line.strip('\n')
                (cleartext, enchash) = line.split(':', 1)
                accounts[enchash] = cleartext
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    else:
        return "Unknown file type sent"

    updated = 0
    for k,v in accounts.iteritems():
        query = (db.t_accounts.f_hash1 == k)|(db.t_accounts.f_hash2 == k)
        for row in db(query).select():
            row.update_record(f_password=v, f_compromised=True, f_message=message)
            updated += 1
            db.commit()
    return "%s accounts updated with passwords" % updated

##-------------------------------------------------------------------------

def process_password_file(pw_file=None, pw_data=None, file_type=None, source=None):
    """
    Process a password file and return a dictionary fit for t_accounts

    file_type values:

      ('PWDUMP', 'MSCa$h Dump', 'UNIX Passwd', 'UNIX Shadow', 'Medusa', 'Hydra', 'Username:Password', 'AccountDB')
    """
    import fileinput

    accounts = {}
    if pw_file is not None:
        try:
            pw_data = []
            for line in fileinput.input(files=pw_file):
                pw_data.append(line)
        except IOError, e:
            log("Error opening %s: %s" % (pw_file, e), logging.ERROR)
            return accounts

    if file_type == 'PWDUMP':
        log("Processing PWDUMP file")
        if source is None:
            source = "PWDUMP"
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                (username, uid, lm, nt) = line.split(':')[0:4]
                if uid == "500": level = "ADMIN"
                else: level = "USER"

                accounts[username] = { 'f_uid': uid, 'f_level': level, 'f_source': source,
                                       'f_hash1': lm, 'f_hash1_type': 'LM',
                                       'f_hash2': nt, 'f_hash2_type': 'NTLM' }
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "MSCa$h Dump":
        log("Processing MSCa$h file")
        if source is None:
            source = "MSCASH"
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                (username, pwhash, domain) = line.split(':')
                accounts[username] = { 'f_hash1': pwhash, 'f_hash1_type': 'MSCASH', 'f_domain': domain, 'f_source': source}
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "UNIX Passwd":
        log("Processing UNIX Passwd file")
        if source is None:
            source == "UNIX Passwd"
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                (username, pwhash, uid, gid, fullname) = line.split(':')[0:5]
                if uid == "0": level = "ADMIN"
                else: level = "USER"

                if len(pwhash) > 4:
                    hashtype = get_hashtype(pwhash)
                    accounts[username] = { 'f_uid': uid, 'f_gid': gid, 'f_level': level,
                                           'f_hash1': pwhash, 'f_hash1_type': hashtype,
                                           'f_fullname': fullname, 'f_source': source }
                else:
                    accounts[username] = { 'f_uid': uid, 'f_gid': gid, 'f_level': level,
                                           'f_fullname': fullname, 'f_source': source }

                log("Account -> %s" % (accounts[username]), logging.DEBUG)
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "UNIX Shadow":
        log("Processing UNIX Shadow file")
        if source is None:
            source = "UNIX Shadow"
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                (username, pwhash, last_changed, min_age, max_age, warning, inactivity, exp_date, reserved) = line.split(':')

                if len(pwhash) > 4:
                    hashtype = get_hashtype(pwhash)
                    accounts[username] = { 'f_hash1': pwhash, 'f_hash1_type': hashtype, 'f_source': source }
                else:
                    accounts[username] = { 'f_source': source }

            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Username:Password":
        log("Processing Username:Password file")
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                (username, password) = line.split(':')[0:2]
                if source is None:
                    source = "Username:Password"
                accounts[username] = { 'f_password': password.strip("\n"), 'f_source': source, 'f_compromised': True  }
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Usernames":
        log("Processing Usernames only file")
        for line in pw_data:
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            accounts[line.strip("\n")] = { 'f_compromised': False }

    elif file_type == "Medusa":
        log("Processing Medusa output file")
        if source is None:
            source = "Medusa"
        for line in pw_data:
            if line[0] == "#": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                pw_data = process_medusa(line)
                # return { 'ip': ip, 'port': port, 'user': user, 'pass': pw, 'hash': ntlm, 'msg': msg }
                if pw_data.get('hash', None):
                    # we have an ntlm hash, split that instead of updating the password
                    (lm, nt) = pw_data['hash'].split(':')[0:2]
                    accounts[pw_data['user']] = { 'f_hash1': lm, 'f_hash1_type': 'LM',
                                                   'f_hash2': nt, 'f_hash2_type': 'NT', 'f_password': pw_data['pass'],
                                                   'f_description': pw_data['msg'], 'f_source': source, 'f_compromised': True }
                else:
                    accounts[pw_data['user']] = { 'f_password': pw_data['pass'],
                                                   'f_message': pw_data['msg'], 'f_source': source, 'f_compromised': True }
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Hydra":
        log("Processing Hydra output file")
        if source is None:
            source = "Hydra"
        for line in pw_data:
            if line[0] == "#": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                pw_data = process_hydra(line)
                if pw_data.has_key('hash'):
                    # we have an ntlm hash, split that instead of updating the password
                    (lm, nt) = pw_data['hash'].split(':')[0:2]
                    accounts[pw_data['user']] = { 'f_hash1': lm, 'f_hash1_type': 'LM',
                                                   'f_hash2': nt, 'f_hash2_type': 'NT',
                                                   'f_description': pw_data['msg'], 'f_source': source, 'f_compromised': True }
                else:
                    accounts[pw_data['user']] = { 'f_password': pw_data['pass'],
                                                   'f_message': pw_data['msg'], 'f_source': source, 'f_compromised': True }
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Metasploit Creds CSV":
        log("Processing Metasploit Creds CSV output file")
        if source is None:
            source = "Metasploit"
        for line in pw_data:
            if line[0] != '"': continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                pw_data = process_msfcsv(line)
                if pw_data['type'] == 'smb':
                    # we have an ntlm hash, split that instead of updating the password
                    (lm, nt) = pw_data['hash'].split(':')[0:2]
                    accounts[pw_data['user']] = {
                        'f_hash1': lm, 'f_hash1_type': 'LM', 'f_hash2': nt, 'f_hash2_type': 'NT',
                        'f_message': pw_data['msg'], 'f_source': source, 'f_compromised': True
                    }
                else:
                    if pw_data['pass']:
                        compromised = True
                    else:
                        compromised = False
                    accounts[pw_data['user']] = {
                        'f_password': pw_data['pass'], 'f_hash1': pw_data['hash'], 'f_hash1_type': pw_data['type'],
                        'f_message': pw_data['msg'], 'f_source': source, 'f_compromised': compromised,
                    }
            except Exception, e:
                log("Error with line (%s): %s" % (line, e), logging.ERROR)

    elif file_type == "Username Only":
        log("Processing Username only output file")
        if source is None:
            source = "Username list"
        for line in pw_data:
            if line[0] == "#": continue
            if line == "\n": continue
            line = line.replace('\n', '')   # remove any and all carriage returns!
            try:
                username = line.split(" ")[0]
                accounts[username] = { 'f_source': source }
            except:
                continue

    elif file_type == "AccountDB":
        log("Processing AccountDB output file")
        if source is None:
            source = "AccountDB"
        from StringIO import StringIO
        import csv
        for line in csv.reader(StringIO(''.join(pw_data))):
            line = line.replace('\n', '')   # remove any and all carriage returns!
            if len(line) == 10:
                IP, Port, User, Password, uid, gid, level, status, fullname, Comment = line
            else:
                log("Line length != 10, skipping", logging.ERROR)
                continue
            if status == "DISABLED":
                status=False
            else:
                status=True
            if Password is not "":
                compromised=True
            else:
                compromised=False
            accounts[User] = {
                'f_password': Password,
                'f_uid': uid,
                'f_gid': gid,
                'f_level': level,
                'f_compromised': compromised,
                'f_active': status,
                'f_fullname': fullname,
                'f_description': Comment,
            }

    else:
        log("Unknown file type provided: %s" % file_type, logging.ERROR)

    log(accounts, logging.DEBUG)
    return accounts

##-------------------------------------------------------------------------

def process_mass_password(pw_file=None, pw_type=None, message=None, proto=None, portnum=None, add_hosts=False, user_id=1):
    """
    Process a medusa/hydra mass password run
    """
    import fileinput

    db = current.globalenv['db']
    cache = current.globalenv['cache']

    added = 0
    updated = 0
    new_hosts = 0
    ip_dict = {}
    if pw_file is not None:
        try:
            fIN = fileinput.input(files=pw_file)
        except IOError, e:
            log("Error opening %s: %s" % (pw_file, e), logging.ERROR)
            return "Error opening %s: %s" % (pw_file, e)
    else:
        return "No filename provided.. that's odd"

    if pw_type is None:
        return "No file type provided.. that's odder"

    if message is None:
        message = pw_type
    for line in fIN:
        if line[0] == "#": continue
        line = line.replace('\n', '')
        try:
            if pw_type == "Medusa":
                mass_pw_data = process_medusa(line)
            elif pw_type == "Hydra":
                mass_pw_data = process_hydra(line)
            elif pw_type == "Metasploit Creds CSV":
                mass_pw_data = process_msfcsv(line)
            else:
                mass_pw_data = {}
                mass_pw_data['error'] = 'Invalid password file type provided'
        except Exception, e:
            log("Error with line (%s): %s" % (line, e), logging.ERROR)
            continue

        if not mass_pw_data.get('error'):
            # return { 'ip': ip, 'port': port, 'user': user, 'pass': pw, 'hash': ntlm, 'msg': msg }
            ip = mass_pw_data.get('ip')
            ip_accts = ip_dict.setdefault(ip, list())
            if mass_pw_data.get('type') == 'smb':
                # we have an ntlm hash, split that instead of updating the password
                (lm, nt) = mass_pw_data['hash'].split(':')[0:2]
                ip_accts.append({
                    'f_username': mass_pw_data.get('user'),
                    'f_hash1': lm, 'f_hash1_type': 'LM',
                    'f_hash2': nt, 'f_hash2_type': 'NT',
                    'f_number': portnum, 'f_proto': proto,
                    'f_password': mass_pw_data.get('pass'),
                    'f_message': mass_pw_data.get('msg'),
                    'f_source': message, 'f_compromised': True
                })
                ip_dict[ip] = ip_accts
            elif mass_pw_data.get('hash'):
                # we have a hash, not a password
                if mass_pw_data['pass']:
                    compromised = True
                else:
                    compromised = False
                ip_accts.append({
                    'f_number': portnum, 'f_proto': proto,
                    'f_username': mass_pw_data.get('user'),
                    'f_password': mass_pw_data.get('pass'),
                    'f_hash1': mass_pw_data.get('hash'),
                    'f_hash1_type': mass_pw_data.get('type'),
                    'f_message': mass_pw_data.get('msg'),
                    'f_source': message, 'f_compromised': compromised,
                })
                ip_dict[ip] = ip_accts
            else:
                # otherwise append the relevant information
                ip_accts.append({
                    'f_number': portnum, 'f_proto': proto,
                    'f_username': mass_pw_data.get('user'),
                    'f_password': mass_pw_data.get('pass'),
                    'f_message': mass_pw_data.get('msg'),
                    'f_source': message, 'f_compromised': True
                })
                ip_dict[ip] = ip_accts

    # run through the ip_accts now to add/update them to the database
    from skaldship.hosts import get_host_record
    for k,v in ip_dict.iteritems():
        for ip_acct in v:
            # build a query to find the service for this host/port combo
            query = (db.t_hosts.f_ipv4 == k) & (db.t_services.f_hosts_id == db.t_hosts.id)
            query &= (db.t_services.f_proto==ip_acct['f_proto']) & (db.t_services.f_number==ip_acct['f_number'])
            svc = db(query).select(db.t_services.id, cache=(cache.ram, 60)).first()
            if svc is None:
                # no service found, get the host record based on the IP
                host_rec = get_host_record(k)
                if host_rec is None and add_hosts:
                    # add host to the database, unfortunately all we know is the IP address so it's pretty bare.
                    # assign it to the current user and asset group of "new_hosts_medusa"
                    fields = {
                        'f_ipv4': k,
                        'f_engineer': user_id,
                        'f_asset_group': 'new_hosts_medusa',
                    }
                    host_rec = db.t_hosts.insert(**fields)
                    db.commit()
                    log("Added new host from Medusa output: %s" % k)
                    new_hosts += 1
                elif host_rec is None:
                    # no host and not asking to add hosts so print message and continue
                    log("Unable to find host_rec for %s" % k, logging.ERROR)
                    continue

                # add the new service to the host_rec
                fields = {
                    'f_hosts_id': host_rec.id,
                    'f_proto': ip_acct['f_proto'],
                    'f_number': ip_acct['f_number'],
                }
                svc_id = db.t_services.insert(**fields)
                db.commit()
                log("Added new service (%s/%s) to host %s" % (ip_acct['f_proto'], ip_acct['f_number'], k))
            else:
                svc_id = svc.id

            # lookup the password from the lm/nt hash fields (if they exist)
            if ip_acct.has_key('f_hash1'):
                ip_acct['f_password'] = lookup_hash("%s:%s" % (ip_acct.get('f_hash1'), ip_acct.get('f_hash2')))

            # remove f_proto and f_number since they're not in t_accounts, add service id
            ip_acct.pop('f_proto')
            ip_acct.pop('f_number')
            ip_acct.update({'f_services_id': svc_id})
            query = (db.t_accounts.f_services_id == svc_id)&(db.t_accounts.f_username == ip_acct['f_username'])
            row = db(query).select().first()
            if row:
                row.update_record(**ip_acct)
                updated += 1
            else:
                db.t_accounts.insert(**ip_acct)
                added += 1
            db.commit()
    return "Completed: %s/Added, %s/Updated, %s/New Hosts" % (added, updated, new_hosts)


def _doctest():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _doctest()
