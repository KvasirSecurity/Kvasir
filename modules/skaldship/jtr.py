#!/usr/bin/env python

"""
JohnTheRipper classes/functions

JohnPot

ntpwchk - Finds the correct case of a password given a word and NT hash
using case permutations.
"""

__author__ =   "Kurt Grutzmacher <kgrutzma@cisco.com>"
__date__ =     "05/17/2012"
__revision__ = "1.11"

import sys, os
import fileinput, re
import logging
logger = logging.getLogger("web2py.app.kvasir")

###

class JohnPot:
    def __init__(self):
        self.potdata = {}
        self.win_hash_regex = re.compile("^(\$NT\$|\$LM\$|M\$\w+#)")
    def upper_windows(self, pwhash):
        # upper case windows hashes
        if pwhash.startswith("M$"):
            # upper case DCC hashes
            try:
                h1, h2 = pwhash.split("#")
            except Exception:
                raise Exception("Bad M$ line: ", pwhash)
            pwhash = "%s#%s" % (h1, h2.upper())
        else:
            # upper case LM/NT hashes
            pwhash = pwhash.upper()
        return pwhash
    def load(self, potfile):
        for p in fileinput.input(potfile):
            # find the first location of a colon separator
            loc = p.find(':')
            if loc > 0:
                # the password hash goes up to the first colon
                pwhash = p[0:loc]
                # the password is everything after the colon
                pw = p[loc+1:].strip('\n')
                if self.win_hash_regex.match(pwhash):
                    pwhash = self.upper_windows(pwhash)
                self.potdata[pwhash] = pw
            else:
                logging.error("Invalid line: ", p)
                continue
        logging.info("Loaded %s hashes" % (len(self.potdata)))
    def get(self, k):
        return self.potdata.get(k)
    def search(self, k):
        # auto upper LM, NT and DCC hashes:
        k = k.strip('\n')
        if self.win_hash_regex.match(k):
            k = self.upper_windows(k)
        if self.potdata.has_key(k):
            # key as-is
            return self.potdata[k]
        if self.potdata.has_key(k.upper()):
            # upper case
            return self.potdata[k.upper()]
        if self.potdata.has_key(k.lower()):
            # lower case
            return self.potdata[k.lower()]
        else:
            # key not found!
            return None

########
def ntpwchk(password, lmhash, nthash):
    """Performs mutation on a cleartext to find it in NT"""
    try:
        import smbpasswd
    except ImportError:
        raise Exception("Requires smbpasswd module. Please install it")

    def generate_perm(word, val):
        for i in range(0,len(word)):
            if (val & 1 << i):
                word = word[:i] + word[i].upper() + word[i+1:]
        return word

    #----------------------------------------------------------------------
    def permutations(word):
        val = 0
        perms = []
        word = word.lower()
        while (val < (1 << len(word))):
            perms.append(generate_perm(word,val))
            val += 1
        return perms

    permutations = permutations(password)

    for mutation in permutations:
        if nthash.upper() == smbpasswd.nthash(mutation):
            return (True, mutation.strip('\n'))

    return (False, None)
