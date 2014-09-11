#!/usr/bin/env python
#coding:utf-8
"""
Metasploit integration library utilizing msgpack

Author:  Kurt Grutzmacher -- <grutz@jingojango.net>
Created: 03/25/10
Modified: 09/09/14
"""

import os
import sys
import logging
import httplib
try:
    import msgpack
except ImportError, e:
    raise Exception("Install 'msgpack' library: 'pip install msgpack-python'")
logger = logging.getLogger("web2py.app.kvasir")


########################################################################
class MSFProAPIError(Exception):
    pass

########################################################################
class MetasploitProAPI:
    """
    Connects to the Metasploit Pro library via msgpack
    """

    def __init__(self, host="localhost:3790", ssl=True, apikey=None, username=None, password=None):
        self.log = logging.getLogger(self.__class__.__name__)
        self.username = username
        self.password = password
        self.apikey = apikey
        self.ssl = ssl
        if host.startswith('http'):
            from urlparse import urlsplit
            (self.host, self.port) = urlsplit(host)[1].split(':')
        else:
            (self.host, self.port) = host.split(':')
        self.port = int(self.port)
        self.debug = False
        self.libraryversion = "1.0"
        self.apiurl = "/api/%s" % (self.libraryversion)
        self.connected = False

    #-----------------------------------------------------------------#
    def build_command(self, command=[], *opts):
        """Builds an API command w/ msgpack, appends the API key and
        any options"""
        if type(command) is not type(list()):
            command = [command]
        if self.apikey:
            command.append(self.apikey)
        for k in opts:
            command.append(k)
        return msgpack.packb(command)

    #-----------------------------------------------------------------#
    def send(self, message=None):
        """Sends a message to Metasploit API and unpacks the response"""
        headers = {"Content-type" : "binary/message-pack"}

        if self.ssl:
            httpclient = httplib.HTTPSConnection(self.host, self.port)
        else:
            httpclient = httplib.HTTPConnection(self.host, self.port)
        try:
            httpclient.request("POST", self.apiurl, message, headers)
        except Exception, e:
            raise MSFProAPIError("HTTP Client error:", e)

        response = httpclient.getresponse()
        if response.status == 200:
            try:
                res = msgpack.unpackb(response.read())
            except Exception, e:
                raise MSFProAPIError("Unable to process response:", e)
            if res.get('error') is True:
                raise MSFProAPIError("API Error:", res['error_string'])
        else:
            raise MSFProAPIError("HTTP Error from MSF:", response.status)
        return res

    #-----------------------------------------------------------------#
    def login(self, host="localhost:3790", ssl=True, apikey=None, username=None, password=None):
        """Perform session setup, sending username/password if defined or
        validating API key. Sets self.connected to True when successfull"""

        self.connected = False

        if self.username:
            self.log.debug("Authenticating with username/password")
            self.apikey = None
            message = self.build_command(['auth.login', self.user, self.password])
            res = self.send(message)
            if res['result'] == 'success':
                self.apikey = res['token']
                self.connected = True
            else:
                self.log.error("Authentication failed!")
                self.connected = False

        elif self.apikey:
            # checking to be sure API key is valid
            self.log.debug("Obtaining Metasploit version and statistics")
            resp = self.version()
            if resp.has_key('version'):
                self.log.info("Server v%s, API %s, Ruby v%s" % (resp['version'], resp['api'], resp['ruby']))
                self.connected = True
            else:
                self.connected = False

        else:
            self.connected = False

        return self.connected

    #-----------------------------------------------------------------#
    def close(self):
        """Closes the connection"""
        self.connected = False

    ###################################################################
    # Metasploit core commands
    #-----------------------------------------------------------------#
    def version(self):
        """Obtain the Metasploit Framework version"""
        self.log.debug("Sending version request")
        message = self.build_command(['core.version'])
        return self.send(message)

    #-----------------------------------------------------------------#
    def add_module_path(self, mod_path=""):
        """Add a local file path to module search list"""
        self.log.debug("Adding %s to module path" % mod_path)
        message = self.build_command(['core.add_module_path'], mod_path)
        return self.send(message)

    #-----------------------------------------------------------------#
    def save(self):
        """Saves the global datastore configuration to disk"""
        self.log.debug("Saving the global datastore to disk")
        message = self.build_command(['core.save'])
        return self.send(message)

    ###################################################################
    # Metasploit Module commands
    #-----------------------------------------------------------------#
    def module_stats(self):
        """Obtain the module counts"""
        self.log.debug("Sending stats request")
        message = self.build_command(['core.module_stats'])
        return self.send(message)

    #-----------------------------------------------------------------#
    def reload_modules(self):
        """Reloads modules"""
        self.log.debug("Reloading modules")
        message = self.build_command(['core.reload_modules'])
        return self.send(message)

    #-----------------------------------------------------------------#
    def module_list(self, modtype="exploits"):
        """Obtain a list of Metasploit Framework modules

        Modtype can be: exploits, auxiliary, payloads, encoders, nops
        """
        self.log.debug("Sending module.%s request" % (modtype))
        message = self.build_command(["module.%s" % (modtype)])
        return self.send(message)

    #-----------------------------------------------------------------#
    def module_info(self, modtype="", module=""):
        """Obtain info on a specific module"""

        if modtype.lower() not in ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]:
            self.log.debug("Invalid module type")
            return

        message = self.build_command(["module.info"], modtype, module)
        return self.send(message)

    #-----------------------------------------------------------------#
    def module_options(self, modtype="", module=""):
        """Obtain options on a specific module"""

        if modtype.lower() not in ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]:
            self.log.debug("Invalid module type")
            return

        message = self.build_command(["module.options"], modtype, module)
        return self.send(message)

    #-----------------------------------------------------------------#
    def compatible_payloads(self, module=""):
        """Obtain compatible payloads for a specific module"""

        message = self.build_command(["module.compatible_payloads"], module)
        return self.send(message)

    #-----------------------------------------------------------------#
    def target_compatible_payloads(self, module="", target=1):
        """Obtain compatible payloads for a specific module and target"""

        message = self.build_command(["module.target.compatible_payloads"], module, target)
        return self.send(message)

    #-----------------------------------------------------------------#
    def compatible_sessions(self, module=""):
        """Obtain compatible sessions for a specific module"""

        message = self.build_command(["module.compatible_sessions"], module)
        return self.send(message)

    #-----------------------------------------------------------------#
    def module_execute(self, modtype="", module="", options={}):
        """Execute a specific module"""

        if module == "":
            self.log.debug("[module_execute] No module specified")
            return
        if modtype.lower() not in ["exploit", "auxiliary", "post"]:
            self.log.debug("[module_execute] Invalid module type specified")
            return

        message = self.build_command(["module.execute"], modtype, module, options)
        return self.send(message)

    ###################################################################
    # Metasploit Jobs, Sessions and Meterpreter
    #-----------------------------------------------------------------#
    def job_list(self):
        """Returns a list of running jobs and job names"""

        message = self.build_command(["job.list"])
        return self.send(message)

    #-----------------------------------------------------------------#
    def job_stop(self, jobid=""):
        """Kill a specific job by ID"""

        message = self.build_command(["job.kill"], jobid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def session_list(self):
        """Returns a list of running jobs and job names"""

        message = self.build_command(["session.list"])
        return self.send(message)

    #-----------------------------------------------------------------#
    def session_stop(self, jobid=""):
        """Kill a specific job by ID"""

        message = self.build_command(["session.kill"], jobid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def shell_read(self, sessionid="", readptr=0):
        """Read any pending output from a 'shell' session"""

        message = self.build_command(["session.shell_read"], sessionid, readptr)
        return self.send(message)

    #-----------------------------------------------------------------#
    def shell_write(self, sessionid="", data=None):
        """Write data to a 'shell' session"""

        message = self.build_command(["session.shell_write"], data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_read(self, sessionid=""):
        """Read any pending output from a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_read"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_write(self, sessionid="", data=None):
        """Write data to a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_write"], data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_run_single(self, sessionid="", data=None):
        """Run a command in a 'Meterpreter' session, no matter who is interacting with it"""

        message = self.build_command(["session.meterpreter_run_single"], sessionid, data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_script(self, sessionid="", data=None):
        """Run a script on a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_script"], data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_session_detach(self, sessionid=""):
        """Detatch a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_session_detach"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_session_kill(self, sessionid=""):
        """Terminates a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_session_kill"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def meterpreter_tabs(self, sessionid="", data=None):
        """Emulates pressing tab from a 'Meterpreter' session"""

        message = self.build_command(["session.meterpreter_tabs"], data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def compatible_modules(self, sessionid=""):
        """Lists compatbile post modules for a session"""

        message = self.build_command(["session.compatible_modules"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def shell_upgrade(self, sessionid="", host=None, port=4444):
        """Attempts to upgrade a shell to Meterpreter, expects multi/handler
        to be running on {host} and {port}"""

        message = self.build_command(["session.shell_upgrade"], sessionid, host, port)
        return self.send(message)

    #-----------------------------------------------------------------#
    def ring_clear(self, sessionid=""):
        """Wipes ring buffer from sessionid"""

        message = self.build_command(["session.ring_clear"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def ring_last(self, sessionid=""):
        """Returns last issued read pointer for a session"""

        message = self.build_command(["session.ring_last"], sessionid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def ring_put(self, sessionid="", data=""):
        """Same as shell_write"""

        message = self.build_command(["session.ring_put"], sessionid, data)
        return self.send(message)

    #-----------------------------------------------------------------#
    def ring_read(self, sessionid="", readptr=0):
        """Same as shell_read"""

        message = self.build_command(["session.ring_read"], sessionid, readptr)
        return self.send(message)

    ###################################################################
    # Metasploit Pro Basic features
    #-----------------------------------------------------------------#
    def pro_about(self):
        """Whatdisabout?"""

        message = self.build_command(["pro.about"])
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_workspaces(self):
        """List active workspaces"""

        message = self.build_command(["pro.workspaces"])
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_workspace_add(self, options={}):
        """Adds a workspace"""

        message = self.build_command(["pro.workspaces_add"], options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_workspace_del(self, workspace=None):
        """Deletes a workspace"""

        message = self.build_command(["pro.workspaces_del"], workspace)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_users(self):
        """List users"""

        message = self.build_command(["pro.users"])
        return self.send(message)

    #-----------------------------------------------------------------#
    # Metasploit Pro Import features
    #-----------------------------------------------------------------#
    def pro_import_data(self, workspace=None, data=None, options={}):
        """Import raw data into MSF"""

        # data should be a string, join it!
        if isinstance(data, list):
            data = ''.join(data)

        message = self.build_command(["pro.import_data"], workspace, data, options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_import_file(self, workspace=None, filename=None, options={}):
        """Import local file into MSF (local to MSF)"""

        message = self.build_command(["pro.import_file"], workspace, filename, options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_start_import(self, options={}):
        """Starts the Import action within Metasploit Pro"""
        message = self.build_command(["pro.start_import"], options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_validate_import_file(self, filename=None):
        """Validates a local file may be imported to MSF"""

        message = self.build_command(["pro.validate_import_file("], filename)
        return self.send(message)

    #-----------------------------------------------------------------#
    def pro_start_import_creds(self, options={}):
        """Import credentials such as users, passwords, hashes, and keys"""

        message = self.build_command(["pro.start_import_creds"], options)
        return self.send(message)

    ###################################################################
    # Metasploit Pro Report features
    #-----------------------------------------------------------------#
    def start_report(self, options={}):
        """Generates report/exportfunctons"""

        message = self.build_command(["pro.start_report"], options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def report_list(self, workspace=None):
        """Lists reports"""

        message = self.build_command(["pro.report_list"], workspace)
        return self.send(message)

    #-----------------------------------------------------------------#
    def report_download(self, rptid=0):
        """Downloads a specific report"""

        message = self.build_command(["pro.report_download"], rptid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def report_download_by_task(self, taskid=0):
        """Downloads a report based upon a task ID"""

        message = self.build_command(["pro.report_download_by_task"], taskid)
        return self.send(message)

    ###################################################################
    # Metasploit Pro Task features
    #-----------------------------------------------------------------#
    def task_list(self):
        """Lists active tasks"""

        message = self.build_command(["pro.task_list"])
        return self.send(message)

    #-----------------------------------------------------------------#
    def task_status(self, task=None):
        """Current status of a task"""

        message = self.build_command(["pro.task_status"], task)
        return self.send(message)

    #-----------------------------------------------------------------#
    def task_stop(self, task=None):
        """Stops a task"""

        message = self.build_command(["pro.task_stop"], task)
        return self.send(message)

    #-----------------------------------------------------------------#
    def task_log(self, task=None):
        """Returns status and log data for a task"""

        message = self.build_command(["pro.task_log"], task)
        return self.send(message)

    #-----------------------------------------------------------------#
    def task_delete_log(self, task=None):
        """Deletes a log data for a task"""

        message = self.build_command(["pro.task_delete_log"], task)
        return self.send(message)

    ###################################################################
    # Metasploit Pro Exploit features
    #-----------------------------------------------------------------#
    def start_import_creds(self, options={}):
        """Imports credentials from a file"""

        message = self.build_command(["pro.start_import_creds"], options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def start_bruteforce(self, options={}):
        """Starts a bruteforce task"""

        message = self.build_command(["pro.start_bruteforce"], options)
        return self.send(message)

    #-----------------------------------------------------------------#
    def start_exploit(self, options={}):
        """Starts an exploit task"""

        message = self.build_command(["pro.start_exploit"], options)
        return self.send(message)

    ###################################################################
    # Metasploit Pro Loot features
    #-----------------------------------------------------------------#
    def loot_list(self, workspace=None):
        """Lists the loot for a workspace"""

        message = self.build_command(["pro.loot_list"], workspace)
        return self.send(message)

    #-----------------------------------------------------------------#
    def loot_download(self, lootid=0):
        """Downloads a loot from an identifier"""

        message = self.build_command(["pro.loot_download"], lootid)
        return self.send(message)

    #-----------------------------------------------------------------#
    def debugmsg(self, message):
        """Simple debug message output"""
        from pprint import pprint
        if self.debug:
            pprint(message)

#----------------------------------------------------------------------
def listallmodules(msf):
    """Function to list all the modules"""

    from pprint import pprint

    payloads = msf.payloads()
    print "All Paylods:"
    for m in payloads:
        pprint("%s: %s" % (m, payloads[m]))

    exploits = msf.module_list("exploits")
    for f in exploits:
        print "Exploit name: %s" % (f)
        modinfo = msf.module_info("exploits", f)
        print "Module Info:"
        for m in modinfo:
            print("%s: %s" % (m, modinfo[m]))
        modopts = msf.module_options("exploits", f)
        print "Module Options:"
        for m in modopts:
            print("%s: %s" % (m, modopts[m]))

    auxiliary = msf.module_list("auxiliary")
    for f in auxiliary:
        print "Auxiliary name: %s" % (f)
        modinfo = msf.module_info("auxiliary", f)
        for m in modinfo:
            print("%s: %s" % (m, modinfo[m]))
        modopts = msf.module_options("exploits", f)
        print "Module Options:"
        for m in modopts:
            print("%s: %s" % (m, modinfo[m]))

#----------------------------------------------------------------------

def import_xml_report(filename=None):
    """
    Process a MSF Pro XML report
    """
    return

#----------------------------------------------------------------------
def login(options):
    """"
    Login!
    """

    msf = MetasploitProAPI( options.username, options.password, options.server, options.ssl )

    print "-" * 75
    print "Metasploit Pro API v%s" % (msf.libraryversion)

    if options.ssl:
        msf.ssl = True
    else:
        msf.ssl = False

    if not msf.connect():
        print "[main] Unable to continue, not connected!"
        sys.exit(1)

    print "Connected to Metasploit Pro version %s" % (msf.version())
    print "-" * 75

    return msf

#----------------------------------------------------------------------
if __name__=='__main__':
    from optparse import OptionParser

    # set up commandline arguments
    Progname=os.path.basename(sys.argv[0])
    Usage="%prog usage: XXX:[command_line_args]\n" \
         "%prog usage: -h\n" \
         "%prog usage: -V"
    optparser = OptionParser(usage=Usage, version="%prog: $Id:$" )
    optparser.add_option("-d", "--debug", dest = "debug", action="store_true", help="Debugging messages")
    optparser.add_option("-v", "--verbose", dest = "verbose", action="store_true", help="Verbose messages")
    optparser.add_option("-u", "--username", dest = "username", action="store", default=None, help="Username")
    optparser.add_option("-p", "--password", dest = "password", action="store", default=None, help="Password")
    optparser.add_option("-k", "--apikey", dest = "apikey", action="store", default=None, help="API Key")
    optparser.add_option("-s", "--server", dest = "server", action="store", default="127.0.0.1:3790", help="Server address:port")
    optparser.add_option("-S", "--SSL", dest = "ssl", action="store_true", default=True, help="Use SSL encryption")
    optparser.add_option("-i", "--interactive", dest = "interactive", action="store_true", default=False, help="Go Interactive")
    optparser.add_option("-b", "--bpython", dest = "bpython", action="store_true", default=False, help="Use Bpython")

    (options, params) = optparser.parse_args()

    root_log = logging.getLogger()
    if options.debug:
        root_log.setLevel(logging.DEBUG)
    elif options.verbose:
        root_log.setLevel(logging.INFO)
    else:
        root_log.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    logformat = "%(name)s: %(levelname)s: %(message)s"
    handler.setFormatter(logging.Formatter(logformat))
    root_log.addHandler(handler)
    log = logging.getLogger(Progname)

    msf = MetasploitProAPI(host=options.server, ssl=options.ssl, apikey=options.apikey, username=options.username, password=options.password)
    msf.login()

    if options.interactive or options.bpython:
        log.info("Attempting to go interactive...")
        if options.bpython:
            try:
                import bpython
                bpython.embed(locals_={'msf':msf}, banner="\nWelcome to MetasploitProAPI, use the variable 'msf'\n")
            except:
                log.warning('import bpython error; trying ipython...')
        else:
            try:
                import IPython
                if IPython.__version__ >= '0.11':
                    from IPython.frontend.terminal.embed import InteractiveShellEmbed
                    shell = InteractiveShellEmbed(user_ns={'msf':msf})
                    shell()
                else:
                    shell = IPython.Shell.IPShell(argv=[],user_ns={'msf':msf})
                    shell.mainloop()
            except:
                log.warning("Unable to go interactive")
        sys.exit(0)

    if msf:
        listallmodules(msf)
