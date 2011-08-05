'''
Created on Jul 30, 2011

Class AuthXMLRPCServerTLS based on the following mraposa code:  
http://blogs.blumetech.com/blumetechs-tech-blog/2011/06/python-xmlrpc-server-with-ssl-and-authentication.html

@author: marius
'''

import socket
import SocketServer
import ssl
from xmlrpclib import Binary
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler
from base64 import b64decode
import os
import sqlite3
import logging
from datetime import datetime
from zlib import adler32
import sys

from deltaindustries import Hashes, Deltas

try:
    import fcntl
except ImportError:
    fcntl = None

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class AuthXMLRPCServerTLS(SimpleXMLRPCServer):
    def __init__(self, addr, userauth = None, requestHandler=RequestHandler,
            keyfile=None, certfile=None, logRequests=True, allow_none=False, 
            encoding=None, bind_and_activate=True):
        """Overriding __init__ method of the SimpleXMLRPCServer

        The method is an exact copy, except the TCPServer __init__
        call, which is rewritten using TLS
        """
        self.logRequests = logRequests
        self.userauth = userauth        

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)

        """This is the modified part. Original code was:

            socketserver.TCPServer.__init__(self, addr, requestHandler, bind_and_activate)

        which executed:

            def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
                BaseServer.__init__(self, server_address, RequestHandlerClass)
                self.socket = socket.socket(self.address_family,
                                            self.socket_type)
                if bind_and_activate:
                    self.server_bind()
                    self.server_activate()

        """
        class VerifyingRequestHandler(SimpleXMLRPCRequestHandler):
            '''
            Request Handler that verifies username and password passed to
            XML RPC server in HTTP URL sent by client.
            '''
            # this is the method we must override
            def parse_request(self):
                # first, call the original implementation which returns
                # True if all OK so far
                if SimpleXMLRPCRequestHandler.parse_request(self):
                    # next we authenticate
                    if self.authenticate(self.headers):
                        return True
                    else:
                        # if authentication fails, tell the client
                        self.send_error(401, 'Authentication failed')
                return False
           
            def authenticate(myself, headers):
                
                #    Confirm that Authorization header is set to Basic
                try:
                    authheader = headers.get('Authorization')
                    if not authheader:
                        # Connection without authentication
                        self.username = None
                        return True
                    
                    (basic, _, encoded) = authheader.partition(' ')
                    assert basic == 'Basic', 'Only basic authentication supported'
               
                    #    Encoded portion of the header is a string
                    #    Need to convert to bytestring
                    encodedByteString = encoded.encode()
                    #    Decode Base64 byte String to a decoded Byte String
                    decodedBytes = b64decode(encodedByteString)
                    #    Convert from byte string to a regular String
                    decodedString = decodedBytes.decode()
                    #    Get the username and password from the string
                    (username, _, password) = decodedString.partition(':')
                    
                    #    Check that username and password are ok
                    #Caution! This self is the AuthXMLRPCServerTLS, not `myself'
                    #(being myself the VerifyingRequestHandler instance)
                    self.username = None 
                    if self.userauth:
                        if self.userauth.UserOk(username,password):
                            self.username = username
                            return True
                        else:
                            return False
                    else:
                        # No user authentication method, 
                        # this may be a security hole
                        return True
                except:
                    pass # Error in headers, ignore it and assume a 401
                return False
       
        #    Override the normal socket methods with an SSL socket
        SocketServer.BaseServer.__init__(self, addr, VerifyingRequestHandler)
        
        if not os.path.isfile(keyfile):
            print "Keyfile", keyfile, "does not exist"
            exit(-55)
        
        if not os.path.isfile(certfile):
            print "Certfile", certfile, "does not exist"
            exit(-56)
        
        print "Using keyfile:", keyfile
        print "Using certfile:", certfile
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            server_side=True,
            keyfile=keyfile,
            certfile=certfile,
            cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_SSLv23,
            )
        if bind_and_activate:
            self.server_bind()
            self.server_activate()

        """End of modified part"""

        # [Bug #1222790] If possible, set close-on-exec flag; if a
        # method spawns a subprocess, the subprocess shouldn't have
        # the listening socket open.
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)
            
#############################################################

# Type of errors
ERR_GENERIC  = -1
ERR_TODO     = -2
ERR_EXISTANT = -10
ERR_SQL      = -11
ERR_CHKSUM   = -12
ERR_SIZE     = -13
ERR_FS       = -14 # filesystem, quite general
ERR_OUTDATED = -15
ERR_DELETED  = -16
ERR_CANNOT   = -17
ERR_NOTEXIST = -18
ERR_INTERNAL = -19
ERR_USER     = -20

# What can a revision come from:
REV_NEWFILE      = 0
REV_COPYFILE     = 1
REV_MOVEFILE     = 2
REV_DELETEFILE   = 3
REV_ROLLEDBACK   = 4
REV_MODIFIED     = 5
REV_FOLDER       = 6

# Most of them are windows-illegal chars, and probably it is still incomplete
# ! is added to avoid an improbable shell-escapation in some badly done scripts
# (better to be extra careful than mess it up, and windows forbids ? anyway) 
FORBIDDEN_CHARS = ['/', "\\",'!','<','>',':','"','|','?','*']
FORBIDDEN_CHARS.extend([chr(i) for i in range(1,32)])

# Side note: Client should be careful to send a POSIX path, so the client is
# expected to strip the slashes '/'. If they do not strip them, probably 
# strange things will happen (maybe server will search for unexistant folders) 

# Windows stuff, again...
FORBIDDEN_NAMES = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
    'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 
    'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9' ]

# Plus something else --posix special folders
FORBIDDEN_NAMES.extend(['.','..'])

class SanitizeError(Exception):
    def __init__(self, char, msg='Found this, not allowed in context: '):
        self.char = char
        self.msg  = msg
    def __str__(self):
        return self.msg + repr(self.char)
        
class ServerInstance():
    def __init__(self, serverParent = None, config = None):
        import string
        self.python_string = string
        self.serverParent = serverParent
        
        try:
            self._userauth = serverParent.userauth
        except AttributeError:
            self._userauth = None
        
        # debugging now!
        self._logger = logging.getLogger('boprox-server')
        self._logger.setLevel(logging.DEBUG)
        
        if config:
            self._repodir   = config.get('Directories','repo')
            self._hashesdir = config.get('Directories','hashes')
            self._deltasdir = config.get('Directories','deltas')
            self._hardsdir  = config.get('Directories','hards')
            self._dbfile    = config.get('Database','dbfile')
        else:
            # Fallback is to do everything "locally"
            self._repodir   = './repo'
            self._hashesdir = './hashes'
            self._deltasdir = './deltas'
            self._hardsdir  = './hards'
            self._dbfile    = './file.sqlite'

        # Test existance of SQLite file
        try:
            self._conn = sqlite3.connect(self._dbfile, 
                detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
            self._conn.row_factory = sqlite3.Row

            # create things if not already exists
            with self._conn as c:
                c.execute('''create table if not exists 
                    files(
                        idfile integer primary key autoincrement,
                        path text,
                        file text,
                        deleted boolean default 0,
                        lastrev integer
                        )
                    ''')
                c.execute('''create table if not exists
                    revisions(
                        idrev integer primary key autoincrement,
                        idfile integer not null,
                        timestamp timestamp,
                        fromrev integer,
                        rollbackrev integer default null,
                        typefrom integer default 0,
                        chksum integer default null,
                        size integer default null,
                        hardexist boolean default 0
                        )
                    ''')
        except:
            # Cannot continue
            print "SQLite error"
            raise
    
    def ping(self):
        '''
        Very dummy function
        '''
        username = self._getUsername()
        
        if not username:
            return 'to anonymous: pong'
        else:
            return 'pong to ' + username
    
    def requestToken(self, username):
        '''
        Request a new password token
        
        @param username: Name of the user. Should be a known user (in the
        users database).
        @return: The RSA encrypted token. The user will be able to decrypt
        it with they private RSA key .
        '''
        if not self._userauth:
            # not having user authentication mechanisms means
            # something is quite wrong
            self._logger.warning('No authentication mechanism set')
            return ERR_INTERNAL
            
        etoken = self._userauth.getNewToken (username)
        
        if not etoken:
            return ERR_USER
        return etoken
        
    def _getUsername(self):
        if self.serverParent:
            return self.serverParent.username
        return None

    def _isLocalPath(self, path):
        '''
        Check if a given path is known. A path is known if either:
          * is empty
          * it is path1/path2 and exists a row in the database with path=path1
            and file=path2, and the row is a directory entry
        
        @param path: String of the path to check
        '''
        if path == '':
            return True
        path1, path2 = os.path.split(path)
        with self._dbfile as c:
            row = c.execute ('select * from files where path=? and file=?',
                (path1,path2) ).fetchone()
        if row:
            return True
        
    def _sanitizeFilename(self, path, file):
        '''
        Check for exploits and dangerous things, '/' and '\' characters (on the 
        server everything is in unix separators), forbidden chars, hidden files 
        and folders, etc.
        
        @param path: String of a folder or a file.
        @return: The sanitized version of the path. Raise a SanitizeError if
        an error is encountered.
        '''
        if not self._isLocalPath(path):
            raise SanitizeError (path, 'Illegal path (not in server): ')
        
        for ch in FORBIDDEN_CHARS:
            if ch in file:
                raise SanitizeError(ch)
            
        if file[0] == '.':
            raise SanitizeError('. (prefix)')
        if file[-1] == '.' or file[-1] == ' ':
            raise SanitizeError('`'+file[-1]+"' (last character)")
        if file in FORBIDDEN_NAMES:
            raise SanitizeError(file,'Illegal name: ')
        
        # everything seems ok, return a full path that should be usable
        return os.path.join(self._repodir,path,file)