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
from traceback import format_exc

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
ERR_SANITIZE = -21

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
        
def wincase_callable(a,b):
    # We assume everything is UTF-8 in the database (let the raise go up)
    x = unicode(a,'UTF-8')
    y = unicode(b,'UTF-8')
    # and compare it case-insensitive
    return cmp (x.lower(), y.lower())
        
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
        
        self._errormsg = ''
        
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
            
            # To enable case-insensitive in more-than-ascii (windows homage)
            self._conn.create_collation('wincase', wincase_callable )

            # create things if not already exists
            with self._conn as c:
                c.execute('''create table if not exists 
                    files(
                        idfile integer primary key autoincrement,
                        path text,
                        file text,
                        deleted boolean default 0,
                        isfolder boolean default 0,
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
          * it is path1/path2 and exists a directory-entry-row in the database 
            with path=path1 and file=path2
        
        @param path: String of the path to check
        @return: False if it is not a local path, True if it is found on database
        '''
        if path == '':
            return True
        path1, path2 = os.path.split(path)
        with self._conn as c:
            row = c.execute ('''select idfile from files where
                path=? collate wincase and
                file=? collate wincase and
                isfolder=1''', (path1,path2)).fetchone()
        if row:
            return True
        
        # No path exists --not local path
        return False
        
    def _safeNew (self, path, file):
        '''
        Special function that checks if it is safe to create a new file (regular
        file or folder). See the collation in __init__ and wincase_callabe.
        
        Note that this function does not check if the file is sanitized, use
        _sanitizeFilename for this goal.
        
        @param path: String of an existant path
        @param file: String of a (expected) non-existant file or folder. This
        function will check if it is safe to create something with this name.
        '''
        with self._conn as c:
            cur = c.execute('''select deleted from files where 
                path=? collate wincase and
                file=? collate wincase''', (path,file))
        
        for row in cur:
            if row['deleted'] == False:
                return False
            
        # No conflicting files found
        # (remind: this could be due an invalid path is invalid 
        #  or a not sanitized file) 
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
        
        firstch, lastch = file[0], file[-1]
        if firstch == '.' or firstch == ' ':
            raise SanitizeError('`'+firstch+"' (first character)")
        if lastch == '.' or lastch == ' ':
            raise SanitizeError('`'+lastch+"' (last character)")
        if file in FORBIDDEN_NAMES:
            raise SanitizeError(file,'Illegal name: ')
        
        # everything seems ok, return a full path that should be usable
        return os.path.join(self._repodir,path,file)
    
    def getErrorMsg(self):
        return self._errormsg
    
    def SendNewFile (self, path, newfile, bindata , chksum = None, size = None):
        '''
        Create a *non-existing* file in server
        
        @param path: String of an *existing* valid path
        @param newfile: String of the file to create into path
        @param bindata: Binary contents of file
        @param chksum: Checksum of file
        @param size: Size of file
        @return: Error code or raise if something goes wrong. A pair idrev and
        timestamp of the file if everything is ok.
        '''
        
        try:
            filepath = self._sanitizeFilename(path, newfile)            
        except SanitizeError as e:
            self._errormsg = e.__str__()
            return ERR_SANITIZE
        
        if not self._safeNew(path, newfile):
            self._errormsg = 'Server not able to create: ' + newfile
            return ERR_CANNOT
        
        self._logger.debug ( "Receiving file %s, saving at %s" , newfile , filepath )
        
        try:
            with open(filepath, "wb") as f:
                f.write(bindata.data)
        except:
            self._errormsg('Internal filesystem error when opening ' + filepath)
            return ERR_FS
        
        # Now we have created the file locally
        # let's check that everything is ok
        
        #first checksum
        with open ( filepath , "rb" ) as f:
            computedChecksum = adler32(f.read())
        if chksum and (chksum != computedChecksum):
            self._errormsg('Checksums do not match --rolled back')
            os.remove(filepath)
            return ERR_CHKSUM
        
        #then size
        computedSize = os.stat(filepath).st_size
        if size and (computedSize != size):
            self._errormsg('Size do not match. Local size: '+ str(computedSize)
                + ' --rolled back')
            os.remove(filepath)
            return ERR_SIZE
        
        tsnow = datetime.now()
        
        with self._conn as c:
            cursor = c.execute('''insert into files 
                (path, file, deleted) values (?,?,0)''', (path, newfile) )
            idfile = cursor.lastrowid
            cursor = c.execute('''insert into revisions 
                ( idfile, timestamp, fromrev, typefrom, chksum, size, hardexist )
                values (?,?,NULL,?,?,?,1)''' , 
                (idfile,tsnow,REV_NEWFILE,computedChecksum,computedSize) 
                )                    
            idrev = cursor.lastrowid
            c.execute("update files set lastrev=? where idfile=?" , 
                (idrev, idfile) )
        
        revPath = os.path.join ( self._hardsdir ,str(idrev) )
        self._logger.info ( "Proceeding to link %s and %s" , filepath , revPath ) 
        os.link ( filepath ,  revPath )
        
        # calculate here hashes for rsync algorithm
        hashes = Hashes.eval(filepath)
        hashes.save (os.path.join(self._hashesdir,str(idrev)))
        
        return idrev, tsnow
    
    def GetFileNews(self, timestamp):
        '''Get a list of changes since timestamp.
        
        @param timestamp: Timestamp of last change. The server will look for 
        all newer entries in the database (revisions table).
        @return: A list of tuples (path,file) of every changed file.
        '''
        self._logger.debug('Getting news from %s' , repr(timestamp) )
        
        # open connection and start working
        with self._conn as c:
            # first, simple iteration ...
            cur = c.execute ( '''select idfile, timestamp as "ts [timestamp]" 
                from revisions order by timestamp desc''' )
            self._logger.debug ('Cursor: %s' , repr(cur) )
            # ... and save every changed id
            idsChanged = set()
            for row in cur:
                self._logger.debug ( "Row with timestamp %s for idfile %s",
                    repr(row['ts']), type(row['ts']) , str(row['idfile']) )
                if row['ts'] > timestamp:
                    idsChanged.add( row['idfile'] )
                else:
                    break
        
            self._logger.debug ( "Getting pathnames for modified files" )
            pathList = []
            for i in idsChanged:
                with self._conn as c:
                    try:
                        row = c.execute ( '''select path,file,
                        from files where idfile=?''', (i,) ).fetchone()
                        pathList.append( (row['path'], row['file']) )
                    except AttributeError, KeyError:
                        self._errormsg = ( 'Internal error --incoherent database\n' +
                            'Exception traceback:\n' + format_exc() )
                        return ERR_INTERNAL
        
        self._logger.debug( "Changed files: %s" , repr(pathList) )
            
        return pathList

    def SendDelta(self, idRev, sentdelta, chksum = None, size = 'NULL'):
        '''
        Send a delta (see rsync algorithm) to server
        
        @param idRev: The identifier of the origin revision
        @param sentdelta: Binary of the delta
        @param chksum: Checksum of the file (not the delta)
        @param size: Size of the file (not the delta)
        @return: Pair of the identifier of the actual revision (once applied
        this delta) and the server timestamp of this file.
        '''        
        tsnow = datetime.now()
        # get real checksum
        self._logger.debug("Receiving delta, now()=%s" , repr(tsnow) )
        self._logger.debug("Chksum received: %s" , repr(chksum) )

        #check if everything is ok
        with self._conn as c:
            self._logger.debug ( "Getting row of revisions . . ." )
            rowRev = c.execute ( "select * from revisions where idrev=?" ,
                (idRev,)).fetchone()
            if not rowRev:
                self._errormsg('Unknown revision')
                return ERR_NOTEXIST
            self._logger.debug ( "Getting row of file information . . ." )
            rowFile = c.execute ( "select * from files where idfile=?" ,
                (rowRev['idfile'],) ).fetchone()
            if not rowFile:
                self._errormsg ('Data not found in the database, check file existance')
                return ERR_NOTEXIST
            
            # Basic checks
            if rowFile['lastrev'] != idRev:
                self._errormsg ("Outdated client: not the last revision")
                return ERR_OUTDATED
            if rowFile['deleted'] == 1:
                self._errormsg("File is deleted, cannot add revisions to it")
                return ERR_DELETED
            if rowFile['isfolder']:
                self._errormsg('The file is a folder, cannot add revisions to it')
                return ERR_CANNOT
            
            # Now do really something
            self._logger.debug ( "Inserting new revision into database . . ." )
            cur = c.execute ( '''insert into revisions 
                (idfile, timestamp, fromrev, typefrom, chksum, size, hardexist) 
                values (?,?,?,?,?,?,0)''' , 
                (rowRev['idfile'], tsnow, idRev, REV_MODIFIED, chksum, size ) )
            nextRev = cur.lastrowid
            c.execute ( '''update files set lastrev=? where idfile=?''' ,
                (nextRev , rowRev['idfile'] ) )
            
        self._logger.debug ( "Going to write the delta file" )
        #save the delta
        delta = Deltas.load(sentdelta)
        delta.save(os.path.join(self._deltasdir,str(nextRev)))
        
        self._logger.debug ( "Latest revision: %s" , int(nextRev) )
        return nextRev, tsnow
