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
import time
from zlib import adler32
import sys
from traceback import format_exc, print_exc
import auth

from deltaindustries import Hashes, Deltas
import Sanitize

try:
    import fcntl
except ImportError:
    fcntl = None

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class AuthXMLRPCServerTLS(SimpleXMLRPCServer):
    def __init__(self, addr, userauth = None, requestHandler=RequestHandler,
            keyfile=None, certfile=None, logRequests=True, allow_none=True, 
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
ERR_NOTAUTH  = -22

# What can a revision come from:
REV_NEWFILE      = 0
REV_COPYFILE     = 1
REV_MODIFIED     = 2
REV_DELETEFILE   = 3
REV_ROLLEDBACK   = 4
REV_FOLDER       = 5
        
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
        
        self._dicterror = {}
        
        # debugging now!
        self._logger = logging.getLogger('boprox-server')
        
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
        @return: The sanitized version of the path. Raise a Error if
        an error is encountered.
        '''
        if not self._isLocalPath(path):
            raise Sanitize.Error (path, 'Illegal path (not in server): ')
        
        for ch in Sanitize.FORBIDDEN_CHARS:
            if ch in file:
                raise Sanitize.Error(ch)
        
        firstch, lastch = file[0], file[-1]
        if firstch == '.' or firstch == ' ':
            raise Sanitize.Error('`'+firstch+"' (first character)")
        if lastch == '.' or lastch == ' ':
            raise Sanitize.Error('`'+lastch+"' (last character)")
        if file in Sanitize.FORBIDDEN_NAMES:
            raise Sanitize.Error(file,'Illegal name: ')
        
        # everything seems ok, return a full path that should be usable
        return os.path.join(self._repodir,path,file)
    
    def _checkPerms (self, path, idperm):
        user = self._getUsername()
        if not user:
            self._seterrormsg ('Not authenticated')
            return ERR_NOTAUTH
        if not self._userauth:
            self._seterrormsg('No authentication mecanism on server')
            return  ERR_INTERNAL
        if not self._userauth.checkPerm(user, path, idperm):
            self._seterrormsg ('User %s not authorized to do that' % user)
            return ERR_NOTAUTH
        return 0
    
    def _getDeltasSinceEvent ( self, eventType , condition , startRev ):
        '''
        Get all the deltas since a given "event" (sqlite column)
        The row that satisfies the condition is added to the list
        (be careful with idrev vs fromrev).
        
        @param eventType: String containing the name of a sqlite column.
        @param condition: Condition to check in the column.
        @param startRev: Revision to start with (newer revision).
        @return: the best error code if something goes wrong, otherwise returns
        the list of delta identifiers
        '''
        # thinking in a yield-ing function maybe?
        # but the chain checker should be done before starting,
        # yield function seems a bad idea
        with self._conn as c:
            revRow = c.execute ( '''select * from revisions
                where idrev=?''' , (startRev,) ).fetchone()
            deltaHistory = []
            while revRow[eventType] != condition:
                if not revRow['typefrom'] in (REV_COPYFILE, REV_MODIFIED):
                    self._seterrormsg('Found an invalid revision when creating a chain of changes')
                    return ERR_CANNOT
                deltaHistory.append( revRow['idrev'] )
                revRow = c.execute ( 'select * from revisions where idrev=?' , 
                    (revRow['fromrev'],) ).fetchone()
                if not revRow:
                    self._seterrormsg('Could not create the chain of events,'+
                        ' a revision was not found')
                    return ERR_CANNOT
                self._logger.debug ( 'This row %s has %s in %s' , 
                    str(revRow['idrev']) , str(revRow[eventType]) , eventType )
        deltaHistory.append(revRow['idrev'])
        return deltaHistory
    
    def _seterrormsg(self, errormsg):
        user = self._getUsername()
        if user:
            self._dicterror[user] = errormsg
    
    def getErrorMsg(self):
        try:
            user = self._getUsername()
            if user:
                return self._dicterror[self._getUsername()]
            else:
                return ("You can only get error messages when authenticated")
        except KeyError:
            return("No error message found. Check authentication." +
                    'Are you sure there has been an error?')
    
    def _basicNewChecks(self, path, newfile):
        '''
        This function has the basics checks when a new file is to be created.
        Used in CopyFile and SendNewFile, and put here to avoid code 
        duplication. May be used somewhere else.
        '''
        ret = self._checkPerms(path, auth.WRITE)
        if ret < 0:
            return ret
        
        try:
            filepath = self._sanitizeFilename(path, newfile)            
        except Sanitize.Error as e:
            self._seterrormsg(e.__str__())
            return ERR_SANITIZE
        
        if not self._safeNew(path, newfile):
            self._seterrormsg('Server not able to create: ' + newfile)
            return ERR_CANNOT
        return filepath
    
    def CopyFile (self, path, newfile, originrev):
        '''
        Create a copy of an existing revision
        
        @param path: String of an *existing* valid path
        @param newfile: String of the file to create into path
        @param originrev: Identificator of a valid non-folder revision
        '''
        filepath = self._basicNewChecks(path, newfile)
        if isinstance(filepath, int):
            return filepath
        
        self._logger.debug( "Copying revision %s into file %s", 
            str(originrev), filepath)
        tsnow = datetime.fromtimestamp(int(time.time()))
        with self._conn as c:
            originrow = c.execute ('select * from revisions where idrev=?',
                (originrev,) ).fetchone()
            if not originrow:
                self._seterrormsg('Unexistant origin revision')
                return ERR_NOTEXIST
            # good place to create hard revision, if not already exists
            if not originrow['hardexist']:
                ret = self._createHard(originrev, c)
                if ret < 0:
                    return ret
                self._logger.debug ('Created hard revision for origin')
            else:
                self._logger.debug ('A hard revision already existed for origin')
            cursor = c.execute('''insert into files 
                (path, file, deleted) values (?,?,0)''', (path, newfile) )
            idfile = cursor.lastrowid
            cursor = c.execute('''insert into revisions 
                ( idfile, timestamp, fromrev, typefrom, chksum, size, hardexist )
                values (?,?,?,?,?,?,1)''' , 
                    (idfile,tsnow,originrev,REV_COPYFILE,
                    originrow['chksum'], originrow['size']) 
                )
            idrev = cursor.lastrowid
            c.execute("update files set lastrev=? where idfile=?" , 
                (idrev, idfile) )
        self._logger.debug('Linking everything')
        os.link(
            os.path.join(self._hardsdir,str(originrev)), 
            os.path.join(self._hardsdir,str(idrev))     )
        os.link( os.path.join(self._hardsdir,str(originrev)), filepath)
        return idrev, tsnow
    
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
        filepath = self._basicNewChecks(path, newfile)
        if isinstance(filepath, int):
            return filepath
        
        self._logger.debug ( "Receiving file %s, saving at %s" , newfile , filepath )
        try:
            with open(filepath, "wb") as f:
                f.write(bindata.data)
        except:
            self._seterrormsg('Internal filesystem error when opening ' 
                + filepath)
            return ERR_FS
        
        # Now we have created the file locally
        # let's check that everything is ok
        
        #first checksum
        with open ( filepath , "rb" ) as f:
            computedChecksum = adler32(f.read())
        if chksum and (chksum != computedChecksum):
            self._seterrormsg('Checksums do not match --rolled back')
            os.remove(filepath)
            return ERR_CHKSUM
        
        #then size
        computedSize = os.stat(filepath).st_size
        if size and (computedSize != size):
            self._seterrormsg('Size do not match. Local size: '+ 
                str(computedSize) + ' --rolled back')
            os.remove(filepath)
            return ERR_SIZE
        
        tsnow = datetime.fromtimestamp(int(time.time()))
        
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
        savehash = os.path.join(self._hashesdir,str(idrev))
        self._logger.debug ("Saving hash in %s", savehash)
        hashes.save (savehash)
        
        return idrev, tsnow
    
    def GetFileNews(self, timestamp):
        '''Get a list of changes since timestamp.
        
        @param timestamp: Timestamp of last change. The server will look for 
        all newer entries in the database (revisions table).
        @return: A list of tuples (path,file) of every changed file.
        
        Note: This function is highly inefficient for multiuser servers. This 
        can be improved a lot. TODO
        '''
        # Check that is authenticated
        if not self._getUsername():
            self._seterrormsg('Should be authenticated to do that')
            return ERR_NOTAUTH
        
        self._logger.debug('Getting news from %s' , repr(timestamp) )
        
        # open connection and start working
        with self._conn as c:
            # first, simple iteration ...
            cur = c.execute ( '''select idfile, timestamp as "ts [timestamp]" from revisions
                order by timestamp desc''' )
            self._logger.debug ('Cursor: %s' , repr(cur) )
            # ... and save every changed id
            idsChanged = set()
            for row in cur:
                self._logger.debug ( "Row with timestamp %s for idfile %s",
                    repr(row['ts']), str(row['idfile']) )
                if row['ts'] > timestamp:
                    idsChanged.add( row['idfile'] )
                else:
                    break
        
            self._logger.debug ( "Getting pathnames for modified files" )
            pathList = []
            for i in idsChanged:
                with self._conn as c:
                    try:
                        row = c.execute ( '''select path,file
                            from files where idfile=?''', (i,) ).fetchone()
                        # only return information if the user has read permissions
                        # on that folder
                        if self._checkPerms(row['path'], auth.READ) == 0:
                            pathList.append( (row['path'], row['file']) )
                    except AttributeError, KeyError:
                        self._seterrormsg('Internal error --incoherent database\n' +
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
        tsnow = datetime.fromtimestamp(int(time.time()))
        # get real checksum
        self._logger.debug("Receiving delta, now()=%s", repr(tsnow) )
        self._logger.debug("Chksum received: %s", repr(chksum) )

        #check if everything is ok
        with self._conn as c:
            self._logger.debug ( "Getting row of revisions . . ." )
            rowRev = c.execute ( "select * from revisions where idrev=?" ,
                (idRev,)).fetchone()
            if not rowRev:
                self._seterrormsg('Unknown revision')
                return ERR_NOTEXIST
            self._logger.debug ( "Getting row of file information . . ." )
            rowFile = c.execute ( "select * from files where idfile=?" ,
                (rowRev['idfile'],) ).fetchone()
            if not rowFile:
                self._seterrormsg('Data not found in the database, '+
                    'check revision existance')
                return ERR_NOTEXIST
            
            # Authentication check
            self._checkPerms(rowFile['path'], auth.WRITE)
            
            # Basic checks
            if rowFile['lastrev'] != idRev:
                self._seterrormsg("Outdated client: not the last revision")
                return ERR_OUTDATED
            if rowFile['deleted'] == 1:
                self._seterrormsg("File is deleted, cannot add revisions to it")
                return ERR_DELETED
            if rowFile['isfolder']:
                self._seterrormsg('The file is a folder, cannot add revisions to it')
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

    def GetDelta(self, idRev, idFromRev):
        '''
        Get a delta (see rsync algorithm) from the server to jump to a newer
        revision. The delta is known to the server or fabricated from some 
        deltas
        
        @param idRev: "Destination revision"
        @param irFromRev: "Origin revision"
        @return: Binary information of the petition (asked delta)
        '''
        
        with self._conn as c:
            # First, check permissions
            row = c.execute ("select idfile from revisions where idrev=?",
                (idFromRev,) ).fetchone()
            if not row:
                self._seterrormsg("Unknown origin revision")
                return ERR_NOTEXIST
            row = c.execute ("select path,isfolder from files where idfile=?",
                (row['idfile'],) )
            if not row:
                self._seterrormsg('Unconsistent files table (database error)')
                return ERR_INTERNAL
            if row['isfolder']:
                self._seterrormsg('Cannot get a delta for a folder')
                return ERR_CANNOT
            originpath = row['path']
            ret = self._checkPerms(originpath, auth.READ)
            if ret < 0:
                return ret
            
            # Until now everything seems fine, let's check "destination"
            revRow = c.execute( "select * from revisions where idrev=?" , 
                (idRev,) ).fetchone()
            if not revRow:
                self._seterrormsg('Unknown destination revision')
                return ERR_NOTEXIST
            row = c.execute ("select path,isfolder from files where idfile=?" ,
                (revRow['idfile']) ).fetchone()
            if not row:
                self._seterrormsg('Inconsistent files table (database error)')
                return ERR_INTERNAL
            if row['isfolder']:
                self._seterrormsg('Cannot get a delta for a folder')
                return ERR_CANNOT
            # only check permissions if there is a folder change
            if originpath != row['path']:
                ret = self._checkperms(row['path'], auth.READ)
                if ret < 0:
                    return ret
        #if it's the easy way, we do it the easy way (most likely to hapen)
        if (revRow['fromrev'] == idFromRev) and (revRow['fromtype'] == REV_MODIFIED):
            #yes, we are lucky!
            try:
                return Deltas.open(os.path.join(self._deltasdir,str(idRev))).getXMLRPCBinary()
            except:
                return ERR_FS
        else:
            # 1st: check that exists a chain of non-deletions between 
            # this two revisions (save the first hardcopy for later)
            deltaList = self._getDeltasSinceEvent ( 'fromrev' , idFromRev , idRev )
            if type(deltaList) == int:
                return deltaList
                
            # 2nd: try to join everything
            try:
                listoffiles = [os.path.join(self._deltasdir, str(i)) for i in deltaList]
                delta = Deltas.multiOpen(listoffiles)
            except:
                return ERR_FS
            
            # 3rd: Send delta
            return delta.getXMLRPCBinary()
        
    def CheckFileMetadata (self, size, chksum):
        '''
        This functions is used by the client to check if a ``new file'' is 
        really new or it is a copy of an existing file (some revision).
        
        @param size: Size of the file
        @param chksum: ``Standard'' checksum of the file
        @return: 0 if did not found any, or the revision number otherwise   
        '''
        with self._conn as c:
            cur = c.execute ('''select idrev,idfile from revisions where 
                size=? and chksum=?''', (size,chksum) )
            for row in cur:
                fileinfo = c.execute ('''select path,file from files where 
                    idfile=?''', (row['idfile'],) ).fetchone()
                if not fileinfo:
                    self._seterrormsg('Inconsistent database, a file was not found')
                    return ERR_INTERNAL
                if self._checkPerms(fileinfo['path'], auth.READ) == 0:
                    return row['idrev']
        return 0
    
    def _createHard(self, idRev, openedconn):
        self._logger.debug ( 'Doing a hard revision on %s', str(idRev) )
        deltaList = self._getDeltasSinceEvent ('hardexist', 1, idRev)
        self._logger.debug ( "received this deltaList: %s", repr(deltaList) )
        if type(deltaList) == int:
            self._seterrormsg( 'Could not create internal chain of deltas. '+
                'Internal error: ' + str(deltaList) )
            return ERR_INTERNAL
        
        # join everything
        # first throw away this, but save for later
        hardRev = deltaList.pop()
        self._logger.debug ( "Generating internal delta" )
        try:
            listoffiles = [os.path.join(self._deltasdir, str(i)) for i in deltaList]
            delta = Deltas.multiOpen(listoffiles)
        except:
            return ERR_FS
        # the last one, now will have hardcopy
        openedconn.execute ( '''update revisions set hardexist=1
            where idrev=?''' , (idRev,) )
        infile =  os.path.join(self._hardsdir,str(hardRev))
        outfile = os.path.join(self._hardsdir,str(idRev))
        delta.patch(infile, outfile)
        return 0
    
    def GetFullRevision ( self, idRev ):
        '''
        Get a full file (not a delta) by its revision identificator. The server
        can be asked any revision (not necessarily the most recent).
        
        @param idRev: Revision that the client asks for
        @return: Error code or Binary information of the file
        '''
        self._logger.info( 'Getting full revision for %s' , str(idRev) )
        
        with self._conn as c:
            row = c.execute ('select * from revisions where idrev=?' , 
                (idRev,) ).fetchone()
            if not row:
                self._seterrormsg('Unknown revision')
                return ERR_NOTEXIST
            # check permissions
            fileRow = c.execute('select path from files where idfile=?' ,
                (row['idfile'],) ).fetchone()
            if not fileRow:
                self._seterrormsg('Inconsistent files table (database error)')
                return ERR_INTERNAL
            ret = self._checkPerms(fileRow['path'], auth.READ)
            if ret < 0:
                return ret
            # check if this operation can be the easy way
            if row['hardexist'] != 1:
                ret = self._createHard(idRev, c)
                if ret < 0:
                    return ret

        self._logger.debug ( 'Sending hard revision to client' )
        with open ( os.path.join ( self._hardsdir , str(idRev) ) , "rb" ) as f:
            return Binary ( f.read() )

    def GetMetaInfo ( self, idrev, force=False):
        '''
        Get the metainfo of some revision.
        
        @param idrev: The identifier of the revision.
        @param force: If a force GetMetaInfo is done (force=True) then the 
        server will do a hard copy (if does not exist) and physically check
        this values. A write permission is needed in this case. Default False.
        @return: The metainfo (actually a tuple size,checksum,timestamp). Size
        and/or checksum may be None if not forced.
        '''
        with self._conn as c:
            row = c.execute('''select 
                idfile,size,chksum,timestamp as "ts [timestamp]" 
                from revisions where idrev=?''', (idrev,) ).fetchone()
            if not row:
                self._seterrormsg('Unknown revision')    
                return ERR_NOTEXIST
            fileRow = c.execute ('select path,isfolder from files where idfile=?',
                (row['idfile'],) ).fetchone()
            if not fileRow:
                self._seterrormsg('Inconsistent files table (database error)')
                return ERR_INTERNAL

        if force == False:
            ret = self._checkPerms(fileRow['path'], auth.READ)
            if ret < 0:
                return ret
            return row['size'], row['chksum'], row['ts'], fileRow['isfolder']
        else:
            ret = self._checkPerms(fileRow['path'], auth.WRITE)
            if ret < 0:
                return ret
            return ERR_TODO
        
    def GetLastRev(self, path, file):
        '''
        Get the identifier of the last revision of some file
        @param path: Path of the file
        @param file: Filename
        @return: identifier of the last revision of previous file
        '''
        ret = self._checkPerms(path, auth.READ)
        if ret < 0:
            return ret
        with self._conn as c:
            row = c.execute ( 'select lastrev from files where path=? and file=?', 
                (path,file) ).fetchone()
        if not row:
            self._seterrormsg('Unknown file')
            return ERR_NOTEXIST
        return row['lastrev']
        
    def MakeDir (self, path, folder ):
        '''
        Create directory
        
        @param path: Path where to create
        @param folder: Name of the folder to create
        @return: Identifier of the folder revision and timestamp from server
        '''
        ret = self._checkPerms(path, auth.WRITE)
        if ret < 0:
            return ret
        try:
            folderpath = self._sanitizeFilename(path, folder)            
        except Sanitize.Error as e:
            self._seterrormsg(e.__str__())
            return ERR_SANITIZE
        # Safely ready to create it
        tsnow = datetime.fromtimestamp(int(time.time()))
        try:
            os.mkdir(folderpath)
        except:
            self._seterrormsg('Filesystem error when creating folder')
            return ERR_FS
        with self._conn as c:
            cursor = c.execute('''insert into files 
                (path, file, deleted, isfolder) 
                values (?,?,0,1)''', (path, folder) )
            idfile = cursor.lastrowid
            cursor = c.execute('''insert into revisions 
                ( idfile, timestamp, fromrev, typefrom, hardexist )
                values (?,?,NULL,?,NULL)''' , (idfile,tsnow,REV_FOLDER) )                    
            idrev = cursor.lastrowid
            c.execute("update files set lastrev=? where idfile=?" , 
                (idrev, idfile) )
        return idrev, tsnow
