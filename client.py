'''
Created on Aug 4, 2011

@author: marius
'''

import rsa
from pyasn1.codec.der.decoder import decode as derdecode
from base64 import b64decode
from xmlrpclib import ServerProxy, Binary, ProtocolError
import sqlite3
import os.path
from datetime import datetime
from zlib import adler32
import logging

from deltaindustries import Deltas, Hashes
import Sanitize

def _fileAcceptor( filenames ):
    '''
    Auxiliary function for filtering filenames and foldernames.
    Ignore the files with a dot prefixing it (hidden files in unix operative 
    systems). Using Sanitize information
    '''
    for file in filenames:
        badfile = False
        for ch in Sanitize.FORBIDDEN_CHARS:
            if ch in file:
                badfile = True
                break
        if not badfile:
            firstch, lastch = file[0], file[-1]
            if firstch == '.' or firstch == ' ' or lastch == '.' or lastch == ' ':
                badfile = True
            elif file in Sanitize.FORBIDDEN_NAMES:
                badfile = True
            else: 
                yield file

def getKeyFromPEM(PEMdata):
    '''
    Return a private key that can be feeded to the rsa module.
    
    @param PEMdata: data of a PEM certificate (without header nor footer)
    @return: key dictionary with private d,p,q values
    '''
    derdata = b64decode(PEMdata)
    privkey = derdecode(derdata)[0]
    return {'d': int(privkey[3]) , 'p': int(privkey[4]), 'q':int(privkey[5])}
    
def getKeyFromPEMfile(filename):
    '''
    Return a private key that can be feeded to the rsa module.
    
    @param filename: String containing file to extract 
    pass
    '''
    privdata = ''
    with open('johnsmith.rsa' , 'r') as f:
        for line in f:
            if line[0:5] != '-----':
                pass
            else:
                for line in f:
                    if line[0:5] == '-----':
                        return getKeyFromPEM(privdata)
                    else:
                        privdata += line
    # File ended, not a goot header/footer
    return None

class ClientError(Exception):
    def __init__(self, retcode='-1', call=None):
        self.retcode = retcode
        self.file = file
        self.call = call
        # This variable is for a catch-set-reraise procedure
        self.moreinfo = None 

    def __str__(self):
        estr = '\nError in client communication with server\n'
        estr+= '-----------------------------------------\n'
        estr+= 'Return code: ' + str(self.retcode)
        if self.call:
            estr += '\nRemote call in progress: ' + self.call
        if self.moreinfo:
            estr+= '\n-----------------------------------------\n'+self.moreinfo
        return estr
    
class LocalError(Exception):
    pass

class SingleRepoClient:
    def __init__(self, host, port, username, dbfile, localpath, 
        remotepath = '', hashesdir = './hashes', key=None, permatoken=None):
        '''
        Create a sort-of API to connect with one server (one repository). One
        and only one of key and permatoken parameters must not be None.
        
        @param host: Host to connect
        @param port: Port to connect
        @param username: Name to authenticate
        @param dbfile: sqlite database file to track files and revisions
        @param localpath: Local path used to synchronize
        @param remotepath: Remote path to synchronize with (default: .) --useful
        for shared resources or multiuser servers.
        @param key: RSA key used for authentication
        @param permatoken: Password (considered a ``permanent token'')
        '''

        ######################################################
        ## The following two classes have been ``inspired'' ##
        ## from xmlrpclib.py and its ServerProxy            ##
        ######################################################
        
        # Some magic method-caller
        class _Method:
            '''
            Inspiration in xmlrpclib.py
    
            Stripping off the nested support
            '''
            def __init__(self,send,name):
                self.__send = send
                self.__name = name
    
            def __call__(myself, *args):
                try:
                    ret = myself.__send(myself.__name, args)
                except ProtocolError:
                    del (self._authConn)
                    self._requestToken()
                    # if it fails here, then let the raise "go up"
                    ret = myself.__send(myself.__name, args)
                return ret
        
        # Some magic transparent proxy for remote calls
        class CallProxifier:
            def __init__(self):
                pass
            
            def __request(myself, methodname, params):
                func = getattr(self._authConn, methodname)
                ret = func(*params)
                if isinstance(ret, int) and ret < 0:
                    raise ClientError(ret, methodname)
                return ret
            
            def __getattr__(self, name):
                return _Method(self.__request, name)
            
        # Basic check of authentication mechanism
        if not key and not permatoken:
            raise TypeError('Either key or permatoken must be given')
        
        if not permatoken:
            # Do it for key
            self._key = key
            self._permatoken = False
            self._token = None
        else:
            # We have permatoken
            self._key = None
            self._permatoken = True
            self._token = permatoken

        # initialize values
        self._host = host
        self._port = port
        self._username = username
        self._localpath  = os.path.abspath(localpath)
        self._remotepath = remotepath
        self._hashesdir = os.path.abspath(hashesdir)
        
        # initialize logging facility
        self._logger = logging.getLogger('boproxclient')
        
        # open database
        self._db = sqlite3.connect(dbfile,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._db.row_factory = sqlite3.Row
        
        # create things if they do not exist alreay
        with self._db as c:
            c.execute('''create table if not exists 
                files(
                    idfile integer primary key autoincrement,
                    path text,
                    file text,
                    deleted boolean default 0,
                    lastrev integer,
                    timestamp timestamp,
                    localtime real,
                    chksum integer default null,
                    size integer default null,
                    isdir boolean default 0,
                    conflict boolean default 0
                    )
                ''')
        
        # initialize XMLRPC connection
        anonURL = "https://%s:%s" % (host,str(port))
        self._anonConn = ServerProxy(anonURL)
        self._requestToken()
        
        # Prepare the ``magic'' (no precoding of remote functions, and 
        # automatic re-ask of tokens when expired)
        self._RemoteCaller = CallProxifier()
        
        # Save a timestamp
        self._lockTimestamp()

    def _requestToken(self):
        # If we have permatoken, then it is in _token and we do nothing
        if self._permatoken == False:
            # Otherwise, do the RSA standard procedure with the server.
            etoken = self._anonConn.requestToken(self._username)
            self._token = rsa.decrypt(etoken, self._key)
        self._authURL = "https://%s:%s@%s:%s" % (self._username, self._token, 
            self._host, str(self._port) )
        self._authConn = ServerProxy(self._authURL, use_datetime=True, 
            allow_none=True)
        
    def _notThisRepo(self, path):
        '''
        Checks if a given path starts with ``remotepath'' and, striping this 
        prefix, is a valid local directory
        '''
        self._logger.debug("Remote path:%s", self._remotepath)
        self._logger.debug(" Local path:%s", path )
        
        if not path.startswith(self._remotepath):
            return True
        spath = path[len(self._remotepath):].lstrip('/')
        if spath == '':
            return False
        path1, path2 = os.path.split(spath)
        with self._db as c:
            row = c.execute ('''select idfile from files where
                path=? collate wincase and
                file=? collate wincase and
                isfolder=1''', (path1,path2)).fetchone()
        if row:
            return False
        # No path exists --not local path
        return True
        
    def _sanitizeFilename(self, path, file):
        '''
        Check for exploits and dangerous things, '/' and '\' characters (on the 
        server everything is in unix separators), forbidden chars, hidden files 
        and folders, etc. The server does this, but the client may not trust 
        the server.
        
        @param path: String of a folder or a file.
        @return: The sanitized version of the path. Raise a Error if
        an error is encountered.
        '''
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
        return os.path.join(self._localpath,path,file)

        
    def ping(self):
        '''
        Dummy function --calling the remote dummy function
        '''
        return self._RemoteCaller.ping()
    
    def CheckLocalIntegrity(self):
        '''
        This call forces a checksum on each and every file in the local side.
        Useful if some things have become corrupt or strange things happen with
        modified time attribute on files.
        
        Use with caution: very IO (hard-disk) intensive.
        
        If things have changed, local database will be updated and changes will
        be sent to the server as usual. 
        '''
        pass
    
    def CheckRepoIntegrity(self):
        '''
        This call walks all the files in the repository database and checks if 
        every file is correct (from the server point of view). If there is 
        something wrong (outdated) this function tries to update it as a normal
        update.
        
        It is quite network-intensive --much more than UpdateFromServer().
        Recommended to use it not very often (every couple of hours, when the 
        client starts, when there are problems, when the user explicitly asks 
        for it...)
        '''
        pass
    
    def _lockTimestamp(self):
        '''
        Saves the current more up-to-date timestamp. This datetime is used
        later in UpdateFromServer to minimize the network traffic.
        '''
        try:
            self._timestamp = self._db.execute ( 
                '''select timestamp as "ts [timestamp]" 
                from files order by timestamp desc''' ).fetchone()['ts']
        except:
            # If there is any error, get all the changes
            self._timestamp = datetime.min
            
    def CheckChanges(self, filecheck, dirpath, remotedir, rowInfo):
        '''
        Given a file (with metadata) check if it has changed. If changes have
        been made, then send them to the server and update database.
        
        @param filecheck: The name of the new file
        @param dirpath: Must be a correct relative path where file is
        @param remotedir: The remote counterpart of dirpath
        @param rowinfo: A database row with metainfo of the file
        '''
        localfile = os.path.join(dirpath,filecheck)
        modifiedTime = os.stat(localfile).st_mtime
        computedSize = os.stat(localfile).st_size    
        if ( rowInfo['localtime'] != modifiedTime or
                 rowInfo['size']  != computedSize ):
            # Here! Some file needs care
            self._logger.info('Detected modified file: %s' , localfile )
            hashes = Hashes.open(os.path.join(
                self._hashesdir, str(rowInfo['idfile'] )))    
            # Get size
            computedSize = os.stat(localfile).st_size
            
            with open ( localfile , "rb" ) as f:
                # Get checksum
                computedChksum = adler32(f.read())
                # Get delta
                f.seek(0)
                delta = hashes.computeDelta(f)
            self._logger.debug ( "Last revision: %s" , repr(rowInfo['lastrev']) )
            self._logger.debug ( "Checksum: %s" , repr(computedChksum) )
            self._logger.debug ( "Size: %s" , repr(computedSize) )
            ret = self._RemoteCaller.SendDelta ( rowInfo['lastrev'], 
                delta.getXMLRPCBinary(), computedChksum, computedSize )
            self._logger.debug ( "Sent, response: %s" , repr(ret) )
            
            with self._db as c:
                c.execute ( '''update files set 
                    lastrev=?, timestamp=?, localtime=?, chksum=?, size=?
                    where idfile=?''' , (ret[0], ret[1], modifiedTime, 
                        computedChksum, computedSize, rowInfo['idfile'] )
                    )
            # update the hashes
            self._logger.debug ( "Updating hash file %s" , str(rowInfo['idfile']) )
            hash = Hashes.eval(localfile)
            hash.save(os.path.join(self._hashesdir, str(rowInfo['idfile']) ))
        else:
            self._logger.debug('No changes found for file:%s (path:%s)'
                % (filecheck,dirpath) )
        
    def NewFile(self, filecheck, dirpath, remotedir):
        '''
        Function used when a potential new file is found.
        
        @param filecheck: The name of the new file
        @param dirpath: Must be a correct relative path where file is
        @param remotedir: The remote counterpart of dirpath
        '''
        localfile = os.path.join(dirpath,filecheck)
        modifiedTime = os.stat(localfile).st_mtime
        computedSize = os.stat(localfile).st_size    
        self._logger.info('Detected new file: %s' , localfile )
        with open ( localfile , "rb" ) as f:
            # Get checksum
            computedChksum = adler32(f.read())
            # Get data
            f.seek(0)
            dataToSend = Binary(f.read())
            
        # Checking if the server knows the file
        ret = self._RemoteCaller.CheckFileMetadata (computedSize, computedChksum)
        if ret > 0:
            # Say the server that we want to copy
            self._logger.debug( "Creating a copy of revision %s", str(ret) )
            retcp = self._RemoteCaller.CopyFile ( remotedir, filecheck, ret )
            self._logger.debug ( "Sent, response: %s" , repr(retcp) )
            lastrev, timestamp = retcp
        else:
            # Send everything (new) to server
            self._logger.debug( "Transfering new file to server" )
            ret = self._RemoteCaller.SendNewFile( remotedir, filecheck,
                dataToSend, computedChksum, computedSize)
            self._logger.debug ( "Sent, response: %s" , repr(ret) )
            lastrev,timestamp = ret
        # We use the revision id
        with self._db as c:
            cur = c.execute ( '''insert into files 
                (path, file, lastrev, timestamp, localtime, chksum, size) 
                values (?,?,?,?,?,?,?)''' , 
                    (dirpath, filecheck, 
                    lastrev, timestamp, modifiedTime, 
                    computedChksum, computedSize )
                )
            fileId = cur.lastrowid
        # Save the hashes for later use
        hashes = Hashes.eval(localfile)
        hashes.save(os.path.join(self._hashesdir, str(fileId) ))
        
    def CheckExistantFiles(self):
        '''
        This function checks every file and folder in the actual folder
        (the caller should previously chdir to localpath).
        '''
        for walkpath, dirnames, filenames in os.walk('.'):
            dirpath = os.path.normpath(walkpath)
            if dirpath == '.': dirpath = ''
            remotedir = os.path.normpath(os.path.join (self._remotepath, dirpath))
            if remotedir == '.': remotedir = ''
            # first, eliminate directories which haven't been modified
            for dircheck in _fileAcceptor(dirnames):
                modifiedTime = os.stat(os.path.join(dirpath,dircheck)).st_mtime
                row = self._db.execute ( '''select localtime from files where
                    path=? and file=? and isdir=1''', 
                    (dirpath,dircheck) ).fetchone()
                if not row:
                    self._logger.info('Creating folder %s in path %s (remote: %s)',
                        dircheck, dirpath, remotedir )
                    idrev,serverTimestamp = self._RemoteCaller.MakeDir(
                        remotedir, dircheck)
                    with self._db as c:
                        c.execute ( '''insert into files 
                            (path,file,lastrev,timestamp,localtime,isdir) 
                            values (?,?,?,?,?,1)''' , (dirpath, dircheck, 
                                idrev, serverTimestamp, modifiedTime)
                            )
                elif (row['localtime'] == modifiedTime ):
                    dirnames.remove(dircheck)
            for filecheck in _fileAcceptor(filenames):
                row = self._db.execute ( "select * from files where path=? and file=?",
                    (dirpath,filecheck) ).fetchone()
                if row == None:
                    # New file!
                    self.NewFile(filecheck, dirpath, remotedir)
                else:
                    self.CheckChanges(filecheck, dirpath, remotedir, row)
    
    def CheckDeletedFiles(self):
        '''
        The database is "walked" looking for missing files. 
        '''
        pass

    def UpdateFromServer(self):
        '''
        Get all changed things from the server (last-timestamp system) and
        update everything that is changed.
        
        It is safe to call this function periodically, when there are no changes
        it is not network-intensive.
        '''
        self._logger.debug('Getting changes since %s' , self._timestamp )
        changedData = self._RemoteCaller.GetFileNews( self._timestamp )
        # now get each change
        for path,file in changedData:
            with self._db as c:
                if self._notThisRepo(path):
                    continue
                lastrev = self._RemoteCaller.GetLastRev(path, file)
                self._logger.debug("Changes for file,path: %s,%s (revision: %s)" , 
                    file,path,str(lastrev) )
                filepath = self._sanitizeFilename(path, file)
                #if exists, get the delta; if not, get the file
                row = c.execute ( 'select * from files where file=? and path=?' , 
                    (file,path) ).fetchone()
                serverSize,serverChksum,serverTimestamp, isdir = \
                    self._RemoteCaller.GetMetaInfo(lastrev)
                self._logger.debug('Metainfo received: %s' , 
                    repr((serverSize,serverChksum,serverTimestamp, isdir)) )
                if row:
                    self._logger.debug ('Checking that the file is in a older revision')
                    if row['lastrev'] == lastrev:
                        continue
                    if row['isdir'] and isdir:
                        self._logger.debug('It is a folder')
                        # TODO maybe we have to track deleted folders and
                        # something else... from now on, ``silently'' continue
                        continue
                    if row['isdir'] or isdir:
                        raise LocalError('Server and client inconsistent with '+
                            'folder/file %s' , filepath)
                    self._logger.debug ('Checking that size and mtime of local file')
                    computedSize = os.stat(filepath).st_size
                    modifiedTime = os.stat(filepath).st_mtime
                    if ( computedSize != row['size'] or
                         modifiedTime != row['localtime'] ):
                        raise LocalError ('Found modified file %s' % filepath)
                    
                    # assuming that everything is up-to-date and ok, 
                    # but update is needed
                    self._logger.debug ('Getting the delta')
                    delta = self._RemoteCaller.GetDelta ( lastrev, row['lastrev'] )            
                    self._logger.debug ( "Using delta information" )
                    tmpp,tmpf = os.path.split (filepath)
                    tmpfile = os.path.join ( tmpp, '.'+tmpf+'-'+str(lastrev)+'.tmp')
                    os.rename(filepath, tmpfile)
                    delta.patch (tmpfile, filepath)
                    os.remove(tmpfile)
                else:
                    if not isdir:
                        self._logger.debug('Getting the file (revision %s)' , str(lastrev) )
                        data = self._RemoteCaller.GetFullRevision ( lastrev )
                        with open ( filepath , "wb" ) as f:
                            f.write(data.data)
                    else:
                        # Special case for directories
                        self._logger.info('Creating folder %s', filepath)
                        os.mkdir(filepath)
                        modifiedTime = os.stat(filepath).st_mtime
                        c.execute ('''insert into files 
                            (path, file, lastrev, timestamp, localtime, isdir)
                            values (?,?,?,?,?,1)''' , 
                            (path,file,lastrev,serverTimestamp,modifiedTime) 
                            )
                        continue
                # check and save metadata
                with open (filepath, "rb") as f:
                    computedChksum = adler32(f.read())
                computedSize = os.stat(filepath).st_size
                modifiedTime = os.stat(filepath).st_mtime
                if ( (  serverSize and   serverSize != computedSize  ) or
                     (serverChksum and serverChksum != computedChksum) ):
                    raise LocalError('Metadata error on received file %s' % filepath)
                c.execute ('''insert into files 
                    (path, file, lastrev, timestamp, localtime, chksum, size)
                    values (?,?,?,?,?,?,?)''' , 
                    (path,file,lastrev,serverTimestamp,modifiedTime,
                        computedChksum, computedSize) 
                    )
        self._lockTimestamp()
    
    def UpdateToServer(self):
        '''
        This function walks the repository looking for modified files (comparing
        its modified time and size with the local database).
        '''
        os.chdir(self._localpath)
        self.CheckExistantFiles()
        self.CheckDeletedFiles()