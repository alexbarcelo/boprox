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

import logging
from foolscap.test.test_appserver import CLI

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
        str = '\nError in client communication with server\n'
        str+= '-----------------------------------------\n'
        str+= 'Return code: ' + self.retcode
        if self.call:
            str += '\nRemote call in progress: ' + self.call
        if self.moreinfo:
            str+= '\n-----------------------------------------\n'+self.moreinfo
        return str



class SingleRepoClient:
    def __init__(self, host, port, username, dbfile, localpath, 
        remotepath = '.', key=None, permatoken=None):
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
        self._localpath  = localpath
        self._remotepath = remotepath
        
        # initialize logging facility
        self._logger = logging.getLogger('boprox-client')
        self._logger.setLevel(logging.DEBUG)
        
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

    def _requestToken(self):
        # If we have permatoken, then it is in _token and we do nothing
        if self._permatoken == False:
            # Otherwise, do the RSA standard procedure with the server.
            etoken = self._anonConn.requestToken(self._username)
            self._token = rsa.decrypt(etoken, self._key)
        self._authURL = "https://%s:%s@%s:%s" % (self._username, self._token, 
            self._host, str(self._port) )
        self._authConn = ServerProxy(self._authURL)
        
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
    
    def UpdateFromServer(self):
        '''
        Get all changed things from the server (last-timestamp system) and
        update everything that is changed.
        
        It is safe to call this function periodically, when there are no changes
        it is not network-intensive.
        '''
        pass            
    
    def UpdateToServer(self):
        '''
        This function walks the repository looking for modified files (comparing
        its modified
        '''
        pass