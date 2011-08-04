'''
Created on Aug 4, 2011

@author: marius
'''

import rsa
from pyasn1.codec.der.decoder import decode as derdecode
from base64 import b64decode
from xmlrpclib import ServerProxy, Binary
import sqlite3
import os.path


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

class SingleRepoClient:
    def __init__(self, host, port, username, key, dbfile, localpath, remotepath = '.'):
        '''
        Create a sort-of API to connect with one server (one repository)
        
        @param host: Host to connect
        @param port: Port to connect
        @param username: Name to authenticate
        @param key: RSA key used for authentication
        @param dbfile: sqlite database file to track files and revisions
        @param localpath: Local path used to synchronize
        @param remotepath: Remote path to synchronize with (default: .). Useful
        for shared resources or multiuser servers.
        '''
        # initialize values
        self._host = host
        self._port = port
        self._username = username
        self._key = key
        self._localpath  = localpath
        self._remotepath = remotepath
        
        # open database
        self._db = sqlite3.connect(dbfile,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._db.row_factory = sqlite3.Row
        
        # create things if they do not exist alreay
        with self._db as c:
            c.execute('''create table if not exists 
                files(
                    idfile integer primary key autoincrement,
                    path text unique,
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
        self._anonConn = ServerProxy(anonURL, use_datetime=True)
        etoken = self._anonConn.requestToken(self._username)
        self._token = rsa.decrypt(etoken, key)
        