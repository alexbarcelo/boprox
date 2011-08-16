'''
Created on Jul 30, 2011

@author: marius
'''

import rsa
from pyasn1.codec.der.decoder import decode as derdecode
from base64 import b64decode
import random
import sqlite3
from datetime import datetime
import os.path

TOKENLENGTH = 16
# A bit more than base64, to generate a very random token 
uppercase  = [chr(65+i) for i in range(0,26)]
lowercase  = [chr(97+i) for i in range(0,26)]
numbers    = [chr(48+i) for i in range(0,10)]
other      = ['+','=','<','>','-','.','!','(',')','[',']','*',';','_']
# the '/' character gives invalid URL. Also invalid '?'
# ':' is valid (it works) but it is confusing:
# a token ``to:k:en'' becomes a URL https://user:to:k:en@localhost:port)

TOKENCHARS = []
TOKENCHARS.extend(uppercase)
TOKENCHARS.extend(lowercase)
TOKENCHARS.extend(numbers)
TOKENCHARS.extend(other)

BASEMASK   =  0x03
READ       =  0x01 
WRITE      =  0x02
DELEGMASK  =  0x0C
DELEGREAD  =  0x04
DELEGWRITE =  0x08

class UserSQLiteAuth:
    '''
    Class to check user permissions --SQLite backend
    '''

    def __init__(self, dbusers):
        '''
        Constructs the class that can check the permissions of a user
        
        @param dbusers: String containing the sqlite file
        '''
        # default is no-timeout of token password
        self._timeout = -1 
        self._constusers = {}
        self._randgen = random.SystemRandom()
        
        self._dbusers = sqlite3.connect(dbusers ,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._dbusers.row_factory = sqlite3.Row
        # Everything should be ascii, and publickey will be quite large
        # (performance reasons)
        self._dbusers.text_factory = str
        with self._dbusers as c:
            c.execute ( '''create table if not exists
                users ( 
                    uid integer primary key autoincrement,
                    username text unique not null,
                    publickey text
                    )
                ''')
            c.execute ( '''create table if not exists
                permissions (
                    idperm integer primary key autoincrement,
                    uid integer,
                    path text,
                    permcode integer
                    )
                ''')
        
        self._dbtoken = sqlite3.connect ( ":memory:" ,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._dbtoken.row_factory = sqlite3.Row
        # Everything should be ascii too. And we do not want to mess around
        # strange encodings for token and username.
        self._dbtoken.text_factory = str
        with self._dbtoken as c:
            c.execute ( '''create table tokens (
                username text primary key,
                timestamp timestamp,
                token text
                )''')
    
    def getUID(self, user):
        '''
        Give the user identificator (uid) for a given name. Standard database
        users start at 1001 (real identificator = 1000 + uid database column)
        '''
        # hardcoded admin
        if user == 'admin':
            return 0
        
        with self._dbusers as c:
            row = c.execute ('select uid from users where username=?' ,
                (user,) ).fetchone()
        if not row:
            return -1
        return 1000+row['uid']
    
    def checkPerm(self, user, path, idperm):
        '''
        Check the user permissions
        
        @param user: Name of the user
        @param path: String of the folder to be checked
        @param idperm: Identifier of the permissions being checked
        @return: True if the user can do that, false otherwise
        '''
        # Hardcoded admin
        if user == 'admin':
            return True
        with self._dbusers as c:
            rowUser = c.execute ('select uid from users where username=?' , 
                (user,) ).fetchone()
            if not rowUser:
                return False
            cur = c.execute ('''select path,permcode from permissions 
                where uid=?''' , (rowUser['uid'],) ) 
        BaseChecked  = False
        DelegChecked = False
        
        for row in cur:
            # First check if the path in the row is a subfolder of asked path
            if path.startswith(row['path']):
                # Check that this (or any previous one) has enough base permissions
                if ( not BaseChecked and 
                     idperm & BASEMASK  <= row['permcode'] & BASEMASK):
                    BaseChecked = True
                # Check that this (or any previous one) has enough delegation permissions
                if ( not DelegChecked and
                     idperm & DELEGMASK <= row['permcode'] & DELEGMASK ):
                    DelegChecked = True
                # If at this point we have enough permissions, then can return
                if DelegChecked and BaseChecked:
                    return True
        # Couldn't find enough permissions in the database for this user and path
        return False
        
    def setTimeout (self, timeout):
        '''
        Set the timeout of the tokens. Default is -1 (no timeout).
        
        @param timeout: Timeout in seconds
        '''
        self._timeout = timeout
        
    def setConstUsers (self, users):
        '''
        Set a list of "persistent" users (users with a constant password).
        This is less secure than public/private key and tokens, 
        should be used for debugging and/or admin purposes. At this moment,
        this only is used for adding an ``admin'' that is (hardcoded) 
        administrator of everything.
        
        @param users: List of tuples [ (user1,pass1) , (user2,pass2) ... ]
        or simply a tuple (user,pass)
        '''
        userlist = None
        if type(users) == tuple:
            userlist = [users]
        elif type(users) == list:
            userlist = users
        else: 
            raise TypeError
        for userpass in userlist:
            self._constusers[userpass[0]] = userpass[1]
            
    def _getMaxPermissions (self, perm1, perm2):
        '''
        Get the maximum int of permissions between the two parameters. 
        Return it.
        
        (Uber simple function, but in case the implementation changes...)
        '''
        return perm1 | perm2
        
    def GetPermissions (self, user, dirpath):
        '''
        Check the permissions of a user in a certain path. The maximum 
        permissions that this user has (a user may have more than one 
        effective permission, more specific as the filesystem goes deep).
        
        @param user: Username. No check is done, the server has to call to 
        UserOk before doing any real operation.
        @param dirpath: Path of a folder. The path should have been sanitized
        before calling this function. The path cannot be a file path.
        @return: A permission int, containing the maximum permissions of user 
        in this folder. 0 if the user has no permissions.
        '''
        with self._dbusers as c:
            rowUser = c.execute ('select uid from users where user=?', 
                (user,) ).fetchone()
            if not rowUser:
                return -1
            cur = c.execute('select * from permissions where uid=?',
                (rowUser['uid'],) )
        currperm = 0
        for row in cur:
            if dirpath.startswith(row['path']):
                self._getMaxPermissions(currperm, row['permcode'])
        return currperm
        
    def UserOk(self,user,secret):
        '''
        Check if the user and password are correct.
        
        @param user: Username
        @param secret: Password token
        @return: True when the user is known and the password token is correct,
        False otherwise
        '''
        # Shortcut for constant users
        if user in self._constusers and self._constusers[user]==secret:
            return True
        
        with self._dbtoken as c:
            row = c.execute ('''select timestamp as "ts [timestamp]" from tokens 
                where username=? and token=?
                ''', (user, secret) ).fetchone()
        if not row:
            # No user with this token, not authenticated
            return False
        
        if self._timeout > 0:
            # Check if the token has timeout
            tdelta = datetime.now() - row['ts'] 
            if tdelta.total_seconds() > self._timeout:
                # Timeout! Delete row and return False
                with self._dbtoken as c:
                    c.execute ( 'delete from tokens where username=?',
                        (user,) )
                    return False
        return True
    
    def _genToken (self):
        '''
        Create a new token. The random source is random.SystemRandom
        (should be enough). Changing the token type and length should not
        be a problem. Be careful on security issues.

        @return: A string that can be used as a password token --random 
        and secure. Secure means that a user should not be able to collide
        them or obtain a pattern of generation.
        '''
        token = ''
        for i in range(0,TOKENLENGTH):
            token += random.choice(TOKENCHARS)
        return token
    
    def _encryptToken (self, token, publickey):
        '''
        Return encrypted token
        
        @param token: An arbitrary string to be encrypted. Assumed to be "quite"
        random, no padding is done nor further security considerations.
        @param publickey: A string containing a PEM public key, normally 
        multiline. We assume that there is NO header. Normally this value is 
        retrieved from inside the database
        
        @return a string containing the token encrypted, ready to be 
        sent to the user
        '''
        derbits = b64decode(publickey)
        pubkey  = derdecode(derbits)[0]
        # The PEM should be in this schema
        key = { 'n': int(pubkey[0]) , 'e': int(pubkey[1]) }
        return rsa.encrypt(token, key)

    def getNewToken (self, user):
        '''
        Using the known public key of a user, generate a random token
        and return it encrypted for the user, after adding it to the list
        of current tokens
        
        @param user: Known username (the public key of the user must in 
        the sqlite file)
        '''
        with self._dbusers as c:
            row = c.execute ('''select publickey from users 
                where username=?''' , (user,) ).fetchone()
        # If row is none, the user is unknown
        if not row:
            return None
        
        token = self._genToken()
        
        with self._dbtoken as c:
            c.execute ( 'delete from tokens where username=?', (user,))
            c.execute ( '''insert into 
                tokens 
                    (username, timestamp, token)
                values
                    (?,?,?)
                ''' , (user,datetime.now(),token) )
        
        etoken = self._encryptToken ( token , row['publickey'] )
        
        return etoken