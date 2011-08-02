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
        
        self._dbkeys = sqlite3.connect(dbusers ,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._dbkeys.row_factory = sqlite3.Row
        # Everything should be ascii, and publickey will be quite large
        # (performance reasons)
        self._dbkeys.text_factory = str
        with self._dbkeys as c:
            c.execute ( '''create table if not exists
                users ( 
                    username text primary key,
                    publickey text
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
        should be used for debugging and/or admin purposes.
        
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
        
    def UserOk(self,user,secret):
        '''
        Check if the user and password are correct.
        
        @param user: Username
        @param secret: Password token
        @return True when the user is known and the password token is correct,
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
        # 64 bits of random bits, hex representation
        return hex(self._randgen.getrandbits(64))[2:-1]
    
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
        rsa.encrypt(token, key)

    def getNewToken (self, user):
        '''
        Using the known public key of a user, generate a random token
        and return it encrypted for the user, after adding it to the list
        of current tokens
        
        @param user: Known username (the public key of the user must in 
        the sqlite file)
        '''
        with self._dbkeys as c:
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