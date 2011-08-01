'''
Created on Jul 30, 2011

@author: marius
'''

import Crypto
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
        
        self._dbkeys = sqlite3.connect(dbusers ,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._dbkeys.row_factory = sqlite3.Row
        with self._dbkeys as c:
            c.execute ( '''create table if not exists
                users ( 
                    username text primary key,
                    publickey text
                    )
                ''')
        
        self._dbtoken = sqlite3.connect ( ":memory:" ,
            detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        self._dbkeys.row_factory = sqlite3.Row
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
        @param secret: Password
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