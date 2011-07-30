'''
Created on Jul 30, 2011

@author: marius
'''

class UserSQLiteAuth:
    '''
    Class to check user permissions --SQLite backend
    '''

    def __init__(self, dbusers):
        '''
        Constructs the class that can check the permissions of a user
        
        @param dbusers: String containing the sqlite file
        '''
        # TODO
        pass
    
    def UserOk(self,user,secret):
        '''
        Check if the user and password are correct.
        
        @param user: Username
        @param secret: Password
        @return True when the user is known and the password is correct,
        False otherwise
        '''
        
        # We use a dict, quick and ugly hack
        # TODO
        userPassDict = {"admin":"alsonopass",
                "noadmin":"alsanopass"}
        if user in userPassDict:
            if userPassDict[user] == secret:
                return True
        return False
