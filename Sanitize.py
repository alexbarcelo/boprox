'''
Created on Aug 9, 2011

@author: marius
'''

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

# Plus something else --posix special folders and empty names
FORBIDDEN_NAMES.extend(['.','..',''])

class Error(Exception):
    def __init__(self, char, msg='Found this, not allowed in context: '):
        self.char = char
        self.msg  = msg
    def __str__(self):
        return self.msg + repr(self.char)
