'''
Created on Aug 3, 2011

@author: marius
'''

import xmlrpclib

if __name__ == '__main__':
    serverAuth = xmlrpclib.ServerProxy("https://127.0.0.1:1356")
    print "Trying to connect, sending ping: ...", serverAuth.ping() 
