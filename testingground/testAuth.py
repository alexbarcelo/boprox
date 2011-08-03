'''
Created on Aug 3, 2011

@author: marius
'''

import xmlrpclib
import rsa
from pyasn1.codec.der.decoder import decode as derdecode
from base64 import b64decode

if __name__ == '__main__':
    serverAuth = xmlrpclib.ServerProxy("https://127.0.0.1:1356")
    print "Trying to connect, sending ping: ...", serverAuth.ping() 
    
    print "Requesting token..."
    etoken = serverAuth.requestToken('johnsmith')
    if type(etoken) == int: 
        print "Error: ", etoken
        exit(-1)
    
    print "Encrypted token received:"
    print etoken[0:76]
    print '...'
    
    # Open the sample key, read the private key, and try to decrypt
    privdata = ''
    with open('johnsmith.rsa' , 'r') as f:
        for line in f:
            if line[0:5] == '-----':
                pass
            else:
                privdata += line
    derdata = b64decode(privdata)
    privkey = derdecode(derdata)[0]
    key = {'d': int(privkey[3]) , 'p': int(privkey[4]), 'q':int(privkey[5])}
    
    token = rsa.decrypt(etoken, key)
    
    print 'Decrypted token:'
    print token
    
    authURL = 'https://' + 'johnsmith' + ':' + token + '@' + '127.0.0.1' + ':' + '1356' 
    serverConn = xmlrpclib.ServerProxy(authURL)
    
    print "Sending ping from authorized user. Response:"
    print serverConn.ping()
    
    serverConn = xmlrpclib.ServerProxy("https://johnsmith:notpass@127.0.0.1:1356")
    print "Sending ping from unauthorized user. Response:"
    try:
        print serverConn.ping()
    except xmlrpclib.ProtocolError as e:
        if e.errcode == 401:
            print "Authentication error 401, as expected"
        else:
            print "Not expected error:", e.errmsg
    
    serverConn = xmlrpclib.ServerProxy("https://admin:IChangedIt@127.0.0.1:1356")
    print "Sending ping from the admin account (enabled in configuration file)"
    print serverConn.ping()