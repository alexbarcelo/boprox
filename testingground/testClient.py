'''
Created on Aug 4, 2011

@author: marius
'''
import sys
# hack to import client
sys.path.append('../')
import client
from time import sleep
import logging

logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':    
    firstrepo = client.SingleRepoClient(host='localhost', port=1356,
        username='johnsmith', key=client.getKeyFromPEMfile('./johnsmith.rsa'), 
        dbfile='./clientdb.sqlite', localpath='repoclient')
    
    print "Token received from server:", firstrepo._token
    
    print firstrepo.ping()
    
    ## This test worked ok, commenting it now to speed-up things
    #sleep(5)
    #print firstrepo.ping()
    #
    #print "Last token:" , firstrepo._token
    
    print "Now using admin account"
    
    adminrepo = client.SingleRepoClient(host='localhost', port=1356,
        username='admin', permatoken='IChangedIt', dbfile='./clientdb.sqlite',
        localpath='./repoclient', hashesdir='./hashesclient')
    
    print "Doing an admin-ping"
    print adminrepo.ping()
    
    adminrepo.UpdateToServer()
    adminrepo.UpdateFromServer()