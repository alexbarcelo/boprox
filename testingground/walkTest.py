#!/usr/bin/python
'''
Created on Aug 4, 2011

@author: marius
'''
import boprox.client
import logging
import os.path

# Same config as sample-client, but verbose on a walk call and doesn't 
# update anything 

HOST='localhost'
PORT=1356

PASS='IChangedIt'

HOME=os.path.expanduser('~')
REPODIR=os.path.join(HOME,'boprox-repo')
DOTBOPROX = '.boprox'
DBFILE=os.path.join(HOME,DOTBOPROX,'clientdb.sqlite')
HASHESDIR=os.path.join(HOME,DOTBOPROX,'hashesdir')

logging.basicConfig(level=logging.DEBUG)

def main():
    adminrepo = boprox.client.SingleRepoClient(host=HOST, port=PORT,
        username='admin', permatoken=PASS, 
        dbfile=DBFILE, localpath=REPODIR, hashesdir=HASHESDIR)
    
    for (a,b,c) in adminrepo.LocalWalk():
        print "Walk test, 1st value:", a
        print "Walk test, 2nd value:", b
        print "Walk test, 3rd value:", c

if __name__ == '__main__':
    main()
