#!/usr/bin/python
'''
Created on Aug 4, 2011

@author: marius
'''
import sys
import boprox.client
from time import sleep
import logging
import os.path

HOST='localhost'
PORT=1356

PASS='IChangedIt'

HOME=os.path.expanduser('~')
REPODIR=os.path.join(HOME,'boprox-repo')
DOTBOPROX = '.boprox'
DBFILE=os.path.join(HOME,DOTBOPROX,'clientdb.sqlite')
HASHESDIR=os.path.join(HOME,DOTBOPROX,'hashesdir')

logging.basicConfig(level=logging.INFO)

def main():
    adminrepo = boprox.client.SingleRepoClient(host=HOST, port=PORT,
        username='admin', permatoken=PASS, 
        dbfile=DBFILE, localpath=REPODIR, hashesdir=HASHESDIR)
    
    adminrepo.UpdateToServer()
    adminrepo.UpdateFromServer()
    adminrepo.CheckDeletedFiles()

if __name__ == '__main__':
    main()
