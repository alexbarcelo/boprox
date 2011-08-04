'''
Created on Aug 4, 2011

@author: marius
'''

if __name__ == '__main__':
    # ugly hack, importing in another directory was equally ugly 
    execfile ('../client.py')
    
    firstrepo = SingleRepoClient(host='localhost', port=1356,
        username='johnsmith', key=getKeyFromPEMfile('./johnsmith.rsa'), 
        dbfile='./clientdb.sqlite', localpath='./repoclient')
    
    print "Token received from server:", firstrepo._token