import xmlrpc.client
import os
import time
from datetime import datetime
import sqlite3
import pickle
from zlib import adler32
import pyrsync

import logging

# debugging now!
logger = logging.getLogger('minimalclient')
logger.setLevel(logging.DEBUG)

REPOCLIENT = "./NoNameBox"
DBFILE = "./ClientSQL"
HASHESCLIENT = "./NoNameClientHashes"

conn = None
server = None

def look4files():
    os.chdir ( REPOCLIENT )
    for dirpath, dirnames, filenames in os.walk(os.curdir):
        # first, eliminate directories which haven't been modified
        for dircheck in dirnames:
            row = conn.execute ( "select * from dirs where dirpath=?",
                (dircheck,) ).fetchone()
                
            if row == None:
                #unattended? not yet added? ToDo
                pass
            elif (row['localtime'] ==                                 
                os.stat(os.path.join(dirpath,dircheck).st_mtime)) and (row['sync'] == 1):
                dirnames.remove(dircheck)
                
        # Ignore the files with a dot prefixing it (hidden files in 
        # unix operative systems)
        # Also, to avoid multiOS problems, we do not allow any
        # directory separator in filename
        def fileAcceptor( filenames ):
            for filename in filenames:
                if filename[0] != '.':
                    for pathSep in ['/' , '\\' ]:
                        badFile = False
                        if filename.find( pathSep ) != -1:
                            badFile = True
                            break
                    if not badFile:
                        yield filename
            
        for filecheck in fileAcceptor(filenames):
            # Some further check would be more ellegant, although this 
            # should work on unix and windows due to the previous filtering 
            # of bad characters, only path-slashes will be found here
            filepath = os.path.join(dirpath,filecheck).replace('\\' , '/')
            modifiedTime = os.stat(filepath).st_mtime
            
            row = conn.execute ( "select * from files where path=?",
                (filepath,) ).fetchone()
                
            if row == None:
                # New file!
                logger.info('Detected new file: %s' , filepath )
                
                # Get size
                computedSize = os.stat(filepath).st_size
                
                with open ( filepath , "rb" ) as f:
                    # Get checksum
                    intChecksum = adler32(f.read())
                    bytesChecksum = xmlrpc.client.Binary (intChecksum.to_bytes(4, byteorder='big'))
                    # Get data
                    f.seek(0)
                    dataToSend = xmlrpc.client.Binary(f.read())
                
                # Send everything to server
                logger.debug( "Transfering new file to server" )
                ret = server.SendNewFile(filepath, dataToSend, bytesChecksum, computedSize)
                logger.debug ( "Sent, response: %s" , repr(ret) )
                
                if type(ret) == int:
                    # do something about the return, it's an error
                    #... ToDo
                    pass
                else:
                    # Everything went well, we have the revision id
                    with conn as c:
                        cur = c.execute ( '''insert into files 
                            (path, deleted, lastrev, timestamp, localtime, chksum, size, conflict) 
                            values 
                            (?,0,?,?,?,?,?,0)''' , (filepath, ret[0], ret[1],
                                modifiedTime, intChecksum, computedSize )
                            )
                        
                        fileId = cur.lastrowid
                        
                    # Save the hashes for later use
                    try:
                        with open(filepath, "rb") as f:
                            with open(os.path.join(HASHESCLIENT, str(fileId) ) , "wb" ) as fdump:
                                pickle.dump(pyrsync.blockchecksums(f), fdump)
                    except:
                        # mmm some error checking?
                        pass

            elif row['localtime'] != modifiedTime:
                # Here! Some file needs care
                logger.info('Detected modified file: %s' , filepath )
                
                with open ( os.path.join(HASHESCLIENT , str(row['idfile']) ) , "rb" ) as f:
                    hashes = pickle.load(f)

                # Get size
                computedSize = os.stat(filepath).st_size
                
                with open ( filepath , "rb" ) as f:
                    # Get checksum
                    intChecksum = adler32(f.read())
                    bytesChecksum = xmlrpc.client.Binary (intChecksum.to_bytes(4, byteorder='big'))
                    # Get delta
                    f.seek(0)
                    delta = pyrsync.rsyncdelta ( f , hashes )
                
                logger.debug ( "Last revision: %s" , repr(row['lastrev']) )
                logger.debug ( "Delta: %s" , repr(delta) )
                logger.debug ( "Checksum (int): %s" , repr(intChecksum) )
                logger.debug ( "Checksum (bytes): %s" , repr(bytesChecksum) )
                logger.debug ( "Size: %s" , repr(computedSize) )
                ret = server.SendDelta ( row['lastrev'] , delta , bytesChecksum , computedSize )
                logger.debug ( "Sent, response: %s" , repr(ret) )
                
                if type(ret) == int:
                    # Do something about this error
                    #... ToDo
                    pass
                else:
                    with conn as c:
                        #c.execute ( '''update files set lastrev=?, hardexist=0 where idfile=?''' ,
                        cur = c.execute ( '''update files set 
                            lastrev=?, timestamp=?, localtime=?, chksum=?, size=?
                            where idfile=?
                            ''' , ( ret[0],ret[1],modifiedTime, intChecksum, computedSize, row['idfile'] )
                            )
                    
                    # update the hashes
                    with open(filepath, "rb") as f:
                        with open(os.path.join(HASHESCLIENT, str(row['idfile']) ) , "wb" ) as fdump:
                            logger.debug ( "Uptading hash file %s" , str(row['idfile']) )
                            pickle.dump(pyrsync.blockchecksums(f), fdump)
    

def executeClient ():
    global REPOCLIENT
    global DBFILE
    global HASHESCLIENT
    
    REPOCLIENT   = os.path.abspath ( REPOCLIENT )
    DBFILE       = os.path.abspath ( DBFILE )
    HASHESCLIENT = os.path.abspath ( HASHESCLIENT )
    
    inittime = os.stat(REPOCLIENT).st_mtime
    global conn
    global server
    conn = sqlite3.connect(DBFILE,
        detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    server = xmlrpc.client.ServerProxy(
        "https://admin:alsonopass@localhost:1356" , 
        # this is needed because we work with datetime-type timestamp
        use_datetime=True
        )

    try:
        # create things if not already exists
        with conn as c:
            c.execute('''create table if not exists 
                files(
                    idfile integer primary key autoincrement,
                    path text unique,
                    deleted boolean default 0,
                    lastrev integer,
                    timestamp timestamp,
                    localtime real,
                    chksum integer default null,
                    size integer default null,
                    conflict boolean default 0
                    )
                ''')
                
            c.execute('''create table if not exists
                dirs(
                    iddir integer primary key autoincrement,
                    dirpath text unique,
                    sync boolean default 1,
                    localtime real
                    )
                ''')
    except:
        # should do something here . . .
        print ("Should do something here - SQLite error")
        raise
    
    # Get new changes
    with conn as c:
        try:
            timestamp = c.execute ( '''select timestamp as "ts [timestamp]" 
                from files order by timestamp desc''' ).fetchone()['ts']
        except:
            timestamp = datetime.min
    logger.debug('Getting changes since %s' , timestamp )
    pathForChanges = server.GetFileNews( timestamp )
    
    # now get each change
    for p in pathForChanges:
        lastrev = server.GetLastRev( p )
        
        logger.debug("Changes for file id: %s (revision: %s)" , 
            p , str(lastrev) )
            
        #if exists, get the delta, 
        #if not exists, get the file
        row = conn.execute ( '''select * from files 
            where path=?''' , (p,) ).fetchone()
        if row:
            logger.debug ('Getting the delta')
            
            if lastrev < 0:
                logger.warning ( 'Error %s when receiving last revision for %s' ,
                    str(lastrev), p )
                break
            
            delta = server.GetDelta ( lastrev, row['lastrev'] )
            
            if type(delta) == int:
                logger.warning ( "Error received %s when waiting for delta" ,
                    str(delta) )
                break
            
            logger.debug ( "Using delta information" )
            ############### ToDo ###############
            
        else:
            logger.debug('Getting the file (revision %s)' , str(lastrev) )
            data = server.GetFullRevision ( lastrev )
            if type(data) == int:
                logger.warning ('Error %s received instead of file' ,
                    str(data) )
                break
                    
            with open ( os.path.join(REPOCLIENT , p) , "wb" ) as f:
                f.write(data.data)
                
            ############### ToDo ###############
            ### all the metadata, ¡here!
    
    logger.info ( 'Proceeding to main loop' )
    while True:
        
        if os.stat(REPOCLIENT).st_mtime != inittime:
            inittime = os.stat(REPOCLIENT).st_mtime
            
            logger.info('Some modification detected')
            look4files()
            
        time.sleep(2)
    
    

if __name__ == '__main__':  
    executeClient()
