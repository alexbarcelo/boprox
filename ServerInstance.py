import os
from datetime import datetime
import sys
from zlib import adler32
import pickle
import sqlite3
import logging
import pyrsync
import xmlrpc

# debugging now!
logger = logging.getLogger('minimalclient')
logger.setLevel(logging.DEBUG)

# Configure below
REPO='./NoNameRepo'
HASHESDIR='./NoNameHashes'
DELTADIR='./NoNameDeltas'
HARDDIR='./NoNameHard'
DBFILE="./NoNameSQLite"
# Configure above

# Type of errors
ERR_GENERIC  = -1
ERR_TODO     = -2
ERR_EXISTANT = -10
ERR_SQL      = -11
ERR_CHKSUM   = -12
ERR_SIZE     = -13
ERR_FS       = -14 # filesystem, quite general
ERR_OUTDATED = -15
ERR_DELETED  = -16
ERR_CANNOT   = -17
ERR_NOTEXIST = -18
ERR_INTERNAL = -19

# What can a revision come from:
REV_NEWFILE      = 0
REV_COPYFILE     = 1
REV_MOVEFILE     = 2
REV_DELETEFILE   = 3
REV_ROLLEDBACK   = 4
REV_MODIFIED     = 5

class ServerInstance():
    def __init__(self):
        import string
        self.python_string = string
        # Test existance of SQLite file
        try:
            self.__conn = sqlite3.connect(DBFILE, 
                detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
            self.__conn.row_factory = sqlite3.Row

            # create things if not already exists
            with self.__conn as c:
                c.execute('''create table if not exists 
                    files(
                        idfile integer primary key autoincrement,
                        path text unique,
                        deleted boolean default 0,
                        lastrev integer
                        )
                    ''')
                c.execute('''create table if not exists
                    revisions(
                        idrev integer primary key autoincrement,
                        idfile integer not null,
                        timestamp timestamp,
                        fromrev integer,
                        rollbackrev integer default null,
                        typefrom integer default 0,
                        chksum integer default null,
                        size integer default null,
                        hardexist boolean default 0
                        )
                    ''')
        except:
            # should do something here . . .
            print ("Should do something here - SQLite error")
            pass
            
            
    def SendDelta(self, idRev, delta, binchksum = None, size = 'NULL'):
        """Send delta to server (see rsync algorithm)"""        
        tsnow = datetime.now()
        # get real checksum
        try:
            chksum = int.from_bytes( binchksum.data , byteorder='big' )
        except AttributeError:
            chksum = 'NULL'
        
        logger.debug("Receiving delta, now()=%s" , repr(tsnow) )
        logger.debug("Chksum received: %s" , repr(chksum) )
        #check if everything is ok
        with self.__conn as c:
            logger.debug ( "Getting row of revisions . . ." )
            rowRev = c.execute ( "select * from revisions where idrev=?" ,(idRev,)).fetchone()
            logger.debug ( "Getting row of file information . . ." )
            rowFile = c.execute ( "select * from files where idfile=?" ,
                (rowRev['idfile'],) ).fetchone()
            if rowFile['lastrev'] != idRev:
                logger.info("Error: Outdated client")
                return ERR_OUTDATED                
            if rowFile['deleted'] == 1:
                logger.info("Error: file in deleted state")
                return ERR_DELETED
            
            logger.debug ( "Inserting new revision into database . . ." )
            try:
                cur = c.execute ( '''insert into revisions 
                    (idfile, timestamp, fromrev, typefrom, chksum, size, hardexist) values
                    (?,?,?,?,?,?,0)''' , (rowRev['idfile'], tsnow , idRev, REV_MODIFIED,chksum, size ) )
                
                nextRev = cur.lastrowid
            
                c.execute ( '''update files set lastrev=? where idfile=?''' ,
                    (nextRev , rowRev['idfile'] ) )
            except:
                raise
                return ERR_SQL
        
        logger.debug ( "Going to write the delta file" )
        #now, save the delta
        with open ( os.path.join(DELTADIR,str(nextRev)) , "wb" ) as f:
            pickle.dump(delta, f)
        
        logger.debug ( "Latest revision: %s" , int(nextRev) )
        return nextRev, tsnow
    
    def getDeltasSinceEvent ( self, eventType , condition , startRev ):
        """Get all the deltas since a given "event" (sqlite column)
        The row that satisfies the condition is NOT added to the list
        (be careful with idrev vs fromrev)
        Return the best error code if something goes wrong
        """
        # thinking in yield-ing... but if there is an error, 
        # then everything would seem more awkward
        # Maybe is more pytonic, and raise when needed
        deltaHistory = [ startRev ]
        with self.__conn as c:
            revRow = c.execute ( '''select * from revisions
                where idrev=?''' , (startRev,) ).fetchone()
            while revRow[eventType] != condition:
                revRow = c.execute ( '''select * from revisions 
                    where idrev=?''' , 
                    (revRow['fromrev'],) ).fetchone()
                if not revRow:
                    # asking for impossible connexion
                    return ERR_CANNOT
                    
                logger.debug ( 'This row %s has %s in %s' , 
                    str(revRow['idrev']) , str(revRow[eventType]) , 
                    eventType )
                    
                deltaHistory.append( revRow['idrev'] )
        return deltaHistory
        
    def GetDelta(self, idRev, idFromRev):
        """Get delta (see rsync algorithm) to jump between two revisions"""
        
        #if it's the easy way, we do it the easy way (most likely to hapen)
        with self.__conn as c:
            revRow = c.execute( "select * from revisions where idrev=?" , idRev).fetchone()
        
        if (revRow['fromrev'] == idFromRev) and (revRow['fromtype'] == REV_MODIFIED):
            #yes, we are lucky!
            try:
                with open( os.path.join(DELTADIR,str(idRev)) , "rb") as f:
                    delta = pickle.load(f)
            except:
                delta = ERR_FS
            return delta
        else:
            if revRow['fromtype'] != REV_MODIFIED:
                # asking for an inexistant delta 
                return ERR_CANNOT
              
            # 1st: check that exists a chain of non-deletions between 
            # this two revisions (save the first hardcopy for later)
            deltaList = self.getDeltasSinceEvent ( 'idrev' , idFromRev , idRev )
            if type(deltaList) == int:
                return deltaList
                
            # 2nd: try to join everything
            try:
                val = deltaList.pop()
                logger.debug ( "Getting delta for %s" , str(val) )
                delta = pickle.load( os.path.join(
                    DELTADIR , str( val ) 
                    ) )
                while deltaList:
                    pyrsync.joindeltas ( delta , pickle.load( 
                        os.path.join( DELTADIR , str(deltaList.pop() ) )
                        ) )
            except:
                return ERR_FS
                    
            # 3rd: Send delta
            return delta

    def GetMetaInfo ( self, rev , force=False):
        """Get the metainfo (actually size and chksum) of some revision
        
        force = True if want to get this values (a hard copy will be done
        if necessary). If not forced, -1 values will be returned if no 
        hard copy exists)
        """
        
        pass
        
    def GetLastRev(self, filepath):
        """Get the id of the last revision of some file
        Get it by the identificator of """
        with self.__conn as c:
            row = c.execute ( '''select lastrev from files
                where path=?''' , (filepath,) ).fetchone()
        if row == None:
            return ERR_NOTEXIST
        return row['lastrev']
        
    def GetFileNews(self, timestamp):
        """Get a list of changes since timestamp (idFile affected)"""
        logger.debug('Getting news from %s' , repr(timestamp) )
        with self.__conn as c:
            cur = c.execute ( '''select idfile, timestamp as "ts [timestamp]" 
                from revisions order by timestamp desc''' )
        logger.debug ('Cursor: %s' , repr(cur) )
        idsChanged = set()
        row=cur.fetchone()
        logger.debug ('First row: %s' , repr(row) )
        while row:
            logger.debug ( "This row has timestamp %s (type %s), for idfile %s" , 
                repr(row['ts']), type(row['ts']) , str(row['idfile']) )
            if row['ts'] > timestamp:
                idsChanged.add( row['idfile'] )
            else:
                break
            row = cur.fetchone()
        
        logger.debug ( "Getting pathnames for modified files" )
        pathList = []
        for i in idsChanged:
            with self.__conn as c:
                pathList.append ( c.execute ( '''select path
                    from files where idfile=?''', (i,) ).fetchone()['path'] )
        
        logger.debug( "Changed files: %s" , repr(pathList) )
            
        return pathList
        
        
    def MakeDir (self, path ):
        """Create directory ``path''"""
        return ERR_TODO
    
    
    def SendNewFile (self, newfile, bindata , chksum = None, size = None):
        """Create a NON-EXISTING file in *filepath*, with *data* contents"""
        
        filepath = os.path.join(REPO,newfile)
        logger.debug ( "Receiving file %s, saving as %s" , newfile , filepath )
        
        ##full of bugs and security holes here! let's rock let's party
        if os.path.exists(filepath):
            return ERR_EXISTANT
        try:
            with open(filepath, "wb") as f:
                f.write(bindata.data)
        except:
            #ToDo error: Not yet well-documented
            return ERR_FS
            
        #now check the checksum
        with open ( filepath , "rb" ) as f:
            computedChecksum = adler32(f.read())
            
        try:
            if int.from_bytes(chksum.data, byteorder='big') != computedChecksum:
                return ERR_CHKSUM
        except AttributeError:
            pass
    
        computedSize = os.stat(filepath).st_size
        if (size != None) and (computedSize != size):
            return ERR_SIZE
            
        tsnow = datetime.now()
        
        try:
            with self.__conn as c:
                cursor = c.execute("insert into files (path, deleted) values (?,0)", 
                    (newfile,) )
                idfile = cursor.lastrowid
                
                cursor = c.execute('''insert into revisions 
                    ( idfile, timestamp, fromrev, typefrom, chksum, size, hardexist )
                    values (?,?,NULL,?,?,?,1)''' , 
                    (idfile,tsnow,REV_NEWFILE,computedChecksum,computedSize) 
                    )
                    
                idrev = cursor.lastrowid
                
                c.execute("update files set lastrev=? where idfile=?" , 
                    (idrev, idfile) )
                
        except:
            print ("Error: ", sys.exc_info()[0])
            return ERR_SQL
            
        try:
            revPath = os.path.join ( HARDDIR ,str(idrev) )
            logger.info ( "Proceeding to link %s and %s" , filepath , revPath ) 
            os.link ( filepath ,  revPath )
        except:
            return ERR_FS
            
        # calculate here hashes for rsync algorithm
        with open(filepath, "rb") as f:
            with open(os.path.join(HASHESDIR,str(idrev) ) , "wb" ) as fdump:
                pickle.dump(pyrsync.blockchecksums(f), fdump)
            
        return idrev, tsnow
        
    def GetFullRevision ( self, idRev ):
        """Get a file by its revision identificator (not necessarily
        the most actual version of the file)"""
        
        logger.info( 'Getting full revision for %s' , str(idRev) )
        
        with self.__conn as c:
            row = c.execute ('''select * from revisions where
                idrev=?''' , (idRev,) ).fetchone()
            
            #check if it can be the easy way
            if row['hardexist'] != 1:
                logger.debug ( 'Doing it the hard way' )
                # hard way, let's build the hard copy
                # search for last hard copy first
                deltaList = self.getDeltasSinceEvent ( 'hardexist' , 1 , idRev )
                logger.debug ( "(in GetFullRevision) Variable deltaList received: %s" , repr(deltaList) )
                if type(deltaList) == int:
                    logger.debug ( "deltaList is a int")
                    return deltaList
                
                # join everything
                #first throw away this, but save for later
                hardRev = deltaList.pop()
                logger.debug ( "Getting delta" )
                try:
                    val = str(deltaList.pop())
                    logger.debug ( "  - Now: %s" , val )
                    with open(os.path.join( DELTADIR , val), "rb") as f:
                        delta = pickle.load( f )
                    while deltaList:
                        val = str(deltaList.pop())
                        logger.debug ( "  - Now: %s" , val )
                        with open(os.path.join( DELTADIR , val ) , "rb") as f:
                            pyrsync.joindeltas ( delta , pickle.load( f ) )
                except:
                    raise
                    return ERR_FS
                
                logger.debug ( "Empty deltalist, last value: %s" , str(val) )
                
                # the last one, now will have hardcopy
                c.execute ( '''update revisions set hardexist=1
                    where idrev=?''' , (idRev,) )
                
                # this line, saved from
                row = c.execute ( '''select * from revisions 
                    where idrev=?''' , (hardRev,) ).fetchone()
                
                logger.info ( "Creating hard revision %s from revision %s" ,
                    idRev , hardRev )
                
                with open ( os.path.join(HARDDIR,str(val)) , "wb" ) as outstream:
                    with open ( os.path.join(HARDDIR,str(row['idrev'])) , "rb" ) as instream:
                        pyrsync.patchstream ( instream, outstream, delta )
        
        logger.debug ( 'Sending hard revision to client' )
        with open ( os.path.join ( HARDDIR , str(idRev) ) , "rb" ) as f:
            data = xmlrpc.client.Binary ( f.read() )
        return data
