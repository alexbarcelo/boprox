'''
Created on Aug 3, 2011

@author: marius
'''
import pyrsync
from xmlrpclib import Binary

# thinking as python3
import cPickle as pickle

class GenContainer:
    '''
    Generic container for deltas and hashes
    '''
    def __init__ (self, binarydata = None):
        '''
        Constructor for Hash and Delta containers.
        
        @param binarydata: This can be an object with the read method or a 
        string with binary information.
        '''
        if binarydata:
            if hasattr(binarydata,'read'):
                self._bindata = pickle.load(binarydata)
            elif (type(binarydata) == 'str' or
                # thinking in python3...
                type(binarydata) == 'bytes'): 
                self._bindata = pickle.loads(binarydata)
            else:
                print str(type(binarydata))
                raise TypeError
        else:
            self._bindata = None
            
    def dump (self, file):
        '''
        Dump binary information onto an object
        
        @param file: Where to dump binary data. Should have a write method
        '''
        pickle.dump(self._bindata, file)

    def save (self, filename):
        '''
        Dump binary information onto a file
    
        @param delta: DeltaContainer with delta information
        @param filename: String of a file. It will be written
        '''
        with open ( filename , 'wb' ) as f:
            self.dump(f)
            
    def getXMLRPCBinary (self):
        return Binary(pickle.dumps(self._bindata))

            
class DeltaContainer(GenContainer):
    '''
    Container that holds a delta
    '''
    def join (self, delta):
        '''
        Adds to current delta (self) the delta  as a later revision
        
        @param delta: Contains information of a later delta
        '''
        pyrsync.joindeltas(self._bindata, delta._bindata)
        del (delta)
    
    def patch (self, infile, outfile):
        '''
        Patch a file with delta information
        
        @param infile: String with the base file (will be read-opened)
        @param outfile: String with the file to write (will be write-opened)

        ''' 
        with open(outfile, "wb") as outstream:
            with open(infile, "rb") as instream:
                pyrsync.patchstream (instream, outstream, self._bindata)

class HashContainer(GenContainer):
    '''
    Container that holds a hash
    '''
    
    def eval(self, file):
        '''
        Read a file (through a read() method) and save its hashes in this
        container.
        
        @param file: An open()-ed file or an object with a read method
        '''
        if self._bindata:
            del (self._bindata)
        self._bindata = pyrsync.blockchecksums(file)
    
    def computeDelta (self, file):
        '''
        Compute a delta for the open file (with the hash info in self)
        '''
        ret = DeltaContainer()
        ret._bindata = pyrsync.rsyncdelta(file, self._bindata)
        return ret