'''
Created on Aug 3, 2011

@author: marius
'''
from containers import HashContainer
import __builtin__

def open ( filename ):
    '''
    Return a HashContainer that holds the hashes.
    
    @param filename: String of a binary file that has the hashes.
    '''
    with __builtin__.open(filename, 'rb') as f:
        return HashContainer(f)
    
def load ( file ):
    '''
    Return a HashContainer that holds the hashes.
    
    @param file: Should have a read method
    '''
    return HashContainer(file)

def eval (filename):
    '''
    Open a file and return a HashContainer with the computed hashes
    
    @param filename: String of a file. It will be opened, readed, and the
    hashes will be computed and returned in a container
    '''
    ret = HashContainer()
    with __builtin__.open (filename, "rb") as f:
        ret.eval(f)
    return ret
