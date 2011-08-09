'''
Created on Aug 3, 2011

@author: marius
'''

from containers import DeltaContainer
import __builtin__

def open ( filename ):
    '''
    Return a DeltaContainer that holds the delta binary information.
    
    @param filename: String of a binary file that has the delta information.
    '''
    with __builtin__.open(filename, 'rb') as f:
        return DeltaContainer(f)
    
def load ( file ):
    '''
    Return a DeltaContainer that holds the delta binary information.
    
    @param file: Should have a read method
    '''
    return DeltaContainer(file)

def multiOpen (listoffiles):
    '''
    Return a DeltaContainer that holds the delta binary information of multiple
    deltas.
    
    @param listoffiles: List of filenames. The first element must be 
    last-to-apply (normally the newest, unless we are getting a rollback delta).
    Generation will be pop-ing the list
    '''
    val = listoffiles.pop()
    delta = open(val)
    while listoffiles:
        delta.join ( open(listoffiles.pop()) )
    return delta
