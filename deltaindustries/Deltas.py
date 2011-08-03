'''
Created on Aug 3, 2011

@author: marius
'''

from containers import DeltaContainer

def open ( filename ):
    '''
    Return a DeltaContainer that holds the delta binary information.
    
    @param filename: String of a binary file that has the delta information.
    '''
    with open(filename, 'rb') as f:
        return DeltaContainer(f)
    
def load ( file ):
    '''
    Return a DeltaContainer that holds the delta binary information.
    
    @param file: Should have a read method
    '''
    return DeltaContainer(file)
