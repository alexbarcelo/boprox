'''
Created on Aug 18, 2011

@author: marius
'''

from PyQt4 import QtCore

class QRepoManager(QtCore.QObject):
    '''
    Class that manages a QTreeView and keeps it in synch with a certain 
    boprox repository.
    '''
    def __init__(self, clientRepo, parent):
        '''
        Initializes everything. It is very important that the params are
        what they should be.
        
        @param clientRepo: An initialized instance of 
        boprox.client.SingleRepoClient. It is the source of information.
        @param parant: It should be a QObject (the parent of this QObject).
        It must be a QTreeView.
        '''
        QtCore.QObject.__init__(parent)
        self._client = clientRepo
        self._update = False
    
    def treeViewUpdate(self):
        self._update = True
    
    def treeViewLock(self):
        self._update = False
        