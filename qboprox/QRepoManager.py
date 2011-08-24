'''
Created on Aug 18, 2011

@author: marius
'''

from PyQt4 import QtCore
import boprox.client

class RepoWorker(QtCore.QThread):
    def __init__(self, parent = None):
        '''
        Parent must be QRepoManager, callbacks to QRepoManager instances are
        used.
        
        We use Qt signals and slots, but they are only at QRepoManager (more 
        consistent and less verbose).
        '''
        QtCore.QThread.__init__(self, parent)
        self.exiting = False
        self._settings = None
    
    def setRepoName(self, reponame):
        # Open the settings of this repo
        self._settings = QtCore.QSettings('boprox', 'qboprox')
        self._settings.beginGroup('repositories')
        if not reponame in self._settings.childGroups():
            raise AttributeError('No group %s in the configuration backend' % 
                reponame)
        self._settings.beginGroup(reponame)
    
    def _refreshRepo(self):
        try:
            self._repo.UpdateToServer()
            self._repo.UpdateFromServer()
            self._repo.CheckDeletedFiles()
        except (boprox.client.LocalError, boprox.client.ClientError) as e:
            self.parent()._Error(e)
            
    def _localcheckRepo(self):
        try:
            self._repo.UpdateToServer()
            self._repo.CheckDeletedFiles()
        except (boprox.client.LocalError, boprox.client.ClientError) as e:
            self.parent()._Error(e)
    
    def _setTimers(self):
        trefresh = self._settings.value('refresh', 600).toPyObject()
        tlocalcheck = self._settings.value('localcheck', 60).toPyObject()        
        if tlocalcheck > 0:
            self._timerl = QtCore.QTimer()
            self._timerl.timeout.connect(self._localcheckRepo,
                # This is needed because the sqlite object lives in this thread
                QtCore.Qt.DirectConnection)
            self._timerl.start(tlocalcheck*1000)
        self._timerr = QtCore.QTimer()
        self._timerr.timeout.connect(self._refreshRepo,
            # This is needed because the sqlite object lives in this thread
            QtCore.Qt.DirectConnection)
        self._timerr.start(trefresh*1000)
    
    def _setWatcher(self):
        pass
    
    def run(self):
        if not self._settings:
            raise TypeError('No repository name set')
        try:
            numport, success = self._settings.value('port').toInt()
            if not success:
                numport = 1356
            self._repo = boprox.client.SingleRepoClient(
                host=unicode(self._settings.value('host').toPyObject()),
                port=numport,
                username=unicode(self._settings.value('username').toPyObject()),
                permatoken=unicode(self._settings.value('password').toPyObject()),
                key=unicode(self._settings.value('key').toPyObject()),
                dbfile=unicode(self._settings.value('dbfile').toPyObject()),
                localpath=unicode(self._settings.value('localpath').toPyObject()),
                hashesdir=unicode(self._settings.value('hashesdir').toPyObject()),
                )
        except StandardError as e:
            self.parent()._Error(e)
            raise
        self._refreshRepo()
        self._setTimers()
        self._setWatcher()
        self.exec_()

class QRepoManager(QtCore.QObject):
    '''
    Class that manages a QTreeView and keeps it in synch with a certain 
    boprox repository.
    '''
    
    onError = QtCore.pyqtSignal()
    
    def __init__(self, clientRepo, parent):
        '''
        Initializes everything. It is very important that the params are
        what they should be.
        
        @param clientRepo: The identification name of the repository. We 
        give our hope to the QSettings class and magic 
        @param parant: A QObject, that will become the parent of this QObject.
        It must be a QTreeView.
        '''
        QtCore.QObject.__init__(self, parent)
        self._update = False
        self.thread = RepoWorker(self)
        self.thread.setRepoName(clientRepo)
        self.exitmutex = QtCore.QMutex()
        self.treemutex = QtCore.QMutex()
        self.thread.start()
        
    def _Error(self, e):
        '''
        Callback function
        '''
        self.lastError = e
        self.onError.emit()
    
    def treeViewUpdate(self):
        '''
        This QRepoManager has permission to change and update the QTreeView
        '''
        self._update = True
    
    def treeViewLock(self):
        '''
        This QRepoManager has no longer permission to change the QTreeView.
        Will wait if it was being updated.
        '''
        # wait if we were doing something
        QtCore.QMutexLocker(self.treemutex)
        self._update = False
        