'''
Created on Aug 18, 2011

@author: marius
'''

from PyQt4 import QtGui, QtCore
from about import Ui_About
from main import Ui_MainWindow
from repositories import Ui_repoListDialog
from qrepoconfig import QRepoConfig
from QRepoManager import QRepoManager

class qboproxMainWindow(QtGui.QMainWindow):
    '''
    Subclass of QMainWindow, main window of qboprox application
    '''
    def loadSettings(self):
        self.sett = QtCore.QSettings('boprox','qboprox')
        
    def displayAbout(self):
        DialogAbout = QtGui.QDialog(self)
        ui = Ui_About()
        ui.setupUi(DialogAbout)
        DialogAbout.show()
    
    def displayRepoList(self):
        DialogRepoList = QtGui.QDialog(self)
        ui = Ui_repoListDialog()
        ui.setupUi(DialogRepoList)
        
        def updateList():
            # first delete all rows
            for i in reversed(xrange(0, ui.repoList.rowCount())):
                ui.repoList.removeRow(i)
            self.sett.beginGroup('repositories')
            for repo in self.sett.childGroups():
                self.sett.beginGroup(repo)
                ui.repoList.insertRow(0)
                ui.repoList.setItem(0,0, 
                    QtGui.QTableWidgetItem(repo) )
                localpath = self.sett.value('localpath').toPyObject()
                if localpath: 
                    ui.repoList.setItem(0,1, 
                        QtGui.QTableWidgetItem(localpath) )
                host = self.sett.value('host').toPyObject()
                ui.repoList.setItem(0,2, 
                    QtGui.QTableWidgetItem(host) )
                if self.sett.value('enabled').toPyObject():
                    val = QtGui.QTableWidgetItem('yes')
                else:
                    val = QtGui.QTableWidgetItem('no')
                ui.repoList.setItem(0,3, val)
                self.sett.endGroup()
            self.sett.endGroup()
            ui.repoList.setCurrentCell(0, 0)
        
        def displayRepoConfigAdd ():
            DialogRepoConfig.addRepo()
            updateList()
            
        def displayRepoConfigEdit ():
            # set all the information
            # TODO
            DialogRepoConfig.editRepo(str(ui.repoList.item(
                ui.repoList.currentRow(), 0 ).data(0).toPyObject() ))
            updateList()
        
        def delRepo():
            name = ui.repoList.item(
                ui.repoList.currentRow(),0 ).data(0).toPyObject()
            if name: 
                self.sett.beginGroup('repositories')
                self.sett.remove(name)
                self.sett.endGroup()
            updateList()
            
        # prepare this, just in case
        DialogRepoConfig = QRepoConfig(DialogRepoList)        
        ui.addButton.clicked.connect(displayRepoConfigAdd)
        ui.editButton.clicked.connect(displayRepoConfigEdit)
        ui.delButton.clicked.connect(delRepo)
        updateList()
        DialogRepoList.exec_()
        
    def triggerRefresh(self):
        pass
    
    def triggerQuit(self):
        QtCore.QCoreApplication.exit()
        
    def toggleVisible(self, reason):
        if reason == QtGui.QSystemTrayIcon.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show()
    
    def closeEvent(self, event):
        self.setVisible(False)
        event.ignore()
        
    def connectMySlots(self):
        self.mainUi.actionRefresh.activated.connect(self.triggerRefresh)
        self.mainUi.actionRepositoryList.activated.connect(self.displayRepoList)
        self.mainUi.trayRefresh.activated.connect(self.triggerRefresh)
        self.mainUi.trayShow.activated.connect(self.show)
        self.mainUi.actionAbout.activated.connect(self.displayAbout)
        self.mainUi.actionQuit.activated.connect(self.triggerQuit)
        self.mainUi.trayQuit.activated.connect(self.triggerQuit)
        self.mainUi.trayIcon.activated.connect(self.toggleVisible)
        
    def createTray(self):
        # "De-attach" de MenuTray menu
        self.mainUi.menubar.removeAction(
            self.mainUi.menuTrayIcon.menuAction()) 
        if not QtGui.QSystemTrayIcon.isSystemTrayAvailable:
            # We don't have a tray icon
            self.mainUi.actionClose.setDisabled(True)
        else:
            self.mainUi.trayIcon = QtGui.QSystemTrayIcon(self);
            ic = QtGui.QIcon(":/icons/tray.svg")
            self.mainUi.trayIcon.setContextMenu(self.mainUi.menuTrayIcon);
            self.mainUi.trayIcon.setIcon(ic)
            self.mainUi.trayIcon.setToolTip('qboprox')
            self.mainUi.trayIcon.show()
    
    def updateRepos(self):
        self.sett.beginGroup('repositories')
        for qi in self.sett.childGroups():
            i = str(qi)
            if i not in self._reposWatchers:
                newrepo = QRepoManager(i, self.mainUi.fileTree)
                self._reposWatchers[i] = newrepo
        self.sett.endGroup()

    def __init__(self, *args):
        apply(QtGui.QMainWindow.__init__, (self,) + args)
        self.mainUi = Ui_MainWindow()
        self.mainUi.setupUi(self)
        self.loadSettings()
        self.createTray()
        self.connectMySlots()
        self._reposWatchers = dict()
        self.updateRepos()
        self.show()