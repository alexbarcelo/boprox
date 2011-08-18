'''
Created on Aug 18, 2011

@author: marius
'''

from PyQt4 import QtGui, QtCore

from about import Ui_About
from main import Ui_MainWindow

import boprox

class qboproxMainWindow(QtGui.QMainWindow):
    '''
    Subclass of QMainWindow, main window of qboprox application
    '''
    def loadSettings(self):
        self.sett = QtCore.QSettings()
        
    def displayAbout(self):
        DialogAbout = QtGui.QDialog(self)
        ui = Ui_About()
        ui.setupUi(DialogAbout)
        DialogAbout.show()
        
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
        print 'a'
        self.setVisible(False)
        event.ignore()
        
    def connectMySlots(self):
        self.mainUi.actionRefresh.activated.connect(self.triggerRefresh)
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

    def __init__(self, *args):
        apply(QtGui.QMainWindow.__init__, (self,) + args)
        self.mainUi = Ui_MainWindow()
        self.mainUi.setupUi(self)
        
        self.createTray()
        self.connectMySlots()
        
        self.show()