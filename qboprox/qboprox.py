'''
Created on Aug 17, 2011

@author: marius
'''

from PyQt4 import QtGui, QtCore

from about import Ui_About
from main import Ui_MainWindow

global MainWindow
global MainGUI
global sett

def loadSettings():
    global sett
    sett = QtCore.QSettings()
    
def displayAbout():
    global MainWindow
    DialogAbout = QtGui.QDialog(MainWindow)
    ui = Ui_About()
    ui.setupUi(DialogAbout)
    DialogAbout.show()
    
def connectMySlots():
    global MainGUI
    MainGUI.actionAbout.activated.connect(displayAbout)

def createTray():
    # "De-attach" de MenuTray menu
    MainGUI.menubar.removeAction(
        MainGUI.menuTrayIcon.menuAction()) 
    if not QtGui.QSystemTrayIcon.isSystemTrayAvailable:
        # We don't have a tray icon
        MainGUI.actionHide.setDisabled(True)
    else:
        trayIcon = QtGui.QSystemTrayIcon(MainWindow);
        ic = QtGui.QIcon(":/icons/tray.svg")
        trayIcon.setContextMenu(MainGUI.menuTrayIcon);
        trayIcon.setIcon(ic)
        trayIcon.show()

def main():
    import sys
    global MainGUI
    global MainWindow
    
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    MainGUI = Ui_MainWindow()
    MainGUI.setupUi(MainWindow)
    MainWindow.show()
    connectMySlots()
    loadSettings()
    createTray()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()