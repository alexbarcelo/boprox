'''
Created on Aug 22, 2011

@author: marius
'''

from PyQt4 import QtGui
import string
from repoconfig import Ui_repoConfig

class QRepoConfig(QtGui.QDialog):
    
    _allowed_chars = string.ascii_letters + string.digits + '_-'
    _trans_table = string.maketrans('','')


    def __init__(self, parent = None):
        QtGui.QDialog.__init__(self, parent)
        
    def _prepare(self):
        self.ui = Ui_repoConfig()
        self.ui.setupUi(self)
        
    def addRepo(self):
        self.editRepo()
    
    def editRepo(self, name = None):
        self._prepare()
        # ToDo
        # if name not None, load settings and put them in dialog
        self.exec_()
    
    def accept(self):
        try:
            name = str(self.ui.lineEditName.text())
            isvalid = not name.translate(self._trans_table,self._allowed_chars)
        except UnicodeEncodeError:
            isvalid = False
            name = True
        if not name:
            msgBox = QtGui.QMessageBox()
            msgBox.setText("No repository name introduced")
            msgBox.setInformativeText("Please, introduce a name for the repository");
            msgBox.setStandardButtons(QtGui.QMessageBox.Ok)
            msgBox.setDefaultButton(QtGui.QMessageBox.Ok);
            msgBox.exec_();
        elif not isvalid:
            msgBox = QtGui.QMessageBox()
            msgBox.setText("Invalid repository name")
            msgBox.setInformativeText("Use only basic ascii characters, digits, '-' and '_'")
            msgBox.setStandardButtons(QtGui.QMessageBox.Ok)
            msgBox.setDefaultButton(QtGui.QMessageBox.Ok);
            msgBox.exec_();
        else:
            # ToDo
            self.close()
    
    def closeEvent(self, closeEvent):
        # we remove everything and create again
        for i in self.children():
            i.deleteLater()