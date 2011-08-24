'''
Created on Aug 22, 2011

@author: marius
'''

from PyQt4 import QtGui, QtCore
import string
from repoconfig import Ui_repoConfig

class QRepoConfig(QtGui.QDialog):
    
    _allowed_chars = string.ascii_letters + string.digits + '_-'
    _trans_table = string.maketrans('','')


    def __init__(self, parent = None):
        QtGui.QDialog.__init__(self, parent)
        self._sett = QtCore.QSettings('boprox','qboprox')
        self._sett.beginGroup('repositories')
        
    def _prepare(self):
        self.ui = Ui_repoConfig()
        self.ui.setupUi(self)
            
    def addRepo(self):
        self.editRepo()
    
    def editRepo(self, name = None):
        self._prepare()
        if name and (name in self._sett.childGroups()):
            self._sett.beginGroup(name)
            self.ui.lineEditName.setText(name)
            self.ui.lineEditHost.setText(self._sett.value('host').toPyObject())
            port, extra = self._sett.value('port').toInt()
            if not extra:
                port = 1356
            self.ui.spinBoxPort.setValue(port)
            if self._sett.value('enabled'):
                self.ui.checkBoxEnabled.setChecked(True)
            else:
                self.ui.checkBoxEnabled.setChecked(False)
            self.ui.lineEditUsername.setText(self._sett.value('username').toPyObject())
            if 'key' in self._sett.childKeys():
                self.ui.comboBoxAuthType.setCurrentIndex(0)
                self.ui.lineEditRSA.setText(self._sett.value('key').toPyObject())
            else:
                self.ui.comboBoxAuthType.setCurrentIndex(1)
                self.ui.lineEditPassword.setText(self._sett.value('password').toPyObject())
            self.ui.lineEditLocalPath.setText(self._sett.value('localpath').toPyObject())
            self.ui.lineEditHashes.setText(self._sett.value('hashesdir').toPyObject())
            self.ui.lineEditDB.setText(self._sett.value('dbfile').toPyObject())
            self._sett.endGroup()
        self.exec_()
        
    def reject(self):
        self.close()
    
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
            self._sett.beginGroup(name)
            self._sett.setValue('host', self.ui.lineEditHost.text())
            self._sett.setValue('port', self.ui.spinBoxPort.value())
            self._sett.setValue('enabled', self.ui.checkBoxEnabled.isChecked())
            self._sett.setValue('username', self.ui.lineEditUsername.text())
            if self.ui.comboBoxAuthType.currentIndex() == 0:
                self._sett.setValue('key', self.ui.lineEditRSA.text())
                self._sett.remove('password')
            else:
                self._sett.setValue('password', self.ui.lineEditPassword.text())
                self._sett.remove('key')                
            self._sett.setValue('localpath', self.ui.lineEditLocalPath.text())        
            self._sett.setValue('hashesdir', self.ui.lineEditHashes.text())
            self._sett.setValue('dbfile', self.ui.lineEditDB.text())
            self._sett.endGroup()
            self.close()
    
    def closeEvent(self, closeEvent):
        # we remove everything, it will be created next time
        for i in self.children():
            i.deleteLater()