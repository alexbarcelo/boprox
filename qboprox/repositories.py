# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'repositories.ui'
#
# Created: Sun Aug 21 16:29:37 2011
#      by: PyQt4 UI code generator 4.8.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_repoListDialog(object):
    def setupUi(self, repoListDialog):
        repoListDialog.setObjectName(_fromUtf8("repoListDialog"))
        repoListDialog.resize(450, 200)
        repoListDialog.setMinimumSize(QtCore.QSize(450, 200))
        repoListDialog.setMaximumSize(QtCore.QSize(450, 200))
        self.verticalLayout = QtGui.QVBoxLayout(repoListDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.repoList = QtGui.QTableWidget(repoListDialog)
        self.repoList.setEditTriggers(QtGui.QAbstractItemView.DoubleClicked|QtGui.QAbstractItemView.EditKeyPressed)
        self.repoList.setRowCount(0)
        self.repoList.setObjectName(_fromUtf8("repoList"))
        self.repoList.setColumnCount(3)
        self.repoList.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(2, item)
        self.repoList.horizontalHeader().setVisible(True)
        self.repoList.horizontalHeader().setMinimumSectionSize(50)
        self.repoList.horizontalHeader().setStretchLastSection(True)
        self.repoList.verticalHeader().setVisible(False)
        self.verticalLayout.addWidget(self.repoList)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.addButton = QtGui.QPushButton(repoListDialog)
        self.addButton.setObjectName(_fromUtf8("addButton"))
        self.horizontalLayout.addWidget(self.addButton)
        self.editButton = QtGui.QPushButton(repoListDialog)
        self.editButton.setObjectName(_fromUtf8("editButton"))
        self.horizontalLayout.addWidget(self.editButton)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.closeButton = QtGui.QPushButton(repoListDialog)
        self.closeButton.setObjectName(_fromUtf8("closeButton"))
        self.horizontalLayout.addWidget(self.closeButton)
        self.verticalLayout.addLayout(self.horizontalLayout)

        self.retranslateUi(repoListDialog)
        QtCore.QObject.connect(self.closeButton, QtCore.SIGNAL(_fromUtf8("clicked()")), repoListDialog.close)
        QtCore.QMetaObject.connectSlotsByName(repoListDialog)

    def retranslateUi(self, repoListDialog):
        repoListDialog.setWindowTitle(QtGui.QApplication.translate("repoListDialog", "Repositories", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("repoListDialog", "Name", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("repoListDialog", "Path", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("repoListDialog", "Host", None, QtGui.QApplication.UnicodeUTF8))
        self.addButton.setText(QtGui.QApplication.translate("repoListDialog", "Add repository", None, QtGui.QApplication.UnicodeUTF8))
        self.editButton.setText(QtGui.QApplication.translate("repoListDialog", "Edit repository", None, QtGui.QApplication.UnicodeUTF8))
        self.closeButton.setText(QtGui.QApplication.translate("repoListDialog", "Close", None, QtGui.QApplication.UnicodeUTF8))

