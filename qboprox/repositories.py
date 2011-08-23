# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'repositories.ui'
#
# Created: Tue Aug 23 18:38:46 2011
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
        repoListDialog.resize(500, 200)
        repoListDialog.setMinimumSize(QtCore.QSize(500, 200))
        repoListDialog.setMaximumSize(QtCore.QSize(500, 200))
        self.verticalLayout = QtGui.QVBoxLayout(repoListDialog)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.repoList = QtGui.QTableWidget(repoListDialog)
        self.repoList.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.repoList.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        self.repoList.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.repoList.setRowCount(1)
        self.repoList.setObjectName(_fromUtf8("repoList"))
        self.repoList.setColumnCount(4)
        self.repoList.setRowCount(1)
        item = QtGui.QTableWidgetItem()
        self.repoList.setVerticalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setHorizontalHeaderItem(3, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setItem(0, 0, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setItem(0, 1, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setItem(0, 2, item)
        item = QtGui.QTableWidgetItem()
        self.repoList.setItem(0, 3, item)
        self.repoList.horizontalHeader().setVisible(True)
        self.repoList.horizontalHeader().setHighlightSections(False)
        self.repoList.horizontalHeader().setMinimumSectionSize(50)
        self.repoList.horizontalHeader().setStretchLastSection(True)
        self.repoList.verticalHeader().setVisible(False)
        self.repoList.verticalHeader().setHighlightSections(False)
        self.verticalLayout.addWidget(self.repoList)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.addButton = QtGui.QPushButton(repoListDialog)
        self.addButton.setObjectName(_fromUtf8("addButton"))
        self.horizontalLayout.addWidget(self.addButton)
        self.editButton = QtGui.QPushButton(repoListDialog)
        self.editButton.setObjectName(_fromUtf8("editButton"))
        self.horizontalLayout.addWidget(self.editButton)
        self.delButton = QtGui.QPushButton(repoListDialog)
        self.delButton.setObjectName(_fromUtf8("delButton"))
        self.horizontalLayout.addWidget(self.delButton)
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
        self.repoList.verticalHeaderItem(0).setText(QtGui.QApplication.translate("repoListDialog", "0", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(0).setText(QtGui.QApplication.translate("repoListDialog", "Name", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(1).setText(QtGui.QApplication.translate("repoListDialog", "Path", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(2).setText(QtGui.QApplication.translate("repoListDialog", "Host", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.horizontalHeaderItem(3).setText(QtGui.QApplication.translate("repoListDialog", "Enabled", None, QtGui.QApplication.UnicodeUTF8))
        __sortingEnabled = self.repoList.isSortingEnabled()
        self.repoList.setSortingEnabled(False)
        self.repoList.item(0, 0).setText(QtGui.QApplication.translate("repoListDialog", "testnane", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.item(0, 1).setText(QtGui.QApplication.translate("repoListDialog", "/test/path", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.item(0, 2).setText(QtGui.QApplication.translate("repoListDialog", "testhost.com", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.item(0, 3).setText(QtGui.QApplication.translate("repoListDialog", "Yes", None, QtGui.QApplication.UnicodeUTF8))
        self.repoList.setSortingEnabled(__sortingEnabled)
        self.addButton.setText(QtGui.QApplication.translate("repoListDialog", "Add", None, QtGui.QApplication.UnicodeUTF8))
        self.editButton.setText(QtGui.QApplication.translate("repoListDialog", "Edit", None, QtGui.QApplication.UnicodeUTF8))
        self.delButton.setText(QtGui.QApplication.translate("repoListDialog", "Delete", None, QtGui.QApplication.UnicodeUTF8))
        self.closeButton.setText(QtGui.QApplication.translate("repoListDialog", "Close", None, QtGui.QApplication.UnicodeUTF8))

