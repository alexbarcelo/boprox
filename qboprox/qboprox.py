'''
Created on Aug 17, 2011

@author: marius
'''

from PyQt4 import QtGui
from qboproxMainWindow import qboproxMainWindow

def main():
    import sys    
    app = QtGui.QApplication(sys.argv)
    # this window is managed on its own
    MW = qboproxMainWindow()
    sys.exit(app.exec_())
    if MW:
        del (MW)

if __name__ == '__main__':
    main()