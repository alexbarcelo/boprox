#!/bin/bash

pyuic4 -o main.py  main.ui
pyuic4 -o about.py about.ui
pyuic4 -o repositories.py repositories.ui
pyuic4 -o repoconfig.py repoconfig.ui

pyrcc4 -o resources_rc.py resources.qrc
