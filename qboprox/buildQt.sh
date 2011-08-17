#!/bin/bash

pyuic4 -o main.py  main.ui
pyuic4 -o about.py about.ui

pyrcc4 -o resources.py resources.qrc
