#!/bin/bash

pyuic4 main.ui > main.py
pyuic4 about.ui > about.py

pyrcc4 resources.qrc > resources.py
