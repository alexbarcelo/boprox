#!/bin/bash

./clean.sh
mkdir repoclient/testfolder
echo "This is a test" > repoclient/johnsmith/admintest
echo "This is a normal user test" > repojohnsmith/johntest

/usr/bin/python ../boproxd.py --config testing.ini
