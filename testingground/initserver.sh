#!/bin/bash

./clean.sh

mkdir repoclient/testfolder
echo "This is a test" > repoclient/testfile

/usr/bin/python ../boproxd.py --config testing.ini
