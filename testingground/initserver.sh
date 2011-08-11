#!/bin/bash

./clean.sh
mkdir repoclient/testfolder
echo "This is a test" > repoclient/johnsmith/admintest
echo "This is a normal user test" > repojohnsmith/johntest
echo "file1" > repoclient/testfolder/file1
echo "file2" > repoclient/testfolder/file2
mkdir repoclient/testfolder/subfolder
echo "file3" > repoclient/testfolder/subfolder/file3

/usr/bin/python ../boproxd.py --config testing.ini --quiet
