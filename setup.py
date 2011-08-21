from setuptools import setup
import os, sys

if sys.version_info < (2 , 6):
    requireSSL = '\nssl\n',
else:
    requireSSL = '\n'

setup (
    name = "boprox_server",
    version = "0.2.1",
    description="",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    packages = ['boprox'],
    provides = ['boprox.Sanitize'],
    long_description = """The boprox_server provides the boprox server daemon. 

This server should run in the central server, and all clients that 
share the repository (or more than one if it's intended as a 
multi-user server).
""",
    license = 'GPL',
    dependency_links = [
        'http://sourceforge.net/projects/boprox/files/deltaindustries/'
        ],
    install_requires = """
        deltaindustries >= 0.1
        rsa >= 1.0.0
        pyasn1 >= 0.0.1""" + requireSSL,
    entry_points = {
        'console_scripts': [
            'boproxd = boprox.boproxd:main',
        ],
    },
    )

