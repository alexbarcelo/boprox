from setuptools import setup
import os, sys

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

if sys.version_info < (2 , 6):
    requireSSL = '\nssl\n',
else:
    requireSSL = '\n'

setup (
    name = "boprox_server",
    version = "0.1",
    description="",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    packages = ['boprox'],
    long_description = read( os.path.join('boprox','README-server') ),
    license = 'GPL',
    install_requires = """
        rsa >= 1.0.0
        pyasn1 >= 0.0.1""" + requireSSL,
    entry_points = {
        'console_scripts': [
            'boproxd = boprox.boproxd:main',
        ],
    },
    )

