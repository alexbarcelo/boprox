from setuptools import setup
import os

setup (
    name = "boprox_client",
    version = "0.1",
    description="",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    package_dir= {'boprox': ''},
    py_modules = ['boprox.client', 'boprox.Sanitize'],
    long_description = """The boprox client is used to connect to a boprox server. 

It synchronizes file with the server, and can manage all the client
actions (revision control, rollbacks, updates, adding shares...).

It's not a fully-featured client for end-users, is more a API that 
handles all filesystem and network communication and authentication
with the server.
"""
    license = 'GPL',
    dependency_links = [
        'http://sourceforge.net/projects/boprox/files/deltaindustries/'
        ],
    install_requires = """
        deltaindustries >= 0.1
        rsa >= 1.0.0
        pyasn1 >= 0.0.1
    """,
    )
