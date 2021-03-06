from setuptools import setup
import os

setup (
    name = "boprox_client",
    version = "0.3.0",
    description="Client API package for the boprox project",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    package_dir= {'boprox': ''},
    py_modules = ['boprox.client', 'boprox.Sanitize'],
    provides = ['boprox.Sanitize'],
    long_description = """The boprox client is used to connect to a boprox server. 

It's not a fully-featured client for end-users, it's an API that 
handles all filesystem and network communication and authentication
with the server. See the project page for more information about
user-friendly clients.
""",
    license = 'GPL',
    dependency_links = [
        'http://sourceforge.net/projects/boprox/files/deltaindustries/'
        ],
    install_requires = """
        deltaindustries >= 0.3.0, < 0.4.0
        rsa >= 1.0.0
        pyasn1 >= 0.0.1
    """,
    )

