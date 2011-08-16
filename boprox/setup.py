from setuptools import setup
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup (
    name = "boprox_client",
    version = "0.1",
    description="",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    package_dir= {'boprox': ''},
    py_modules = ['boprox.client', 'boprox.Sanitize'],
    long_description = read('README-client'),
    license = 'GPL',
    install_requires = """
        rsa >= 1.0.0
        pyasn1 >= 0.0.1
        ssl
    """,
    )

