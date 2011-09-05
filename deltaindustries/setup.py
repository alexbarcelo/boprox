from setuptools import setup
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup (
    name = "deltaindustries",
    version = "0.3.0",
    description="Delta and hash utilities (calculation and containers) for the boprox project",
    author='Alex Barcelo',
    author_email='alex.barcelo@gmail.com',
    url='http://boprox.net',
    package_dir= {'deltaindustries': ''},
    packages = ['deltaindustries'],
    long_description = read('README'),
    license = "GPL",
    )
