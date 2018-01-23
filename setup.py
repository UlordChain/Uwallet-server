from setuptools import setup, find_packages
from uwalletserver import __version__
import os
import sys

requires = [
    'plyvel==0.9',
    'jsonrpclib',
    'python-bitcoinrpc==0.1',
    'appdirs==1.4.3',
    'unetschema',
]

#'unetschema==0.0.1rc1'

if sys.platform == "darwin":
    os.environ['CFLAGS'] = "-mmacosx-version-min=10.7 -stdlib=libc++ -I/usr/local/Cellar/leveldb/1.20/include"
    os.environ['LDFLAGS'] = "-L/usr/local/Cellar/leveldb/1.20/lib"

base_dir = os.path.dirname(os.path.abspath(__file__))

setup(
    name="uwallet-server",
    packages=find_packages(base_dir, exclude=['tests']),
    version=__version__,
    entry_points={'console_scripts': ['uwallet-server = uwalletserver.main:main']},
    install_requires=requires,
    description="UC Electrum Server",
    author="QiPing Liu",
    author_email="798013715@qq.com",
    license="GNU Affero GPLv3",
    url="http://192.168.14.240:3000/liuqiping/uwallet-server/",
    long_description="""Server for the Electrum Lightweight UC Wallet"""
)
 