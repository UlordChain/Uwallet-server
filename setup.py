from setuptools import setup, find_packages
from uwalletserver import __version__
import os
import sys
from distutils.sysconfig import get_python_lib
import shutil
import platform
current_place = get_python_lib()

if platform.system().startswith('Win'):
    shutil.copyfile(os.path.join('uwalletserver', 'cryptohello_hash.pyd'),
                    os.path.join(current_place, 'cryptohello_hash.pyd'))
else:
    shutil.copyfile(os.path.join('uwalletserver', 'cryptohello_hash.so'),
                    os.path.join(current_place, 'cryptohello_hash.so'))


requires = [
    'plyvel==0.9',
    'jsonrpclib',
    'python-bitcoinrpc==0.1',
    'appdirs==1.4.3',
    'unetschema',
]


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
    description="Ulord  Lightweight Wallet Server",
    author="JustinQP",
    author_email="JustinQP007@gmail.com",
    license="GNU Affero GPLv3",
    long_description="""Server for the Electrum client. for the ulord Lightweight  Wallet """
)
 