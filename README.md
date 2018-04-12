# Uwallet-server for the Uwallet client

### Language: Python

### Features：
- The server indexes UTXOs by address, in a Patricia tree structure described by Alan Reiner (see the 'ultimate blockchain compression' thread in the Bitcointalk forum)
- The server code is open source. Anyone can run a server, removing single points of failure concerns.
- The server knows which set of Bitcoin addresses belong to the same wallet, which might raise concerns about anonymity. However, it should be possible to write clients capable of using several servers.

### Dependencies:
- [python2.7+](https://www.python.org/)

- [ulordd](https://github.com/UlordChain/UlordChain) 
  Ulord is a P2P value delivery public chain. 

- [unetschema](https://github.com/UlordChain/UlordChain)
  It is used to define the format of the data and validate it in the Ulord blockchain. You can:
  
      git https://github.com/UlordChain/Uschema.git
      cd Uschema && python setup.py install
      
- [leveldb](https://github.com/google/leveldb)
  You can add the repository and install using the following commands:
  
      sudo add-apt-repository ppa:bitcoin/bitcoin
      sudo apt-get update
      sudo apt-get install libdb4.8-dev libdb4.8++-dev 

## Installation：
  To install and run a server, see INSTALL. 
  For greater detail on the installation process, see [HOWTO](https://github.com/spesmilo/electrum-server/blob/master/HOWTO.md).
  
### To start and stop the server, use the `uwallet-server` script

### License：
  Uwallet-server is made available under the terms of the GNU Affero General Public License, version 3. See the included LICENSE for more details.
