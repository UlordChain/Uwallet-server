# Uwallet-server for the uwallet client
## Language: Python
## Features：
### The server indexes UTXOs by address, in a Patricia tree structure described by Alan Reiner (see the 'ultimate blockchain compression' thread in the Bitcointalk forum)
### The server requires, leveldb and plyvel
### The server code is open source. Anyone can run a server, removing single points of failure concerns.
### The server knows which set of Bitcoin addresses belong to the same wallet, which might raise concerns about anonymity. However, it should be possible to write clients capable of using several servers.
## Installation：
### To install and run a server, see INSTALL. For greater detail on the installation process, see HOWTO.md.
### To start and stop the server, use the 'uwallet-server' script
## License：
### Uwallet-server is made available under the terms of the GNU Affero General Public License, version 3. See the included LICENSE for more details.
