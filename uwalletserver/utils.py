#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import hashlib
import logging
import logging.handlers
import os
import threading
import time
#from cryptonite_hash import cpu_has_aes_in_supported, cryptolite_hash, cryptonite_hash
from cryptohello_hash import cpu_has_aes_in_supported,cryptohello_hash
from itertools import imap

logger = logging.getLogger("uwalletserver")


def init_logger(logfile):
    hdlr = logging.handlers.WatchedFileHandler(logfile)
    formatter = logging.Formatter('%(asctime)s %(message)s', "[%d/%m/%Y-%H:%M:%S]")
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)


def print_log(*args):
    logger.info(" ".join(imap(str, args)))


def print_warning(message):
    logger.warning(message)


__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

global PUBKEY_ADDRESS
global SCRIPT_ADDRESS
global PUBKEY_ADDRESS_PREFIX  #prefix
global SCRIPT_ADDRESS_PREFIX  #script

PUBKEY_ADDRESS = 0
SCRIPT_ADDRESS = 5
PUBKEY_ADDRESS_PREFIX = 36  #85
SCRIPT_ADDRESS_PREFIX = 204 #122

HAS_AES_NI = cpu_has_aes_in_supported()

def rev_hex(s):
    return s.decode('hex')[::-1].encode('hex')


def int_to_hex(i, length=1):
    s = hex(i)[2:].rstrip('L')
    s = "0" * (2 * length - len(s)) + s
    return rev_hex(s)


def sha256(x):
    return hashlib.sha256(x).digest()


def sha512(x):
    return hashlib.sha512(x).digest()


def ripemd160(x):
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()


def Hash(x):
    if type(x) is unicode: x = x.encode('utf-8')
    #r = cryptonite_hash(x, HAS_AES_NI)
    r = cryptohello_hash(x, HAS_AES_NI)
    return r


def PoWHash(x):
    if type(x) is unicode: x = x.encode('utf-8')
    r = sha512(Hash(x))
    r1 = ripemd160(r[:len(r) / 2])
    r2 = ripemd160(r[len(r) / 2:])
    r3 = Hash(r1 + r2)
    return r3


def hash_encode(x):
    return x[::-1].encode('hex')


def hash_decode(x):
    return x.decode('hex')[::-1]


def header_to_string(res):
    pbh = res.get('prev_block_hash')
    if pbh is None:
        pbh = '0' * 64

    return int_to_hex(res.get('version'), 4) \
           + rev_hex(pbh) \
           + rev_hex(res.get('merkle_root')) \
           + rev_hex(res.get('claim_trie_root')) \
           + int_to_hex(int(res.get('timestamp')), 4) \
           + int_to_hex(int(res.get('bits')), 4) \
           + int_to_hex(int(res.get('nonce')), 4) #\
           #+ rev_hex(res.get('solution'))

#Fix block header loss validation issue -lqp
def header_to_string_verify(res):
    pbh = res.get('prev_block_hash')
    if pbh is None:
        pbh = '0' * 64

    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(pbh) \
        + rev_hex(res.get('merkle_root')) \
        + rev_hex(res.get('claim_trie_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')),4) 
    #sol_len = len(res.get('solution')) / 2
    #str_len = ''
    #if sol_len < 253:
    #    str_len = int_to_hex(sol_len, 1)
    #elif sol_len <= 0xfff:
    #    str_len = int_to_hex(253, 1) + int_to_hex(sol_len, 2)
    #elif sol_len <= 0xFFFFFFFF:
    #    str_len = int_to_hex(254, 1) + int_to_hex(sol_len, 4)
    #else:
    #    str_len = int_to_hex(255, 1) + int_to_hex(sol_len, 8)
    #s += str_len
    #s += res.get('solution')
    #print 'header2222====',s
    return s
 
def hex_to_int(s):
    return int('0x' + s[::-1].encode('hex'), 16)

#TODO Modify the block header verification problem -lqp
def header_from_string(s):
    return {
        'version': hex_to_int(s[0:4]),
        'prev_block_hash': hash_encode(s[4:36]),
        'merkle_root': hash_encode(s[36:68]),
        'claim_trie_root': hash_encode(s[68:100]),
        'timestamp': hex_to_int(s[100:104]),
        'bits': hex_to_int(s[104:108]),
        'nonce': hex_to_int(s[108:112])#,
        #'solution': hash_encode(s[140:1484]) #3 1487
    }
    #'nonce': hex_to_int(s[108:140]),

############ functions from pywallet #####################



def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def public_key_to_pubkey_address(public_key):
    return hash_160_to_pubkey_address(hash_160(public_key))


def public_key_to_bc_address(public_key):
    """ deprecated """
    return public_key_to_pubkey_address(public_key)


def hash_160_to_pubkey_address(h160, addrtype=None):
    """ deprecated """
    if not addrtype:
        addrtype = PUBKEY_ADDRESS
    return hash_160_to_address(h160, addrtype)


def hash_160_to_pubkey_address(h160):
    return hash_160_to_address(h160, PUBKEY_ADDRESS)


def hash_160_to_script_address(h160):
    return hash_160_to_address(h160, SCRIPT_ADDRESS)


def hash_160_to_address(h160, addrtype=0):
    """ Checks if the provided hash is actually 160bits or 20 bytes long and returns the address, else None
    """
    if h160 is None or len(h160) is not 20:
        return None

    if addrtype == 0:
        c = chr(PUBKEY_ADDRESS_PREFIX)
    elif addrtype == 5:
        c = chr(SCRIPT_ADDRESS_PREFIX)

    vh160 = c + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)


def bc_address_to_hash_160(addr):
    if addr is None or len(addr) is 0:
        return None
    bytes = b58decode(addr, 25)
    return bytes[1:21] if bytes is not None else None


def b58encode(v):
    """encode v, which is a string of bytes, to base58."""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def EncodeBase58Check(vchIn):
    hash = Hash(vchIn)
    return b58encode(vchIn + hash[0:4])


def DecodeBase58Check(psz):
    vchRet = b58decode(psz, None)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(key)
    cs32 = hash[0:4]
    if cs32 != csum:
        return None
    else:
        return key


########### end pywallet functions #######################


def random_string(length):
    return b58encode(os.urandom(length))


def timestr():
    return time.strftime("[%d/%m/%Y-%H:%M:%S]")


class ProfiledThread(threading.Thread):
    def __init__(self, filename, target):
        self.filename = filename
        threading.Thread.__init__(self, target=target)

    def run(self):
        import cProfile
        profiler = cProfile.Profile()
        profiler.enable()
        threading.Thread.run(self)
        profiler.disable()
        profiler.dump_stats(self.filename)
