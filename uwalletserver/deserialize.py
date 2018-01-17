import mmap
import struct
import types

from uwalletserver.utils import hash_160_to_pubkey_address, hash_160_to_script_address, public_key_to_pubkey_address
from uwalletserver.utils import hash_encode, hash_160

# this code comes from ABE. it can probably be simplified

def rev_hex(s):
    return s.decode('hex')[::-1].encode('hex')

# get the claim id hash from txid bytes and int n 
def claim_id_hash(txid, n):
    return hash_160(txid + struct.pack('>I',n))

def claim_id_bytes_to_hex(claim_id_bytes):
    return rev_hex(claim_id_bytes.encode('hex'))

class SerializationError(Exception):
    """Thrown when there's a problem deserializing or serializing."""


class BCDataStream(object):
    """Workalike python implementation of Bitcoin's CDataStream class."""

    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, bytes):  # Initialize with string of bytes
        if self.input is None:
            self.input = bytes
        else:
            self.input += bytes

    def map_file(self, file, start):  # Initialize with bytes from file
        self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        self.read_cursor = start

    def seek_file(self, position):
        self.read_cursor = position

    def close_file(self):
        self.input.close()

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :    1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def write_string(self, string):
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return ''

    def read_boolean(self):
        return self.read_bytes(1)[0] != chr(0)

    def read_int16(self):
        return self._read_num('<h')

    def read_uint16(self):
        return self._read_num('<H')

    def read_int32(self):
        return self._read_num('<i')

    def read_uint32(self):
        return self._read_num('<I')

    def read_int64(self):
        return self._read_num('<q')

    def read_uint64(self):
        return self._read_num('<Q')

    def write_boolean(self, val):
        return self.write(chr(1) if val else chr(0))

    def write_int16(self, val):
        return self._write_num('<h', val)

    def write_uint16(self, val):
        return self._write_num('<H', val)

    def write_int32(self, val):
        return self._write_num('<i', val)

    def write_uint32(self, val):
        return self._write_num('<I', val)

    def write_int64(self, val):
        return self._write_num('<q', val)

    def write_uint64(self, val):
        return self._write_num('<Q', val)

    def read_compact_size(self):
        size = ord(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num('<H')
        elif size == 254:
            size = self._read_num('<I')
        elif size == 255:
            size = self._read_num('<Q')
        return size

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(chr(size))
        elif size < 2 ** 16:
            self.write('\xfd')
            self._write_num('<H', size)
        elif size < 2 ** 32:
            self.write('\xfe')
            self._write_num('<I', size)
        elif size < 2 ** 64:
            self.write('\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


class EnumException(Exception):
    pass


class Enumeration:
    """enum-like type

    From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
    """

    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = []
        uniqueValues = []
        for x in enumList:
            if isinstance(x, types.TupleType):
                x, i = x
            if not isinstance(x, types.StringType):
                raise EnumException("enum name is not a string: %r" % x)
            if not isinstance(i, types.IntType):
                raise EnumException("enum value is not an integer: %r" % i)
            if x in uniqueNames:
                raise EnumException("enum name is not unique: %r" % x)
            if i in uniqueValues:
                raise EnumException("enum value is not unique for %r" % x)
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value):
        return self.reverseLookup[value]


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')


# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4] + "..." + t[-4:]


def parse_TxIn(vds):
    d = {}
    d['prevout_hash'] = hash_encode(vds.read_bytes(32))
    d['prevout_n'] = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    d['sequence'] = vds.read_uint32()
    return d


def parse_TxOut(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['address'] = get_address_from_output_script(scriptPubKey)
    d['raw_output_script'] = scriptPubKey.encode('hex')
    d['index'] = i
    return d


def parse_Transaction(vds, is_coinbase):
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['inputs'] = []
    for i in xrange(n_vin):
        o = parse_TxIn(vds)
        if not is_coinbase:
            d['inputs'].append(o)
    n_vout = vds.read_compact_size()
    d['outputs'] = []
    for i in xrange(n_vout):
        o = parse_TxOut(vds, i)
        d['outputs'].append(o)

    d['lockTime'] = vds.read_uint32()
    return d


opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT",
    "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    "OP_NOP1", "OP_NOP2", "OP_NOP3", "OP_NOP4", "OP_NOP5", "OP_CLAIM_NAME", "OP_SUPPORT_CLAIM",
    "OP_UPDATE_CLAIM", "OP_NOP9", "OP_NOP10", ("OP_INVALIDOPCODE", 0xFF),
])


def script_GetOp(bytes):
    i = 0
    while i < len(bytes):
        vch = None
        opcode = ord(bytes[i])
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = ord(bytes[i])
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', bytes, i)
                i += 4
            if i + nSize > len(bytes):
                vch = "_INVALID_" + bytes[i:]
                i = len(bytes)
            else:
                vch = bytes[i:i + nSize]
                i += nSize

        yield (opcode, vch, i)


def script_GetOpName(opcode):
    try:
        return (opcodes.whatis(opcode)).replace("OP_", "")
    except KeyError:
        return "InvalidOp_" + str(opcode)


def decode_script(bytes):
    result = ''
    for (opcode, vch, i) in script_GetOp(bytes):
        if len(result) > 0:
            result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:" % (opcode,)
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True

###############################Claim###########################
class NameClaim(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value
    def __repr__(self):
        return "NameClaim, name:{}, value:{}".format(self.name,self.value)

class ClaimUpdate(object):
    def __init__(self, name, claim_id, value):
        self.name = name
        self.claim_id = claim_id
        self.value = value

    def __repr__(self):
        return "ClaimUpdate, name:{}, claim_id:{}, value:{}".format(self.name, self.claim_id, self.value)
class ClaimSupport(object):
    def __init__(self, name, claim_id):
        self.name = name
        self.claim_id = claim_id

    def __repr__(self):
        return "ClaimSupport, name:{}, claim_id:{}".format(self.name, self.claim_id)

def decode_claim_script(decoded_script):
    if len(decoded_script) <= 6:
        return False
    op = 0
    claim_type = decoded_script[op][0]
    if claim_type == opcodes.OP_UPDATE_CLAIM:
        if len(decoded_script) <= 7:
            return False
    if claim_type not in [
        opcodes.OP_CLAIM_NAME,
        opcodes.OP_SUPPORT_CLAIM,
        opcodes.OP_UPDATE_CLAIM
    ]:
        return False
    op += 1
    value = None
    claim_id = None
    claim = None
    if not (0 <= decoded_script[op][0] <= opcodes.OP_PUSHDATA4):
        return False
    name = decoded_script[op][1]
    op += 1
    if not (0 <= decoded_script[op][0] <= opcodes.OP_PUSHDATA4):
        return False
    if decoded_script[0][0] in [
        opcodes.OP_SUPPORT_CLAIM,
        opcodes.OP_UPDATE_CLAIM
    ]:
        claim_id = decoded_script[op][1]
        if len(claim_id) != 20:
            return False
    else:
        value = decoded_script[op][1]
    op += 1
    if decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        value = decoded_script[op][1]
        op += 1
    if decoded_script[op][0] != opcodes.OP_2DROP:
        return False
    op += 1
    if decoded_script[op][0] != opcodes.OP_DROP and decoded_script[0][0] == opcodes.OP_CLAIM_NAME:
        return False
    elif decoded_script[op][0] != opcodes.OP_2DROP and decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        return False
    op += 1
    if decoded_script[0][0] == opcodes.OP_CLAIM_NAME:
        if name is None or value is None:
            return False
        claim = NameClaim(name, value)
    elif decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        if name is None or value is None or claim_id is None:
            return False
        claim = ClaimUpdate(name, claim_id, value)
    elif decoded_script[0][0] == opcodes.OP_SUPPORT_CLAIM:
        if name is None or claim_id is None:
            return False
        claim = ClaimSupport(name, claim_id)
    return claim, decoded_script[op:]


def get_address_from_output_script(bytes):
    try:
        decoded = [x for x in script_GetOp(bytes)]
    except:
        return None
    r = decode_claim_script(decoded)
    if r is not False:
        claim_info, decoded = r

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return public_key_to_pubkey_address(decoded[0][1])

    # coins sent to black hole
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_0, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return None

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return hash_160_to_pubkey_address(decoded[2][1])

    # strange tx
    match = [opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG,
             opcodes.OP_NOP]
    if match_decoded(decoded, match):
        return hash_160_to_pubkey_address(decoded[2][1])

    # p2sh
    match = [opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL]
    if match_decoded(decoded, match):
        addr = hash_160_to_script_address(decoded[1][1])
        return addr

    return None
