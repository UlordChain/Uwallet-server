"""
Main network and testnet3 definitions
"""

#TODO: add regtest
#NOTICE: This port may be 9456
params = {
    'ulord_main': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 68,#130,#68,
        'script_address_prefix': 63,#125,#63, 
        'genesis_hash': '0000079b37c3c290dc81e95bca28aa7df5636145ae35ebee86e10cc3cce96fb2',
        'default_rpc_port': 9889#19889#9889
    },
    'ulord_test': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 130,
        'script_address_prefix': 125,
        'genesis_hash': '000009c278dda2285ff7d1595d919b2ae1f3728306409f50e374ea313391db8f',
        'default_rpc_port': 19889  #9998
    }
}
