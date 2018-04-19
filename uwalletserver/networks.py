"""
Main network and testnet3 definitions
"""

#TODO: add regtest
#NOTICE: This port may be 9456
params = {
    'unet_main': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 130,#68,
        'script_address_prefix': 125,#63, #204
        'genesis_hash': '000f378be841f44e75346eebd931b13041f0dee561af6a80cfea6669c1bfec03',
        'default_rpc_port': 19889#9889
    },
    'unet_test': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 130,
        'script_address_prefix': 125,
        'genesis_hash': '000009c278dda2285ff7d1595d919b2ae1f3728306409f50e374ea313391db8f',
        'default_rpc_port': 19889  #9998
    }
}
