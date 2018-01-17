"""
Main network and testnet3 definitions
"""

#TODO: add regtest
#NOTICE: This port may be 9456
params = {
    'unet_main': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 36,
        'script_address_prefix': 16, #204
        'genesis_hash': '0002c1ef6d2dea451635ff2d7e4be5e660f8c78c91524a1df0d6e1e501661838',
        'default_rpc_port': 9457  #9998
    },
    'unet_test': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 66,
        'script_address_prefix': 239,
        'genesis_hash': '0002c1ef6d2dea451635ff2d7e4be5e660f8c78c91524a1df0d6e1e501661838',
        'default_rpc_port': 9457  #9998
    }
}
