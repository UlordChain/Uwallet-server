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
        'genesis_hash': '000002287d4bdfb69539d264be0eae5f08c8f990732b84cb6c0834bcee80de3a',
        'default_rpc_port': 9457  #9998
    },
    'unet_test': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 66,
        'script_address_prefix': 239,
        'genesis_hash': '000002287d4bdfb69539d264be0eae5f08c8f990732b84cb6c0834bcee80de3a',
        'default_rpc_port': 9457  #9998
    }
}
