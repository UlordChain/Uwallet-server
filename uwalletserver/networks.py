"""
Main network and testnet3 definitions
"""

#TODO: add regtest
#NOTICE: This port may be 9456
params = {
    'unet_main': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 130,
        'script_address_prefix': 16, #204
        'genesis_hash': '00000a98aa88364a5105f3d831368f823e14291a9cd2aba50d6eb5a416b97630',
        'default_rpc_port': 9457  #9998
    },
    'unet_test': {
        'pubkey_address': 0,
        'script_address': 5,
        'pubkey_address_prefix': 66,
        'script_address_prefix': 239,
        'genesis_hash': '00000a98aa88364a5105f3d831368f823e14291a9cd2aba50d6eb5a416b97630',
        'default_rpc_port': 9457  #9998
    }
}
