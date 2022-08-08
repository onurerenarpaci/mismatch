from web3 import Web3
import merkletools
import sha3
from eth_abi.abi import encode_abi

def translate_proof(mt_ins, x):
    root = '0x' + mt_ins.get_merkle_root()
    leaf = '0x' + mt_ins.get_leaf(x)
    res_proof = []
    res_bool = []
    for p in mt_ins.get_proof(x):
        if list(p.keys())[0] == 'left':
            res_proof.append('0x' + p['left'])
            res_bool.append(False)
        else:
            res_proof.append('0x' + p['right'])
            res_bool.append(True)
    return {"root":root, "leaf":leaf, "arr":res_proof, "pos":res_bool}

def hash_op(PC, op):
    raw = [PC, int(op['OpCode']), op['args']]
    return bytes(Web3.solidityKeccak(['int32', 'int32', 'int32[]'], raw)).hex()

def code_mt(codes):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = [hash_op(PC, op) for PC, op in enumerate(codes)]
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt

def make_store_leaf(idx, x):
    return bytes(Web3.solidityKeccak(['int32', 'int32'], [idx, x.item()])).hex()

def store_mt(store):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = [make_store_leaf(idx, x) for idx, x in enumerate(store)]
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt

def hash_rc(rc):
    raw = [rc['PC'], int(rc['OpCode']), rc['args'], rc['store_mt_root']]
    return bytes(Web3.solidityKeccak(['int32', 'int32', 'int32[]', 'bytes32'], raw)).hex()

def sterilize_ints(ints):
    return list(map(lambda x: x if (type(x) is int) else x.item(), ints))

def reduced_config_mt(rc):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = list(map(hash_rc, rc))
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt