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
    return root, leaf, res_proof, res_bool

def hash_op(op):
    combined = [0, 0, 0, 0]
    combined[0] = op['OpCode']
    combined[1:len(op['args'])+1] = op['args']
    
    return bytes(Web3.solidityKeccak(['int32', 'int32', 'int32', 'int32'], combined)).hex()

def code_mt(codes):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = list(map(hash_op, codes))
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt

def make_store_leaf(x):
    return sha3.keccak_256(encode_abi(['int32'], [x.item()])).hexdigest()

def store_mt(store):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = list(map(make_store_leaf, store))
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt

def hash_rc(rc):
    raw = [rc['PC'], int(rc['OpCode']), rc['args'], sterilize_ints(rc['args_values']), rc['store_mt_root']]
    return bytes(Web3.solidityKeccak(['int32', 'int32', 'int32[]', 'int32[]', 'bytes32'], raw)).hex()

def sterilize_ints(ints):
    return list(map(lambda x: x if (type(x) is int) else x.item(), ints))

def reduced_config_mt(rc):
    mt = merkletools.MerkleTools(hash_type="keccak_256")
    leaves = list(map(hash_rc, rc))
    mt.add_leaf(leaves)
    mt.make_tree()
    return mt