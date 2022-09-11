import numpy as np
import enum
import client.utils as utils

class OpCode(enum.IntEnum):
    LOAD = 1
    ADD = 2
    SUB = 3
    COPYID = 4
    COPYDI = 5
    JNZ = 6
    END = 7

class Ram():
    def __init__(self, source):
        self.store = np.zeros(source['size'], dtype=np.int32)
        self.code = source['code']
        self.PC = 0
        self.rc_list = []
        self.code_mt = utils.code_mt(self.code)
    
    def __call__(self):
        while (self.code[self.PC]['OpCode'] != OpCode.END):
            op_code = self.code[self.PC]['OpCode']
            args = self.code[self.PC]['args']

            store_mt = utils.store_mt(self.store)
            args_proof = None
            args_values = None

            reduced_configuration = {
                "PC": self.PC,
                "OpCode": op_code,
                "args": args,
                "args_values": [],
                "args_proofs": [],
                "store_mt_root": '0x' + store_mt.get_merkle_root(),
                "next_op_proof": []
            }

            if op_code == OpCode.LOAD:
                args_values, args_proof = self.load(args, store_mt)
            elif op_code == OpCode.ADD:
                args_values, args_proof = self.add(args, store_mt)
            elif op_code == OpCode.SUB:
                args_values, args_proof = self.sub(args, store_mt)
            elif op_code == OpCode.COPYID:
                args_values, args_proof = self.copy_id(args, store_mt)
            elif op_code == OpCode.COPYDI:
                args_values, args_proof = self.copy_di(args, store_mt)
            elif op_code == OpCode.JNZ:
                args_values, args_proof = self.jnz(args, store_mt)

            reduced_configuration["args_values"] = args_values
            reduced_configuration["args_proofs"] = args_proof
            reduced_configuration["next_op_proof"] = utils.translate_proof(self.code_mt, self.PC)

            self.rc_list.append(reduced_configuration)
            
    
    def load(self, args, store_mt):
        rd_val = self.store[args[1]]
        rd_proof = utils.translate_proof(store_mt, args[1])
        self.store[args[1]] = args[0]
        self.PC = self.PC + 1
        return [rd_val], [rd_proof]
    
    def add(self, args, store_mt):
        rs1 = self.store[args[0]]
        rs2 = self.store[args[1]]
        args_values = [self.store[x] for x in args]
        args_proofs = [utils.translate_proof(store_mt, x) for x in args]
        
        self.store[args[2]] = rs1 + rs2
        self.PC = self.PC + 1
        return args_values, args_proofs 

    def sub(self, args, store_mt):
        rs1 = self.store[args[0]]
        rs2 = self.store[args[1]]
        args_values = [self.store[x] for x in args]
        args_proofs = [utils.translate_proof(store_mt, x) for x in args]
        
        self.store[args[2]] = rs1 - rs2
        self.PC = self.PC + 1
        return args_values, args_proofs

    def copy_id(self, args, store_mt):
        rs = self.store[self.store[args[0]]]
        args_values = [self.store[args[0]], self.store[args[1]], rs]
        args_proofs = [
            utils.translate_proof(store_mt, args[0]),
            utils.translate_proof(store_mt, args[1]),
            utils.translate_proof(store_mt, self.store[args[0]])
            ]
        
        self.store[args[1]] = rs
        self.PC = self.PC + 1
        return args_values, args_proofs

    
    def copy_di(self, args, store_mt):
        rs = self.store[args[0]]
        args_values = [rs, self.store[args[1]], self.store[self.store[args[1]]]]
        args_proofs = [
            utils.translate_proof(store_mt, args[0]),
            utils.translate_proof(store_mt, args[1]),
            utils.translate_proof(store_mt, self.store[args[1]])
            ]
        self.store[self.store[args[1]]] = rs
        self.PC = self.PC + 1

        return args_values, args_proofs
    
    def jnz(self, args, store_mt):
        args_values = [self.store[args[0]]]
        args_proofs = [utils.translate_proof(store_mt, args[0])]

        if self.store[args[0]] > 0:
            self.PC = args[1]
        else:
            self.PC = self.PC + 1

        return args_values, args_proofs


class RamCoder():
    def __init__(self, size):
        self.code = []
        self.source = {
            "size": size,
            "code": self.code
        }

    def load(self, C, rd):
        self.code.append({
            "OpCode": OpCode.LOAD,
            "args": [C, rd]
        })
    
    def add(self, rs1, rs2, rd):
        self.code.append({
            "OpCode": OpCode.ADD,
            "args": [rs1, rs2, rd]
        })
    
    def sub(self, rs1, rs2, rd):
        self.code.append({
            "OpCode": OpCode.SUB,
            "args": [rs1, rs2, rd]
        })

    def copy_id(self, rp, rd):
        self.code.append({
            "OpCode": OpCode.COPYID,
            "args": [rp, rd]
        })
    
    def copy_di(self, rs, rp):
        self.code.append({
            "OpCode": OpCode.COPYDI,
            "args": [rs, rp]
        })
    
    def jnz(self, r, I):
        self.code.append({
            "OpCode": OpCode.JNZ,
            "args": [r, I]
        })
    
    def end(self):
        self.code.append({
            "OpCode": OpCode.END,
            "args": []
        })

class Ram_simple():
    def __init__(self, source):
        self.store = np.zeros(source['size'], dtype=np.int32)
        self.code = source['code']
        self.PC = 0
    
    def __call__(self):
        while (self.code[self.PC]['OpCode'] != OpCode.END):
            op_code = self.code[self.PC]['OpCode']
            args = self.code[self.PC]['args']

            if op_code == OpCode.LOAD:
                self.load(args)
            elif op_code == OpCode.ADD:
                self.add(args)
            elif op_code == OpCode.SUB:
                self.sub(args)
            elif op_code == OpCode.COPYID:
                self.copy_id(args)
            elif op_code == OpCode.COPYDI:
                self.copy_di(args)
            elif op_code == OpCode.JNZ:
                self.jnz(args)
            
    
    def load(self, args ):
        self.store[args[1]] = args[0]
        self.PC = self.PC + 1
    
    def add(self, args ):
        rs1 = self.store[args[0]]
        rs2 = self.store[args[1]]       
        self.store[args[2]] = rs1 + rs2
        self.PC = self.PC + 1

    def sub(self, args ):
        rs1 = self.store[args[0]]
        rs2 = self.store[args[1]]        
        self.store[args[2]] = rs1 - rs2
        self.PC = self.PC + 1

    def copy_id(self, args ):
        rs = self.store[self.store[args[0]]]       
        self.store[args[1]] = rs
        self.PC = self.PC + 1
   
    def copy_di(self, args ):
        rs = self.store[args[0]]
        self.store[self.store[args[1]]] = rs
        self.PC = self.PC + 1
  
    def jnz(self, args ):
        if self.store[args[0]] > 0:
            self.PC = args[1]
        else:
            self.PC = self.PC + 1



