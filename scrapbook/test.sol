pragma solidity ^0.8.7;

contract Test {

    struct proof{
        bytes32 root;
        bytes32 leaf;
        bytes32[] arr;
        bool[] pos;
    }

    function send_committed_step(
        int32 PC
        ,int32 OpCode
        ,int32[] memory args
        ,int32[] memory args_values
        ,proof[] memory args_proof
        ,bytes32 store_mt_root
        ,int32 nextOpCode
        //,int32 nextArgs
        //,proof memory next_op_proof
    ) public returns(int32)
    {
        return PC;
    }

}