pragma solidity ^0.8.7;

contract Test {

    struct code {
        int32 op_code;
        int32[] args;
    }

    function encode (code memory the_code) public pure returns(bytes memory) {
        return abi.encode(the_code);
    }

}