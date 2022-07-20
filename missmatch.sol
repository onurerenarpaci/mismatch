pragma solidity ^0.8.7;

contract Missmatch {
    uint256 s;
    bytes32[2] z;
    uint256 low;
    uint256 high;
    uint256 middle;
    uint256 deadline;
    uint32 constant deadline_duration = 5;
    address[2] c_address;
    uint8 alg_state = 0; //0 not started, 1 binary search, 2 verify committed step, 3 finished
    address public winner; 
    bytes32[2] c_current_hash;
    bytes32 rc_hash_low;
    bytes32[2] rc_hash_high_c;

    event request_proof_of_middle(uint256 middle);
    event request_proof_of_committed_step(uint256 high);

    function start_committed_bs(
        uint256 _s,
        bytes32 _zi,
        bytes32 _zj,
        address _ci_address,
        address _cj_address
    ) public returns (bool)
    {
        c_address[0] = _ci_address;
        c_address[1] = _cj_address;
        s = _s;
        z[0] = _zi;
        z[1] = _zj;
        low = 0;
        high = _s;
        middle = _s / 2;
        deadline = block.number + deadline_duration;
        alg_state = 1;

        emit request_proof_of_middle(middle);
        return true;
    }

    function send_rc_proof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof,
        bool[] memory proofPos
    ) public returns(bool)
    {
        uint8 sender_idx;
        uint8 other_idx;

        if (msg.sender == c_address[0]){
            sender_idx = 0;
            other_idx = 1;
        }
        else if(msg.sender == c_address[1]){
            sender_idx = 1;
            other_idx = 0;
        }
        else {
            return false;
        }

        if (alg_state != 1){
            return false;
        }
        if (!verify_merkle(root, leaf, proof, proofPos)){
            winner = c_address[other_idx];
            return false;
        }

        c_current_hash[sender_idx] = leaf;

        if (c_current_hash[other_idx] == bytes32(0)){
            return true;
        }

        if(c_current_hash[0] == c_current_hash[1]){
            low = middle;
            rc_hash_low = c_current_hash[0];
        }
        else {
            high = middle;
            rc_hash_high_c[0] = c_current_hash[0];
            rc_hash_high_c[1] = c_current_hash[1];
        }

        if(high == (low + 1)){
            alg_state = 3;
            emit request_proof_of_committed_step(high);
            return true;
        }
        else {
            middle = ((high - low) / 2) + low;
            deadline = block.number + deadline_duration;
            delete c_current_hash;
            emit request_proof_of_middle(middle);
            return true;
        }
    }

    function verify_merkle(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof,
        bool[] memory proofPos
    ) public pure returns (bool)
    {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (proofPos[i]) {
            // Hash(current computed hash + current element of the proof)
            computedHash = keccak256(abi.encode(computedHash, proofElement));
            } else {
            // Hash(current element of the proof + current computed hash)
            computedHash = keccak256(abi.encode(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
}