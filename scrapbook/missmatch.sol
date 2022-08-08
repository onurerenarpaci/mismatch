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
    bytes32 code_mt_root;

    event request_proof_of_middle(uint256 middle);
    event request_proof_of_committed_step(uint256 low);

    struct proof{
        bytes32 root;
        bytes32 leaf;
        bytes32[] arr;
        bool[] pos;
    }

    function start_committed_bs(
        uint256 _s,
        bytes32 _zi,
        bytes32 _zj,
        address _ci_address,
        address _cj_address,
        bytes32 _code_mt_root
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
        code_mt_root = _code_mt_root;
        alg_state = 1;

        emit request_proof_of_middle(middle);
        return true;
    }

    function send_rc_proof(
        proof memory rc_proof
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
        if (!verify_merkle(rc_proof)){
            winner = c_address[other_idx];
            return false;
        }

        c_current_hash[sender_idx] = rc_proof.leaf;

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
            alg_state = 2;
            emit request_proof_of_committed_step(low);
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

    function send_committed_step(
        int32 PC,
        int32 OpCode,
        int32[] memory args,
        int32[] memory args_values,
        proof[] memory args_proof,
        bytes32 store_mt_root,
        int32 nextOpCode,
        int32[] memory nextArgs,
        proof memory next_op_proof
    ) public returns(bool)
    {
        uint8 sender_idx;
        uint8 other_idx;
        bytes32 sim_store_mt_root;
        int32 nextPC;
        
        {// initial checks
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

            if (alg_state != 2){
                return false;
            }
        
            bytes32 submitted_rc_hash_low = keccak256(abi.encodePacked(PC, OpCode, args, store_mt_root));
            if (rc_hash_low != submitted_rc_hash_low){
                winner = c_address[other_idx];
                alg_state = 3;
                return false;
            }
        }

        if (OpCode == 1){//LOAD
            if (!verify_arg_value(args[1], args_values[0], args_proof[0], store_mt_root)){
                winner = c_address[other_idx];
                alg_state = 3;
                return false;
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(args[1], args[0]));
            sim_store_mt_root = update_merkle(next_arg_leaf, args_proof[0].arr, args_proof[0].pos);
            nextPC = PC + 1;
        }
        else if (OpCode == 2 || OpCode == 3){//ADD or SUB
            for (uint8 i = 0; i < 3; i++) {
                if (!verify_arg_value(args[i], args_values[i], args_proof[i], store_mt_root)){
                    winner = c_address[other_idx];
                    alg_state = 3;
                    return false;
                }
            }

            {
                int32 result = OpCode == 2 ? args_values[0] + args_values[1] : args_values[0] - args_values[1];
                bytes32 next_arg_leaf = keccak256(abi.encodePacked(args[2], result));
                sim_store_mt_root = update_merkle(next_arg_leaf, args_proof[2].arr, args_proof[2].pos);
            }
            nextPC = PC + 1;
        }
        else if (OpCode == 4){//COPYID
            if (!verify_arg_value(args[0], args_values[0], args_proof[0], store_mt_root) ||
            !verify_arg_value(args[1], args_values[1], args_proof[1], store_mt_root) ||
            !verify_arg_value(args_values[0], args_values[2], args_proof[2], store_mt_root)){
                winner = c_address[other_idx];
                alg_state = 3;
                return false;
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(args[1], args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, args_proof[1].arr, args_proof[1].pos);
            nextPC = PC + 1;
        }
        else if (OpCode == 5){//COPYDI
            if (!verify_arg_value(args[0], args_values[0], args_proof[0], store_mt_root) ||
            !verify_arg_value(args[1], args_values[1], args_proof[1], store_mt_root) ||
            !verify_arg_value(args_values[1], args_values[2], args_proof[2], store_mt_root)){
                winner = c_address[other_idx];
                alg_state = 3;
                return false;
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(args_values[1], args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, args_proof[2].arr, args_proof[2].pos);
            nextPC = PC + 1;
        }
        else if (OpCode == 6){//JNZ
            if (!verify_arg_value(args[0], args_values[0], args_proof[0], store_mt_root)){
                winner = c_address[other_idx];
                alg_state = 3;
                return false;
            }

            sim_store_mt_root = store_mt_root;
            nextPC = args_values[0] > 0 ? args[1] : PC + 1;
        }

        bytes32 next_op_leaf =  keccak256(abi.encodePacked(nextPC, nextOpCode, nextArgs));
        if (!verify_merkle(proof(code_mt_root, next_op_leaf, next_op_proof.arr, next_op_proof.pos))){
            winner = c_address[other_idx];
            alg_state = 3;
            return false;
        }

        bytes32 rc_hash_simulated = keccak256(abi.encodePacked(nextPC, nextOpCode, nextArgs, sim_store_mt_root));
        if (rc_hash_high_c[sender_idx] == rc_hash_simulated){
            winner = c_address[sender_idx];
            alg_state = 3;
            return true;
        }
        else{
            winner = c_address[other_idx];
            alg_state = 3;
            return false;
        }

    }

    function report() public returns(bool)
    {
        if (block.number <= deadline || alg_state != 1){
            return false;
        }

        if (c_current_hash[0] != bytes32(0)){
            winner = c_address[0];
        }
        else if (c_current_hash[1] != bytes32(0)){
            winner = c_address[1];
        }
        else {
            winner = c_address[block.number % 2];
        }

        alg_state = 3;
        return true;
    }

    function verify_merkle(
        proof memory mk_proof
    ) internal pure returns(bool)
    {
        bytes32 computedHash = mk_proof.leaf;

        for (uint256 i = 0; i < mk_proof.arr.length; i++) {
            bytes32 proofElement = mk_proof.arr[i];

            if (mk_proof.pos[i]) {
            // Hash(current computed hash + current element of the proof)
            computedHash = keccak256(abi.encode(computedHash, proofElement));
            } else {
            // Hash(current element of the proof + current computed hash)
            computedHash = keccak256(abi.encode(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == mk_proof.root;
    }

    function update_merkle(
        bytes32 leaf,
        bytes32[] memory proof_arr,
        bool[] memory proofPos
    ) internal pure returns(bytes32)
    {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof_arr.length; i++) {
            bytes32 proofElement = proof_arr[i];

            if (proofPos[i]) {
            // Hash(current computed hash + current element of the proof)
            computedHash = keccak256(abi.encode(computedHash, proofElement));
            } else {
            // Hash(current element of the proof + current computed hash)
            computedHash = keccak256(abi.encode(proofElement, computedHash));
            }
        }
        return computedHash;
    }

    function verify_arg_value(
        int32 arg_idx,
        int32 arg_value,
        proof memory arg_proof,
        bytes32 store_mt_root
    ) internal pure returns(bool){
        bytes32 arg_leaf = keccak256(abi.encodePacked(arg_idx, arg_value));
        proof memory new_proof = proof(store_mt_root, arg_leaf, arg_proof.arr, arg_proof.pos);
        return verify_merkle(new_proof);
    }
}