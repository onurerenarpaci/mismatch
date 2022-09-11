pragma solidity ^0.8.7;
pragma abicoder v2;

struct MatchCheckInstance {
    uint256 s;
    bytes32 z;
    uint256 deadline;
    address[2] c_address;
    uint8 alg_state; //0 not started, 1 proof requested, 2 finished
    bool[2] is_not_copy;
    bytes32[2] submitted_leafs;
    bytes32 code_mt_root;
}
struct proof{
    bytes32 root;
    bytes32 leaf;
    bytes32[] arr;
    bool[] pos;
}

struct committed_step_params{
    int32 PC;
    int32 OpCode;
    int32[] args;
    int32[] args_values;
    proof[] args_proof;
    bytes32 store_mt_root;
    int32 nextOpCode;
    int32[] nextArgs;
    proof next_op_proof;    
}

contract MatchCheck {
    mapping(bytes32 => MatchCheckInstance) public state;

    uint32 constant deadline_duration = 5;

    event request_proof(bytes32 key, address c, uint256 n);

    function request_mh_proof(
        uint256 _s,
        bytes32 _z,
        address _ci_address,
        address _cj_address,
        bytes32 _code_mt_root
    ) public returns(bool) {
        bytes32 key = keccak256(abi.encodePacked(_s, _z, _ci_address, _cj_address, _code_mt_root));
        if (state[key].alg_state != 0) {
            return false;
        }

        state[key].c_address[0] = _ci_address;
        state[key].c_address[1] = _cj_address;
        state[key].s = _s;
        state[key].z = _z;
        state[key].deadline = block.number + deadline_duration;
        state[key].code_mt_root = _code_mt_root;
        state[key].alg_state = 1;

        emit request_proof(key, _ci_address, _s/3);
        emit request_proof(key, _cj_address, 2 * (_s/3));
        return true;
    }

    function send_proof(
        proof memory rc_proof,
        proof memory rc_proof_high,
        committed_step_params memory params,
        bytes32 key
    )public returns(bool)
    {
        uint8 sender_idx;
        uint8 other_idx;

        require(state[key].alg_state == 1);
        
        if (msg.sender == state[key].c_address[0]){
            sender_idx = 0;
            other_idx = 1;
        }
        else if(msg.sender == state[key].c_address[1]){
            sender_idx = 1;
            other_idx = 0;
        }
        else {
            return(false);
        }

        if (state[key].submitted_leafs[other_idx] != bytes32(0) &&
        state[key].submitted_leafs[other_idx] == rc_proof.leaf
        ) {
            state[key].alg_state = 2;
            return(false);
        }

        if (verify_merkle(rc_proof) && 
        verify_merkle(rc_proof_high) && 
        send_committed_step(params, rc_proof_high.leaf, key)) {
            state[key].is_not_copy[sender_idx] = true;
            state[key].submitted_leafs[sender_idx] = rc_proof.leaf;
            return(true);
        }
        else {
            return(false);
        }
    }

    function send_committed_step(
        committed_step_params memory params,
        bytes32 rc_hash_high,
        bytes32 key
    ) internal view returns(bool res)
    {
        uint8 sender_idx;
        uint8 other_idx;
        bytes32 sim_store_mt_root;
        int32 nextPC;
        MatchCheckInstance storage State = state[key];
        
        {// initial checks
            if (msg.sender == State.c_address[0]){
                sender_idx = 0;
                other_idx = 1;
            }
            else if(msg.sender == State.c_address[1]){
                sender_idx = 1;
                other_idx = 0;
            }
            else {
                return (false);
            }

            if (State.alg_state != 1){
                return (false);
            }
        
            bytes32 submitted_rc_hash_low = keccak256(abi.encodePacked(params.PC, params.OpCode, params.args, params.store_mt_root));
            if (State.submitted_leafs[sender_idx] != submitted_rc_hash_low){
                return (false);
            }
        }

        if (params.OpCode == 1){//LOAD
            if (!verify_arg_value(params.args[1], params.args_values[0], params.args_proof[0], params.store_mt_root)){
                return (false);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args[1], params.args[0]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[0].arr, params.args_proof[0].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 2 || params.OpCode == 3){//ADD or SUB
            for (uint8 i = 0; i < 3; i++) {
                if (!verify_arg_value(params.args[i], params.args_values[i], params.args_proof[i], params.store_mt_root)){
                    return (false);
                }
            }

            {
                int32 result = params.OpCode == 2 ? params.args_values[0] + params.args_values[1] : params.args_values[0] - params.args_values[1];
                bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args[2], result));
                sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[2].arr, params.args_proof[2].pos);
            }
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 4){//COPYID
            if (!verify_arg_value(params.args[0], params.args_values[0], params.args_proof[0], params.store_mt_root) ||
            !verify_arg_value(params.args[1], params.args_values[1], params.args_proof[1], params.store_mt_root) ||
            !verify_arg_value(params.args_values[0], params.args_values[2], params.args_proof[2], params.store_mt_root)){
                return (false);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args[1], params.args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[1].arr, params.args_proof[1].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 5){//COPYDI
            if (!verify_arg_value(params.args[0], params.args_values[0], params.args_proof[0], params.store_mt_root) ||
            !verify_arg_value(params.args[1], params.args_values[1], params.args_proof[1], params.store_mt_root) ||
            !verify_arg_value(params.args_values[1], params.args_values[2], params.args_proof[2], params.store_mt_root)){
                return (false);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args_values[1], params.args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[2].arr, params.args_proof[2].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 6){//JNZ
            if (!verify_arg_value(params.args[0], params.args_values[0], params.args_proof[0], params.store_mt_root)){
                return (false);
            }

            sim_store_mt_root = params.store_mt_root;
            nextPC = params.args_values[0] > 0 ? params.args[1] : params.PC + 1;
        }

        bytes32 next_op_leaf =  keccak256(abi.encodePacked(nextPC, params.nextOpCode, params.nextArgs));
        if (!verify_merkle(proof(State.code_mt_root, next_op_leaf, params.next_op_proof.arr, params.next_op_proof.pos))){
            return (false);
        }

        bytes32 rc_hash_simulated = keccak256(abi.encodePacked(nextPC, params.nextOpCode, params.nextArgs, sim_store_mt_root));
        if (rc_hash_high == rc_hash_simulated){
            return (true);
        }
        else{
            return (false);
        }

    }

    function report(
        bytes32 key
    )public returns(bool) {
        if (block.number <= state[key].deadline || state[key].alg_state != 1){
            return(false);
        }
        else {
            state[key].alg_state = 2;
            return(true);
        }
    }

    function get_results(
        bytes32 key
    )public view returns(bool[2] memory) {
        return state[key].is_not_copy;
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