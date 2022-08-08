pragma solidity ^0.8.7;

struct MissmatchInstance {
    uint256 s;
    bytes32[2] z;
    uint256 low;
    uint256 high;
    uint256 middle;
    uint256 deadline;
    address[2] c_address;
    uint8 alg_state; //0 not started, 1 binary search, 2 verify committed step, 3 finished
    address winner; 
    bytes32[2] c_current_hash;
    bytes32 rc_hash_low;
    bytes32[2] rc_hash_high_c;
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

enum req_type {MIDDLE, COMMITTED_STEP, NONE}

contract Missmatch {
    mapping(bytes32 => MissmatchInstance) public state;

    uint32 constant deadline_duration = 5;

    event request_proof_of_middle(bytes32 key, uint256 middle);
    event request_proof_of_committed_step(bytes32 key, uint256 low);

    function start_committed_bs(
        uint256 _s,
        bytes32 _zi,
        bytes32 _zj,
        address _ci_address,
        address _cj_address,
        bytes32 _code_mt_root
    ) public returns(bool) {
        bytes32 key = keccak256(abi.encodePacked(_s, _zi, _zj, _ci_address, _cj_address, _code_mt_root));
        if (state[key].alg_state != 0) {
            return false;
        }

        state[key].c_address[0] = _ci_address;
        state[key].c_address[1] = _cj_address;
        state[key].s = _s;
        state[key].z[0] = _zi;
        state[key].z[1] = _zj;
        state[key].low = 0;
        state[key].high = _s;
        state[key].middle = _s / 2;
        state[key].deadline = block.number + deadline_duration;
        state[key].code_mt_root = _code_mt_root;
        state[key].alg_state = 1;

        emit request_proof_of_middle(key, state[key].middle);
        return true;
    }

    function send_rc_proof(
        proof memory rc_proof,
        bytes32 key
    ) public returns(bool)
    {
        bool _res; 
        req_type _req; 
        MissmatchInstance memory _res_state;
        (_res, _req, _res_state) = MissmatchLib.send_rc_proof(rc_proof, state[key], msg.sender);

        state[key] = _res_state;
        
        if (_req == req_type.MIDDLE) {
            emit request_proof_of_middle(key, state[key].middle);
        }
        else if (_req == req_type.COMMITTED_STEP){
            emit request_proof_of_committed_step(key, state[key].low);
        }

        return _res;
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
        proof memory next_op_proof,
        bytes32 key
    ) public returns(bool)
    {
        committed_step_params memory params = committed_step_params(PC, OpCode, args, args_values, args_proof, store_mt_root, nextOpCode, nextArgs, next_op_proof);
        bool _res; 
        MissmatchInstance memory _res_state;
        (_res, _res_state) = MissmatchLib.send_committed_step(params, state[key], msg.sender);

        state[key] = _res_state;

        return _res;
    }

    function report(bytes32 key) public returns(bool){
        bool _res;
        MissmatchInstance memory _res_state;

        (_res, _res_state) = MissmatchLib.report(state[key]);

        if(_res){
            state[key] = _res_state;
        }
        
        return _res;
    }

    fallback() external payable {
        int n = 0;
    }

} 

library MissmatchLib {

    uint32 constant deadline_duration = 5;

    function send_rc_proof(
        proof memory rc_proof,
        MissmatchInstance memory state,
        address sender
    ) public view returns(bool res, req_type req, MissmatchInstance memory res_state)
    {
        uint8 sender_idx;
        uint8 other_idx;

        if (sender == state.c_address[0]){
            sender_idx = 0;
            other_idx = 1;
        }
        else if(sender == state.c_address[1]){
            sender_idx = 1;
            other_idx = 0;
        }
        else {
            return (false, req_type.NONE, state);
        }

        if (state.alg_state != 1){
            return (false, req_type.NONE, state);
        }
        if (!verify_merkle(rc_proof)){
            state.winner = state.c_address[other_idx];
            return (false, req_type.NONE, state);
        }

        state.c_current_hash[sender_idx] = rc_proof.leaf;

        if (state.c_current_hash[other_idx] == bytes32(0)){
            return (true, req_type.NONE, state);
        }

        if(state.c_current_hash[0] == state.c_current_hash[1]){
            state.low = state.middle;
            state.rc_hash_low = state.c_current_hash[0];
        }
        else {
            state.high = state.middle;
            state.rc_hash_high_c[0] = state.c_current_hash[0];
            state.rc_hash_high_c[1] = state.c_current_hash[1];
        }

        if(state.high == (state.low + 1)){
            state.alg_state = 2;
            //emit request_proof_of_committed_step(low);
            return (true, req_type.COMMITTED_STEP, state);
        }
        else {
            state.middle = ((state.high - state.low) / 2) + state.low;
            state.deadline = block.number + deadline_duration;
            delete state.c_current_hash;
            //emit request_proof_of_middle(middle);
            return (true, req_type.MIDDLE, state);
        }
    }

    function send_committed_step(
        committed_step_params memory params,
        MissmatchInstance memory state,
        address sender
    ) public pure returns(bool res, MissmatchInstance memory res_state)
    {
        uint8 sender_idx;
        uint8 other_idx;
        bytes32 sim_store_mt_root;
        int32 nextPC;
        
        {// initial checks
            if (sender == state.c_address[0]){
                sender_idx = 0;
                other_idx = 1;
            }
            else if(sender == state.c_address[1]){
                sender_idx = 1;
                other_idx = 0;
            }
            else {
                return (false, state);
            }

            if (state.alg_state != 2){
                return (false, state);
            }
        
            bytes32 submitted_rc_hash_low = keccak256(abi.encodePacked(params.PC, params.OpCode, params.args, params.store_mt_root));
            if (state.rc_hash_low != submitted_rc_hash_low){
                state.winner = state.c_address[other_idx];
                state.alg_state = 3;
                return (false, state);
            }
        }

        if (params.OpCode == 1){//LOAD
            if (!verify_arg_value(params.args[1], params.args_values[0], params.args_proof[0], params.store_mt_root)){
                state.winner = state.c_address[other_idx];
                state.alg_state = 3;
                return (false, state);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args[1], params.args[0]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[0].arr, params.args_proof[0].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 2 || params.OpCode == 3){//ADD or SUB
            for (uint8 i = 0; i < 3; i++) {
                if (!verify_arg_value(params.args[i], params.args_values[i], params.args_proof[i], params.store_mt_root)){
                    state.winner = state.c_address[other_idx];
                    state.alg_state = 3;
                    return (false, state);
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
                state.winner = state.c_address[other_idx];
                state.alg_state = 3;
                return (false, state);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args[1], params.args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[1].arr, params.args_proof[1].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 5){//COPYDI
            if (!verify_arg_value(params.args[0], params.args_values[0], params.args_proof[0], params.store_mt_root) ||
            !verify_arg_value(params.args[1], params.args_values[1], params.args_proof[1], params.store_mt_root) ||
            !verify_arg_value(params.args_values[1], params.args_values[2], params.args_proof[2], params.store_mt_root)){
                state.winner = state.c_address[other_idx];
                state.alg_state = 3;
                return (false, state);
            }

            bytes32 next_arg_leaf = keccak256(abi.encodePacked(params.args_values[1], params.args_values[2]));
            sim_store_mt_root = update_merkle(next_arg_leaf, params.args_proof[2].arr, params.args_proof[2].pos);
            nextPC = params.PC + 1;
        }
        else if (params.OpCode == 6){//JNZ
            if (!verify_arg_value(params.args[0], params.args_values[0], params.args_proof[0], params.store_mt_root)){
                state.winner = state.c_address[other_idx];
                state.alg_state = 3;
                return (false, state);
            }

            sim_store_mt_root = params.store_mt_root;
            nextPC = params.args_values[0] > 0 ? params.args[1] : params.PC + 1;
        }

        bytes32 next_op_leaf =  keccak256(abi.encodePacked(nextPC, params.nextOpCode, params.nextArgs));
        if (!verify_merkle(proof(state.code_mt_root, next_op_leaf, params.next_op_proof.arr, params.next_op_proof.pos))){
            state.winner = state.c_address[other_idx];
            state.alg_state = 3;
            return (false, state);
        }

        bytes32 rc_hash_simulated = keccak256(abi.encodePacked(nextPC, params.nextOpCode, params.nextArgs, sim_store_mt_root));
        if (state.rc_hash_high_c[sender_idx] == rc_hash_simulated){
            state.winner = state.c_address[sender_idx];
            state.alg_state = 3;
            return (true, state);
        }
        else{
            state.winner = state.c_address[other_idx];
            state.alg_state = 3;
            return (false, state);
        }

    }

    function report(MissmatchInstance memory state) public view returns(bool res, MissmatchInstance memory res_state)
    {
        if (block.number <= state.deadline || state.alg_state != 1){
            return (false, state);
        }

        if (state.c_current_hash[0] != bytes32(0)){
            state.winner = state.c_address[0];
        }
        else if (state.c_current_hash[1] != bytes32(0)){
            state.winner = state.c_address[1];
        }
        else {
            state.winner = state.c_address[block.number % 2];
        }

        state.alg_state = 3;
        return (true, state);
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