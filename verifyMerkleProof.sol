pragma solidity ^0.8.7;

contract MerkleProof {
  function verify(
    bytes32 root,
    bytes32 leaf,
    bytes32[] memory proof,
    bool[] memory proofPos
  )
    public
    pure
    returns (bool)
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