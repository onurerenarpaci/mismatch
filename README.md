# Mismatch
This is an implementation of the Mismatch Check Protocol described in [Küpçü, A., Safavi-Naini, R. (2022)](https://link.springer.com/chapter/10.1007/978-3-030-93944-1_16#chapter-info)

Additionally, it includes an implementation of Mismatch Resolution Protocol described in the “Delegate: Coalition, Sybil, and Copy Proof Incentivized Outsourced Computation with Smart Contracts.” by A. Küpçü and O. Biçer.

Lastly, it also includes an implementation of the Match Check Protocol described in [Küpçü, A., Safavi-Naini, R. (2022)](https://link.springer.com/chapter/10.1007/978-3-030-93944-1_16#chapter-info)

# Tech Stack

## Solidity 
We decided to use solidity as our smart contract language because as of now, it is by far the most established smart contract language. It has extensive resources for learning and troubleshooting.

## Python 
I decided to use python for implementation of the client applications. Because I have prior experience with it. It also has the web3.py library which is crucial for interacting with Ethereum providers.

## Truffle
I decided to use truffle as my smart contract development/testing framework, mainly because it provides deployment scripts. It is really helpful for complex deployments with multiple contracts and libraries. It also comes with a test provider called Ganache, which is helpful for using Remix IDE and web3.py on the same test blockchain.

# Smart Contract Design
It was not possible to directly implement the pseudo code written in the [Küpçü, A., Safavi-Naini, R. (2022)](https://link.springer.com/chapter/10.1007/978-3-030-93944-1_16#chapter-info). Because it was written with the idea that Smart contract is a fully autonomous agent that is working independently from other participants of the protocol. But in reality smart contracts work with the ‘must call to execute’ paradigm. Every computation that takes place on the blockchain has a cost (gas), so every code that runs on the blockchain is a result of a transaction sent by a person. When someone sends a transaction they put some amount of gas to cover the cost of the transaction. If the gas runs out while trying to run the code, execution halts. In practical terms, this means that we can’t write a smart contract that runs by itself, or listens for events etc.
So, I re-designed the algorithms with this in mind.

# Random Access Machine
[Küpçü, A., Safavi-Naini, R. (2022)](https://link.springer.com/chapter/10.1007/978-3-030-93944-1_16#chapter-info) describes the computation trace with turing machines, which is appropriate for building theoretical foundations. However, we should use something that is more suitable for real world applications. Random Access Machines are a good abstraction of real computers and I decided to use the read-modify-write model of [Cook and Reckhow](https://doi.org/10.1016/S0022-0000(73)80029-7)

# Merkle Hash Tree
I needed a merkle hash tree implementation in python, first I thought about implementing it myself but then I found the pymerkletools package. It did have all the functionality I needed, so I decided to use this instead. It did not have the keccak256 hash function, which is what ethereum virtual machine (EVM) use, so I modified it to work with keccak256.

# ram.py
ram.py includes the python random access machine implementation

There is an IntEnum for opcodes named ‘OpCode’, this helps with readability, while still storing the opcodes as integers.

There is a class named ‘Ram’, this class implements the logic of the random access machine. To initialize it, a source code must be supplied. There are five properties in this class:  
store: an int32 numpy array, with the size specified in the source code  
code: list of opcodes and their arguments, taken from the source code  
PC: program counter, initialized to 0  
rc_list: the list of reduced configurations, it gets filled as the code is being executed  
code_mt: merkle tree of the code  

There are 7 functions corresponding to each opcode in this class, each of them takes the action dictated by the arguments and the opcode itself, then they produce merkle tree proofs for the related variables in the store.

Lastly there is a \_\_call__ function in this class which executes the source code and creates the reduced configuration list.

Additionally there is another class called ‘RamCoder’. This class is created just for convenience. Instead of manually creating the source code object, this class provides simple functions to create the object easily. The user can initialize it by giving the size of the storage, then they can build the source code by just calling the opcode functions one by one.

# utils.py
This file contains frequently used functions throughout the whole implementation.
For each function, I provided detailed explanations about their purpose in the code with comments.

# mismatch.sol
This is the sol file that includes the complete implementation of the Mismatch Resolution protocol. There are 2 contracts and 1 library in this file and each one of them has their own complex structure, so they will be explained separately in the following sections. 

The MismatchInstance struct represents the state of a single Mismatch Check between two contactors. 

The proof struct represents a merkle proof, it has the same structure with the python implementation of the merkle proof.

The committed_step_params struct is created out of necessity, Its purpose is to mitigate the  “stack too deep” error that the solidity compiler gives when there are too many variables floating around. For code clarity, I wouldn't prefer creating this struct if it was possible.

# MismatchLib
This library contains the logic for executing a single Mismatch Check between two contractors. All the functions inside are pure functions, meaning they don't affect the state of the EVM, they just return values based on their inputs.
### verify_merkle
As the name suggests this function takes a merkle tree proof and verifies it on Ethereum.
### update_merkle 
Given a merkle proof of some leaf, and a different new leaf, this function calculates the merkle root hash when the original leaf is swapped with the new leaf. This function is critical for simulating the reduced configurations.
### verify_arg_value 
This function is used to verify the claim that the value of the store at “arg_idx” is “arg_value”.

The “send_rc_proof”, “send_committed_step”, and “report” functions are implementations of the functions described in the Smart Contract Design section. Refer to that section for their inner working mechanisms.

Mismatch
This contract is mainly a storage contract, meaning that it delegates its logic to MismatchLib and its primary purpose is to allow execution of multiple Mismatch Checks and manage their state.

There is a mapping called “state” it has bytes32 keys and MismatchInstance structs as values. This mapping holds the data for all the Mismatch Checks happened so far, Mismatch Checks happening currently, and it will hold the data for future Mismatch Checks as well. If that sounds inefficient check out how mapping works in Solidity.

With the start_committed_bs function a new Mismatch Check initializes. The key for this Mismatch Check is constructed by taking the keccak256 of all the inputs to the function, this ensures that every Mismatch Check gets a unique key.

There are two events defined in this class. The request_proof_of_middle event is emitted during the binary search phase. It lets contractors know that proof is requested for a particular leaf of reduced configuration. The request_proof_of_committed_step event is emitted for the “verify committed step” phase. It lets contractors know that a particular reduced configuration and its storage proofs is requested.

# MismatchResolve
This contract is the implementation of the Mismatch resolution algorithm described in the “Complete Algorithm of Delegate” section in the Delegate paper. It uses the Mismatch contract as a building block. 

This contract has a struct named resolution, it represents the state of a single resolution. There is also a mapping called state,  very similar to the one in the Mismatch contract. Its purpose is to store all the resolution states. 

There are two public functions, “start_resolution” is meant to be called by the previous part of the delegate protocol and “on_mismatch_result” meant to be called by the problem giver. 
“start_resolution” sets the initial state variables and starts the first Mismatch check. 
“on_mismatch_result” is called when a previously started Mismatch Check returns a result. Since, the Mismatch contract itself will not call this function, the problem giver should observe the ongoing Mismatch Check and call this function when it is finished. The function applies the logic described in the pseudo code, updates the state of the resolution, and starts a new Mismatch Check if it is not done yet.

# Jupyter Notebooks for Testing
There are a few notebooks I wrote for testing different parts of the protocol.
“test_binary_search.ipynb” is for testing only the binary search phase of the protocol. It creates two almost identical merkle trees, one has the correct sequence for the first 32 fibonacci numbers as leaves. The other one is the same but missing the number “55”. We are expecting the protocol to find the point of disagreement between these two merkle trees. It builds and deploys the contract. It calls the start_committed_bs. It then creates two asynchronous loops representing the two contractors. Each listening for the “request proof of middle” event. When they receive the event they call “send_rc_proof” with their proofs. At the end, we can see the request_proof_of_committed_step has been emitted with the correct parameter.
“test_mismatch.ipynb” is for testing a previous implementation of the mismatch. This version can be found in the scrapbook folder with the name “mismatch.sol”. In this version there was no storage and logic separation and the contract was built for just one Mismatch Check. The test builds and deploys the contract, there is also the option of connecting to a contract that is already deployed on the blockchain.


This part of the code creates a simple source code that multiplies 5 with 7, and it runs it on the random access machine. 

Then we create our first merkle tree with the correct reduced configuration list, afterwards, we create a corrupted version of the reduced configuration list, and create a merkle tree out of that too.

We then start our Mismatch Check by calling “start_committed_bs” and pass the length of the merkle tree, the roots of the two newly created merkle trees, account addresses of contractors, and the merkle root of the source code.
Then there is the asynchronous loop part similar to the “test_binary_search.ipynb”, but there are two versions of this code block. The first code block which uses event filters is the correct version, however the ganache test network that I was using for debugging had problems with event filters so I made a version which does not use event filters.
Here, we do the binary search same as the “test_binary_search.ipynb”, then we call the handle_verify_committed_step, and we can see the winner address is the address of the diligent contractor.

