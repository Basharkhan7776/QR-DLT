// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Classical Account Abstraction (ERC-4337 style) utilizing standard ECDSA ecrecover (0x01).
contract EcdsaAccountAbstraction {
    address public owner;
    uint256 public nonce;

    event Executed(address indexed target, uint256 value, bytes data);
    event OwnerUpdated(address newOwner);

    error InvalidEcdsaSignature();
    error ExecutionFailed(bytes revertData);

    constructor(address _owner) payable {
        require(_owner != address(0), "EcdsaAA: Invalid owner address");
        owner = _owner;
    }

    /// Verifies classical ECDSA signature against the digest of [chainId, contract, nonce, target, value, data]
    /// via native ecrecover (address 0x01).
    function executeUserOp(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata ecdsaSignature // 65 bytes: [r (32 B)] [s (32 B)] [v (1 B)]
    ) external payable returns (bytes memory result) {
        bytes32 opHash = keccak256(
            abi.encode(block.chainid, address(this), nonce++, target, value, keccak256(data))
        );

        // Standard Ethereum signed message format
        bytes32 ethSignedOpHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", opHash)
        );

        require(ecdsaSignature.length == 65, "EcdsaAA: Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(ecdsaSignature.offset)
            s := calldataload(add(ecdsaSignature.offset, 32))
            v := byte(0, calldataload(add(ecdsaSignature.offset, 64)))
        }

        address signer = ecrecover(ethSignedOpHash, v, r, s);
        if (signer != owner || signer == address(0)) {
            revert InvalidEcdsaSignature();
        }

        (bool execSuccess, bytes memory execRet) = target.call{value: value}(data);
        if (!execSuccess) {
            revert ExecutionFailed(execRet);
        }

        emit Executed(target, value, data);
        return execRet;
    }

    receive() external payable {}
}
