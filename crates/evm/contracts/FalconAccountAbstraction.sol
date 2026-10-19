// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Post-Quantum Account Abstraction (ERC-4337 style) utilizing native Falcon-512 precompile 0x15.
contract FalconAccountAbstraction {
    address public constant FALCON_PRECOMPILE = address(0x15);

    bytes public falconPublicKey; // 897 bytes
    uint256 public nonce;

    event Executed(address indexed target, uint256 value, bytes data);
    event FalconKeyUpdated(bytes newKey);

    error InvalidFalconSignature();
    error ExecutionFailed(bytes revertData);

    constructor(bytes memory _falconPublicKey) payable {
        require(_falconPublicKey.length == 897, "FalconAA: Invalid public key size");
        falconPublicKey = _falconPublicKey;
    }

    /// Verifies post-quantum Falcon-512 signature against the digest of [chainId, contract, nonce, target, value, data]
    /// via STATICCALL to address(0x15).
    function executeUserOp(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata falconSignature
    ) external payable returns (bytes memory result) {
        bytes32 opHash = keccak256(
            abi.encode(block.chainid, address(this), nonce++, target, value, keccak256(data))
        );

        // Precompile input format: [msgHash (32 B)] [falconPubKey (897 B)] [falconSig (~666 B)]
        bytes memory precompileInput = abi.encodePacked(opHash, falconPublicKey, falconSignature);

        (bool success, bytes memory retData) = FALCON_PRECOMPILE.staticcall(precompileInput);
        require(success && retData.length == 32, "FalconAA: Precompile staticcall failed");

        uint256 verified = abi.decode(retData, (uint256));
        if (verified != 1) {
            revert InvalidFalconSignature();
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
