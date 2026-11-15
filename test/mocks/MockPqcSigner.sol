// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title MockPqcSigner
/// @notice A stand-in for ML-DSA-87 in local tests. Foundry's EVM cannot run
///         QoreChain's precompiles, so tests use a keyed hash instead: the public
///         key and every signature are expanded from a secret, and only someone
///         who knows the secret can make a signature the mock verifier accepts.
///         The byte lengths match ML-DSA-87 (2,592-byte key, 4,627-byte
///         signature) so calldata sizes and length checks are realistic.
library MockPqcSigner {
    uint256 internal constant PUBLIC_KEY_LENGTH = 2592;
    uint256 internal constant SIGNATURE_LENGTH = 4627;

    function publicKey(bytes32 secret) internal pure returns (bytes memory) {
        return _expand(keccak256(abi.encode("mock-ml-dsa-87/pk", secret)), PUBLIC_KEY_LENGTH);
    }

    function sign(bytes32 secret, bytes memory message) internal pure returns (bytes memory) {
        return _expand(keccak256(abi.encode("mock-ml-dsa-87/sig", secret, keccak256(message))), SIGNATURE_LENGTH);
    }

    function _expand(bytes32 seed, uint256 length) private pure returns (bytes memory out) {
        out = new bytes(length);
        uint256 words = (length + 31) / 32;
        for (uint256 i = 0; i < words; ++i) {
            bytes32 w = keccak256(abi.encode(seed, i));
            uint256 n = length - i * 32 < 32 ? length - i * 32 : 32;
            for (uint256 j = 0; j < n; ++j) {
                out[i * 32 + j] = w[j];
            }
        }
    }
}
