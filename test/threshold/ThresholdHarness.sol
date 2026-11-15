// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Shamir} from "../../src/threshold/Shamir.sol";
import {SealedSlot} from "../../src/threshold/SealedSlot.sol";

/// @notice External wrappers, so tests can expect reverts from the libraries
///         and measure their gas as a contract would pay it.
contract ThresholdHarness {
    function combineAtZero(uint256[] memory xs, uint256[] memory ys) external view returns (uint256) {
        return Shamir.combineAtZero(xs, ys);
    }

    function inverse(uint256 a) external view returns (uint256) {
        return Shamir.inverse(a);
    }

    function keyHash(address app, address sender, uint256 seq, uint256 key) external view returns (bytes32) {
        return SealedSlot.keyHash(app, sender, seq, key);
    }

    function shareHash(address app, address sender, uint256 seq, uint256 index, uint256 share)
        external
        view
        returns (bytes32)
    {
        return SealedSlot.shareHash(app, sender, seq, index, share);
    }

    function keystream(address app, address sender, uint256 seq, uint256 key) external view returns (bytes32) {
        return SealedSlot.keystream(app, sender, seq, key);
    }

    function open(address app, address sender, uint256 seq, uint256 key, bytes32 ct) external view returns (bytes32) {
        return SealedSlot.open(app, sender, seq, key, ct);
    }

    function checkShare(address app, address sender, uint256 seq, uint256 index, uint256 share, bytes32 committed)
        external
        view
        returns (bool)
    {
        return SealedSlot.checkShare(app, sender, seq, index, share, committed);
    }

    function recover(
        address app,
        address sender,
        uint256 seq,
        uint256[] memory indices,
        uint256[] memory shares,
        bytes32 committedKeyHash
    ) external view returns (bool, uint256) {
        return SealedSlot.recover(app, sender, seq, indices, shares, committedKeyHash);
    }
}

/// @notice Deals Shamir shares in Solidity, independently of scripts/threshold.ts.
library TestDealer {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

    /// @notice f(x) for f = coeffs[0] + coeffs[1] x + ... (Horner).
    function evaluate(uint256[] memory coeffs, uint256 x) internal pure returns (uint256 y) {
        for (uint256 i = coeffs.length; i > 0; --i) {
            y = addmod(mulmod(y, x, P), coeffs[i - 1], P);
        }
    }

    /// @notice A degree t - 1 polynomial with f(0) = key, coefficients from `seed`.
    function polynomial(uint256 key, uint256 t, uint256 seed) internal pure returns (uint256[] memory coeffs) {
        coeffs = new uint256[](t);
        coeffs[0] = key % P;
        for (uint256 i = 1; i < t; ++i) {
            coeffs[i] = uint256(keccak256(abi.encode(seed, i))) % P;
        }
    }
}
