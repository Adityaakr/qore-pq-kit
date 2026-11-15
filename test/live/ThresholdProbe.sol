// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Shamir} from "../../src/threshold/Shamir.sol";
import {SealedSlot} from "../../src/threshold/SealedSlot.sol";

/// @title ThresholdProbe
/// @notice Runs the threshold libraries on a live chain without deploying
///         anything: send this contract's creation code as an `eth_call` with
///         no `to` (`cast call --create`), and the constructor's answer comes
///         back as the call's return data. No account, gas or funds needed.
///
/// It recombines case 0 of vectors/threshold.json (2-of-3, shares 1 and 3)
/// with the chain's real modexp precompile, and returns
/// abi.encode(chainid, key, keyHash, plaintext, gasUsed).
contract ThresholdProbe {
    address private constant APP = 0x1111111111111111111111111111111111111111;
    address private constant SENDER = 0x2222222222222222222222222222222222222222;

    constructor(uint256[] memory xs, uint256[] memory ys, bytes32 ct, uint256 seq) {
        uint256 g = gasleft();
        uint256 key = Shamir.combineAtZero(xs, ys);
        g -= gasleft();
        bytes memory out = abi.encode(
            block.chainid, key, SealedSlot.keyHash(APP, SENDER, seq, key), SealedSlot.open(APP, SENDER, seq, key, ct), g
        );
        assembly {
            return(add(out, 0x20), mload(out))
        }
    }
}
