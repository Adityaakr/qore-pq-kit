// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqAuth} from "../../src/PqAuth.sol";

/// @title PqAuthProbe
/// @notice Runs PqAuth against the REAL precompiles without deploying anything:
///         `scripts/probe.ts` sends this contract's creation code in an
///         `eth_call`, the constructor does the checks, and returns the answer as
///         the call's return data. A revert comes back as the call's error.
contract PqAuthProbe {
    constructor(address account, bytes memory signature, bytes memory signedMessage) {
        bytes memory key = PqAuth.keyOf(account);
        bool valid = PqAuth.verify(key, signature, signedMessage);
        bytes memory out = abi.encode(keccak256(key), key.length, valid, block.chainid);
        assembly {
            return(add(out, 32), mload(out))
        }
    }
}
