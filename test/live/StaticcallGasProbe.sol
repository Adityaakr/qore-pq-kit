// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title StaticcallGasProbe
/// @notice Measures one STATICCALL on a live chain without deploying: send the
///         creation code as an `eth_call` with no `to`. The constructor calls
///         `target` with `input` and returns
///         abi.encode(ok, returnLength, firstWord, gasUsed, returnData),
///         where gasUsed is the gas the STATICCALL itself consumed.
///         Used by scripts/pqc-gas-probe.ts (spike S6).
contract StaticcallGasProbe {
    constructor(address target, bytes memory input) {
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = target.staticcall(input);
        g -= gasleft();
        uint256 word = ret.length >= 32 ? abi.decode(ret, (uint256)) : type(uint256).max;
        bytes memory out = abi.encode(ok, ret.length, word, g, ret);
        assembly {
            return(add(out, 0x20), mload(out))
        }
    }
}
