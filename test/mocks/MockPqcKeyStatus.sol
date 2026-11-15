// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title MockPqcKeyStatus
/// @notice Etched at 0x…0A02 in tests. Answers `pqcKeyStatus` from entries the
///         test sets, in the four-value shape of chain v3.2.4 and later, and can
///         imitate an inactive precompile (success with empty data).
contract MockPqcKeyStatus {
    struct Entry {
        bool registered;
        uint8 algorithmId;
        bytes pubkey;
        bool possessionProven;
    }

    mapping(address => Entry) internal entries;
    bool public emptyReturn;

    function set(address account, bool registered, uint8 algorithmId, bytes calldata pubkey, bool possessionProven)
        external
    {
        entries[account] = Entry(registered, algorithmId, pubkey, possessionProven);
    }

    function setEmptyReturn(bool on) external {
        emptyReturn = on;
    }

    function pqcKeyStatus(address account) external view returns (bool, uint8, bytes memory, bool) {
        if (emptyReturn) {
            assembly {
                return(0, 0)
            }
        }
        Entry storage e = entries[account];
        return (e.registered, e.algorithmId, e.pubkey, e.possessionProven);
    }
}
