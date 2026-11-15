// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MockPqcSigner} from "./MockPqcSigner.sol";

/// @title MockPqcVerify
/// @notice Etched at 0x…0A01 in tests. Verifies `MockPqcSigner` signatures for
///         keys whose secret the test registered, and can imitate the ways the
///         real precompile can fail: an inactive precompile (success with empty
///         data), a revert, a short answer, or a non-boolean word.
contract MockPqcVerify {
    enum Mode {
        Normal,
        EmptyReturn,
        Revert,
        ShortReturn,
        BadWord,
        AlwaysTrue
    }

    Mode public mode;
    mapping(bytes32 pubkeyHash => bytes32 secret) public secretOf;
    uint256 public calls;

    function setMode(Mode m) external {
        mode = m;
    }

    function setSecret(bytes32 pubkeyHash, bytes32 secret) external {
        secretOf[pubkeyHash] = secret;
    }

    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool)
    {
        Mode m = mode;
        if (m == Mode.EmptyReturn) {
            assembly {
                return(0, 0)
            }
        }
        if (m == Mode.Revert) revert("mock: precompile reverted");
        if (m == Mode.ShortReturn) {
            assembly {
                mstore(0, 1)
                return(0, 16)
            }
        }
        if (m == Mode.BadWord) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (m == Mode.AlwaysTrue) return true;
        bytes32 secret = secretOf[keccak256(pubkey)];
        if (secret == bytes32(0) || signature.length != MockPqcSigner.SIGNATURE_LENGTH) return false;
        return keccak256(signature) == keccak256(MockPqcSigner.sign(secret, message));
    }
}
