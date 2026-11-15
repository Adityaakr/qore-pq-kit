// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqAuth} from "../src/PqAuth.sol";
import {MockPqcVerify} from "./mocks/MockPqcVerify.sol";
import {MockPqcKeyStatus} from "./mocks/MockPqcKeyStatus.sol";
import {MockPqcSigner} from "./mocks/MockPqcSigner.sol";

/// @title PqTestBase
/// @notice Installs the precompile mocks at the real precompile addresses and
///         gives tests a post-quantum "key" per account.
abstract contract PqTestBase is Test {
    MockPqcVerify internal pqcVerifyMock = MockPqcVerify(PqAuth.PQC_VERIFY);
    MockPqcKeyStatus internal pqcKeyStatusMock = MockPqcKeyStatus(PqAuth.PQC_KEY_STATUS);

    function installPqcMocks() internal {
        vm.etch(PqAuth.PQC_VERIFY, type(MockPqcVerify).runtimeCode);
        vm.etch(PqAuth.PQC_KEY_STATUS, type(MockPqcKeyStatus).runtimeCode);
    }

    /// @notice Register `account` with the ML-DSA-87 stand-in key made from `secret`.
    function registerPqKey(address account, bytes32 secret) internal {
        bytes memory pk = MockPqcSigner.publicKey(secret);
        pqcKeyStatusMock.set(account, true, PqAuth.ALGORITHM_ML_DSA_87, pk, true);
        pqcVerifyMock.setSecret(keccak256(pk), secret);
    }

    function pqSign(bytes32 secret, bytes memory message) internal pure returns (bytes memory) {
        return MockPqcSigner.sign(secret, message);
    }

    /// @notice The message PqAuth expects, built independently of the library.
    function pqMessage(
        address verifier,
        address signer,
        bytes32 action,
        uint256 nonce,
        uint256 deadline,
        bytes32 argsHash
    ) internal view returns (bytes memory) {
        return abi.encode(
            keccak256("qore-pq-kit.PqAuth.v1"), block.chainid, verifier, signer, action, nonce, deadline, argsHash
        );
    }
}
