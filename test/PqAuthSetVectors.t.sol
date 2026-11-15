// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PqAuth} from "../src/PqAuth.sol";
import {PqAuthSet} from "../src/PqAuthSet.sol";

/// @notice PqAuthSet's message format against vectors/pqauthset.json, which
///         scripts/pqauthset.ts writes (`npm run vectors`).
contract PqAuthSetVectorsTest is Test {
    using stdJson for string;

    function test_messagesMatchTypeScript() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/vectors/pqauthset.json"));
        vm.chainId(json.readUint(".chainId"));
        bytes32 action = keccak256(bytes(json.readString(".actionName")));
        assertEq(action, json.readBytes32(".action"));
        assertEq(PqAuthSet.quorumAction(action), json.readBytes32(".quorumAction"));
        assertEq(PqAuthSet.anyAction(action), json.readBytes32(".anyAction"));
        address verifier = json.readAddress(".verifier");
        address member = json.readAddress(".member");
        uint256 nonce = json.readUint(".nonce");
        uint256 deadline = json.readUint(".deadline");
        bytes32 argsHash = json.readBytes32(".argsHash");
        assertEq(
            PqAuth.message(verifier, member, PqAuthSet.quorumAction(action), nonce, deadline, argsHash),
            json.readBytes(".quorumMessage")
        );
        assertEq(
            PqAuth.message(verifier, member, PqAuthSet.anyAction(action), nonce, deadline, argsHash),
            json.readBytes(".anyMessage")
        );
    }
}
