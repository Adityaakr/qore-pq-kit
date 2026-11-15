// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Shamir} from "../../src/threshold/Shamir.sol";
import {SealedSlot} from "../../src/threshold/SealedSlot.sol";
import {ThresholdHarness} from "./ThresholdHarness.sol";

/// @notice Checks Shamir.sol and SealedSlot.sol against vectors/threshold.json,
///         which scripts/threshold.ts writes (`npm run vectors`). If the two
///         sides ever disagree, a bidder's browser would commit hashes the
///         contract can never match, and every sealed slot would be unopenable.
contract ThresholdVectorsTest is Test {
    using stdJson for string;

    string internal json;
    ThresholdHarness internal h;

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/vectors/threshold.json"));
        h = new ThresholdHarness();
    }

    function _c(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "].", field);
    }

    function test_domainsAndModulus() public view {
        assertEq(json.readUint(".fieldP"), Shamir.P, "P");
        assertEq(json.readBytes32(".domains.key"), SealedSlot.KEY_DOMAIN, "key domain");
        assertEq(json.readBytes32(".domains.share"), SealedSlot.SHARE_DOMAIN, "share domain");
        assertEq(json.readBytes32(".domains.dem"), SealedSlot.DEM_DOMAIN, "dem domain");
        assertEq(keccak256(bytes(json.readString(".domains.keyLabel"))), SealedSlot.KEY_DOMAIN);
        assertEq(keccak256(bytes(json.readString(".domains.shareLabel"))), SealedSlot.SHARE_DOMAIN);
        assertEq(keccak256(bytes(json.readString(".domains.demLabel"))), SealedSlot.DEM_DOMAIN);
    }

    function test_everyCase() public {
        uint256 count = json.readUint(".count");
        assertGt(count, 0);
        for (uint256 i = 0; i < count; ++i) {
            _checkCase(i);
        }
    }

    struct Case {
        string name;
        address app;
        address sender;
        uint256 seq;
        uint256 key;
        bytes32 keyHash;
        uint256[] shares;
    }

    function _load(uint256 i) internal returns (Case memory c) {
        vm.chainId(json.readUint(_c(i, "chainId")));
        c.name = json.readString(_c(i, "name"));
        c.app = json.readAddress(_c(i, "app"));
        c.sender = json.readAddress(_c(i, "sender"));
        c.seq = json.readUint(_c(i, "seq"));
        c.key = json.readUint(_c(i, "key"));
        c.keyHash = json.readBytes32(_c(i, "keyHash"));
        c.shares = json.readUintArray(_c(i, "shares"));
    }

    function _checkCase(uint256 i) internal {
        Case memory c = _load(i);
        bytes32 ct = json.readBytes32(_c(i, "ct"));
        assertEq(h.keyHash(c.app, c.sender, c.seq, c.key), c.keyHash, string.concat(c.name, ": keyHash"));
        assertEq(
            h.keystream(c.app, c.sender, c.seq, c.key),
            json.readBytes32(_c(i, "keystream")),
            string.concat(c.name, ": keystream")
        );
        assertEq(
            h.open(c.app, c.sender, c.seq, c.key, ct),
            json.readBytes32(_c(i, "plaintext")),
            string.concat(c.name, ": open")
        );

        bytes32[] memory shareHashes = json.readBytes32Array(_c(i, "shareHashes"));
        assertEq(c.shares.length, json.readUint(_c(i, "n")));
        for (uint256 j = 0; j < c.shares.length; ++j) {
            assertEq(
                h.shareHash(c.app, c.sender, c.seq, j + 1, c.shares[j]),
                shareHashes[j],
                string.concat(c.name, ": shareHash")
            );
            assertTrue(h.checkShare(c.app, c.sender, c.seq, j + 1, c.shares[j], shareHashes[j]));
        }

        uint256 sets = abi.decode(vm.parseJson(json, _c(i, "openingSets")), (uint256[][])).length;
        for (uint256 s = 0; s < sets; ++s) {
            uint256[] memory xs = json.readUintArray(string.concat(_c(i, "openingSets"), "[", vm.toString(s), "]"));
            _checkOpening(c, xs, true);
        }

        uint256[] memory shortXs = json.readUintArray(_c(i, "shortSet"));
        if (shortXs.length > 0) {
            uint256 shortValue = _checkOpening(c, shortXs, false);
            assertEq(shortValue, json.readUint(_c(i, "shortValue")), string.concat(c.name, ": short"));
        }
    }

    function _checkOpening(Case memory c, uint256[] memory xs, bool expectKey) internal view returns (uint256 value) {
        uint256[] memory ys = new uint256[](xs.length);
        for (uint256 k = 0; k < xs.length; ++k) {
            ys[k] = c.shares[xs[k] - 1];
        }
        value = h.combineAtZero(xs, ys);
        (bool ok, uint256 got) = h.recover(c.app, c.sender, c.seq, xs, ys, c.keyHash);
        if (expectKey) {
            assertEq(value, c.key, string.concat(c.name, ": combine"));
            assertTrue(ok, string.concat(c.name, ": recover"));
            assertEq(got, c.key);
        } else {
            assertTrue(value != c.key, string.concat(c.name, ": t - 1 shares gave the key"));
            assertFalse(ok, string.concat(c.name, ": t - 1 shares must not recover"));
            assertEq(got, 0);
        }
    }
}
