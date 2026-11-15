// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Shamir} from "../../src/threshold/Shamir.sol";
import {SealedSlot} from "../../src/threshold/SealedSlot.sol";
import {ThresholdHarness, TestDealer} from "./ThresholdHarness.sol";

contract SealedSlotTest is Test {
    ThresholdHarness internal h;
    address internal constant APP = address(0xA11);
    address internal constant SENDER = address(0xB0B);

    function setUp() public {
        h = new ThresholdHarness();
        vm.chainId(9800);
    }

    function _shares(uint256 key, uint256 t, uint256 n, uint256 seed)
        internal
        pure
        returns (uint256[] memory xs, uint256[] memory ys)
    {
        uint256[] memory coeffs = TestDealer.polynomial(key, t, seed);
        xs = new uint256[](n);
        ys = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            xs[i] = i + 1;
            ys[i] = TestDealer.evaluate(coeffs, i + 1);
        }
    }

    function test_domainsAreDistinct() public pure {
        assertTrue(SealedSlot.KEY_DOMAIN != SealedSlot.SHARE_DOMAIN);
        assertTrue(SealedSlot.KEY_DOMAIN != SealedSlot.DEM_DOMAIN);
        assertTrue(SealedSlot.SHARE_DOMAIN != SealedSlot.DEM_DOMAIN);
    }

    function testFuzz_openInvertsSeal(uint256 key, bytes32 pt, uint256 seq) public view {
        bytes32 ct = h.open(APP, SENDER, seq, key, pt); // XOR: sealing is the same call
        assertEq(h.open(APP, SENDER, seq, key, ct), pt);
    }

    /// The same key under another app, sender, seq or chain gives an unrelated stream.
    function testFuzz_everyFieldIsBound(uint256 key, uint256 seq) public {
        seq = bound(seq, 0, type(uint64).max);
        bytes32 base = h.keystream(APP, SENDER, seq, key);
        bytes32 kh = h.keyHash(APP, SENDER, seq, key);
        bytes32 sh = h.shareHash(APP, SENDER, seq, 1, key);
        assertTrue(h.keystream(address(0xA12), SENDER, seq, key) != base, "app");
        assertTrue(h.keystream(APP, address(0xB0C), seq, key) != base, "sender");
        assertTrue(h.keystream(APP, SENDER, seq + 1, key) != base, "seq");
        assertTrue(h.keyHash(APP, SENDER, seq + 1, key) != kh, "keyHash seq");
        assertTrue(h.shareHash(APP, SENDER, seq, 2, key) != sh, "share index");
        assertTrue(h.shareHash(APP, SENDER, seq + 1, 1, key) != sh, "share seq");
        // the three hashes of one slot never coincide
        assertTrue(kh != base && kh != sh && sh != base, "domains");
        vm.chainId(9801);
        assertTrue(h.keystream(APP, SENDER, seq, key) != base, "chain");
        assertTrue(h.keyHash(APP, SENDER, seq, key) != kh, "keyHash chain");
        assertTrue(h.shareHash(APP, SENDER, seq, 1, key) != sh, "shareHash chain");
    }

    function test_checkShare() public view {
        bytes32 committed = h.shareHash(APP, SENDER, 0, 2, 12345);
        assertTrue(h.checkShare(APP, SENDER, 0, 2, 12345, committed));
        assertFalse(h.checkShare(APP, SENDER, 0, 2, 12346, committed), "other value");
        assertFalse(h.checkShare(APP, SENDER, 0, 3, 12345, committed), "other index");
        assertFalse(h.checkShare(APP, SENDER, 1, 2, 12345, committed), "other seq");
        assertFalse(h.checkShare(address(0xA12), SENDER, 0, 2, 12345, committed), "other app");
    }

    function testFuzz_recoverThenOpen(uint256 key, bytes32 pt, uint256 seed) public view {
        key = bound(key, 0, Shamir.P - 1);
        bytes32 ct = h.open(APP, SENDER, 0, key, pt);
        bytes32 kh = h.keyHash(APP, SENDER, 0, key);
        (uint256[] memory xs, uint256[] memory ys) = _shares(key, 2, 3, seed);
        uint256[] memory x2 = new uint256[](2);
        uint256[] memory y2 = new uint256[](2);
        (x2[0], x2[1], y2[0], y2[1]) = (xs[2], xs[0], ys[2], ys[0]);
        (bool ok, uint256 got) = h.recover(APP, SENDER, 0, x2, y2, kh);
        assertTrue(ok);
        assertEq(h.open(APP, SENDER, 0, got, ct), pt);
    }

    /// A dishonest sender dealing shares of a different key than it committed:
    /// recover reports false (the slot is excluded) instead of reverting.
    function test_inconsistentDealingIsReportedNotReverted() public view {
        bytes32 kh = h.keyHash(APP, SENDER, 0, 1111);
        (uint256[] memory xs, uint256[] memory ys) = _shares(2222, 2, 3, 5);
        (bool ok, uint256 got) = h.recover(APP, SENDER, 0, xs, ys, kh);
        assertFalse(ok);
        assertEq(got, 0);
    }

    /// One tampered share among t changes the key, which then fails keyHash.
    function testFuzz_tamperedShareFailsKeyHash(uint256 key, uint256 seed, uint256 delta) public view {
        key = bound(key, 0, Shamir.P - 1);
        delta = bound(delta, 1, Shamir.P - 1);
        bytes32 kh = h.keyHash(APP, SENDER, 0, key);
        (uint256[] memory xs, uint256[] memory ys) = _shares(key, 3, 3, seed);
        ys[1] = addmod(ys[1], delta, Shamir.P);
        (bool ok,) = h.recover(APP, SENDER, 0, xs, ys, kh);
        assertFalse(ok);
    }
}
