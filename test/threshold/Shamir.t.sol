// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Shamir} from "../../src/threshold/Shamir.sol";
import {ThresholdHarness, TestDealer} from "./ThresholdHarness.sol";

contract ShamirTest is Test {
    uint256 internal constant P = Shamir.P;
    ThresholdHarness internal h;

    function setUp() public {
        h = new ThresholdHarness();
    }

    function _deal(uint256 key, uint256 t, uint256 n, uint256 seed)
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

    function _pick(uint256[] memory a, uint256[] memory idx) internal pure returns (uint256[] memory out) {
        out = new uint256[](idx.length);
        for (uint256 i = 0; i < idx.length; ++i) {
            out[i] = a[idx[i]];
        }
    }

    function _arr(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        r[0] = a;
        r[1] = b;
    }

    // ------------------------------------------------------------------
    // Correctness
    // ------------------------------------------------------------------

    function test_modulusIs2To255Minus19() public pure {
        assertEq(P, 2 ** 255 - 19);
    }

    function test_oneShareIsTheKey() public view {
        uint256[] memory xs = new uint256[](1);
        uint256[] memory ys = new uint256[](1);
        xs[0] = 1;
        ys[0] = 42;
        assertEq(h.combineAtZero(xs, ys), 42);
    }

    function test_twoOfThreeEveryPair() public view {
        (uint256[] memory xs, uint256[] memory ys) = _deal(123456789, 2, 3, 7);
        assertEq(h.combineAtZero(_arr(xs[0], xs[1]), _arr(ys[0], ys[1])), 123456789);
        assertEq(h.combineAtZero(_arr(xs[0], xs[2]), _arr(ys[0], ys[2])), 123456789);
        assertEq(h.combineAtZero(_arr(xs[1], xs[2]), _arr(ys[1], ys[2])), 123456789);
        // order does not matter
        assertEq(h.combineAtZero(_arr(xs[2], xs[0]), _arr(ys[2], ys[0])), 123456789);
    }

    function test_moreSharesThanThresholdStillRecover() public view {
        (uint256[] memory xs, uint256[] memory ys) = _deal(P - 1, 2, 5, 9);
        assertEq(h.combineAtZero(xs, ys), P - 1);
    }

    function test_fewerSharesThanThresholdDoNotRecover() public view {
        (uint256[] memory xs, uint256[] memory ys) = _deal(777, 3, 3, 11);
        assertTrue(h.combineAtZero(_arr(xs[0], xs[1]), _arr(ys[0], ys[1])) != 777);
    }

    /// Any t of n shares, in any order, give back the key.
    function testFuzz_anyThresholdSubsetRecovers(uint256 key, uint8 tRaw, uint8 nRaw, uint256 seed, uint256 pickSeed)
        public
        view
    {
        key = bound(key, 0, P - 1);
        uint256 n = bound(nRaw, 1, 7);
        uint256 t = bound(tRaw, 1, n);
        (uint256[] memory xs, uint256[] memory ys) = _deal(key, t, n, seed);
        // a random t-subset, by a Fisher-Yates shuffle of 0..n-1
        uint256[] memory order = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            order[i] = i;
        }
        for (uint256 i = n - 1; i > 0; --i) {
            uint256 j = uint256(keccak256(abi.encode(pickSeed, i))) % (i + 1);
            (order[i], order[j]) = (order[j], order[i]);
        }
        uint256[] memory idx = new uint256[](t);
        for (uint256 i = 0; i < t; ++i) {
            idx[i] = order[i];
        }
        assertEq(h.combineAtZero(_pick(xs, idx), _pick(ys, idx)), key);
    }

    function testFuzz_inverse(uint256 a) public view {
        a = bound(a, 1, P - 1);
        assertEq(mulmod(a, h.inverse(a), P), 1);
    }

    // ------------------------------------------------------------------
    // Refusals
    // ------------------------------------------------------------------

    function test_revertsOnLengthMismatch() public {
        uint256[] memory ys = new uint256[](1);
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirLengthMismatch.selector, 2, 1));
        h.combineAtZero(_arr(1, 2), ys);
    }

    function test_revertsOnNoShares() public {
        vm.expectRevert(Shamir.ShamirNoShares.selector);
        h.combineAtZero(new uint256[](0), new uint256[](0));
    }

    function test_revertsOnZeroIndex() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirBadIndex.selector, 0));
        h.combineAtZero(_arr(0, 1), _arr(5, 6));
    }

    function test_revertsOnIndexAtOrAboveP() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirBadIndex.selector, P));
        h.combineAtZero(_arr(1, P), _arr(5, 6));
    }

    /// x and x + P are the same point; refusing x >= P stops a share counting twice.
    function test_revertsOnIndexAliasingAnotherModP() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirBadIndex.selector, P + 1));
        h.combineAtZero(_arr(1, P + 1), _arr(5, 5));
    }

    function test_revertsOnValueAtOrAboveP() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirBadValue.selector, P));
        h.combineAtZero(_arr(1, 2), _arr(P, 6));
    }

    function test_revertsOnDuplicateIndex() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirDuplicateIndex.selector, 2));
        h.combineAtZero(_arr(2, 2), _arr(5, 5));
    }

    function test_inverseRevertsOnZero() public {
        vm.expectRevert(abi.encodeWithSelector(Shamir.ShamirBadValue.selector, 0));
        h.inverse(0);
    }

    /// An inactive precompile answers with success and empty data: refused.
    function test_failsClosedWhenModexpAnswersEmpty() public {
        vm.mockCall(address(0x05), bytes(""), bytes(""));
        vm.expectRevert(Shamir.ShamirModexpUnavailable.selector);
        h.inverse(3);
    }

    /// A precompile that answers a wrong value cannot produce a wrong key.
    function test_failsClosedWhenModexpAnswersWrongValue() public {
        vm.mockCall(address(0x05), bytes(""), abi.encode(uint256(5)));
        vm.expectRevert(Shamir.ShamirModexpUnavailable.selector);
        h.inverse(3);
    }

    function test_failsClosedWhenModexpReverts() public {
        vm.mockCallRevert(address(0x05), bytes(""), bytes("down"));
        vm.expectRevert(Shamir.ShamirModexpUnavailable.selector);
        h.inverse(3);
    }

    // ------------------------------------------------------------------
    // Gas, as a contract pays it (external call through the harness)
    // ------------------------------------------------------------------

    function test_gas_combine() public {
        for (uint256 t = 2; t <= 7; ++t) {
            (uint256[] memory xs, uint256[] memory ys) = _deal(99, t, t, t);
            uint256 g = gasleft();
            h.combineAtZero(xs, ys);
            emit log_named_uint(string.concat("combineAtZero gas, t=", vm.toString(t)), g - gasleft());
        }
    }
}
