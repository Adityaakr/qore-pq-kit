// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqAuth} from "../src/PqAuth.sol";
import {PqAuthSet} from "../src/PqAuthSet.sol";
import {PqTestBase} from "./PqTestBase.sol";
import {MockPqcVerify} from "./mocks/MockPqcVerify.sol";

/// A treasury-shaped contract guarded by a PqAuthSet: a gated counter, a
/// membership change and a cancel any single member may sign. It also has a
/// single-signer PqAuth action, to prove the two kinds of signature cannot be
/// swapped for each other.
contract PqAuthSetHarness {
    using PqAuthSet for PqAuthSet.Set;
    using PqAuth for PqAuth.Signer;

    bytes32 public constant ACTION_BUMP = keccak256("Harness.bump");
    bytes32 public constant ACTION_SET = keccak256("Harness.setMembers");
    bytes32 public constant ACTION_CANCEL = keccak256("Harness.cancel");
    uint256 public constant MAX_TTL = 1 days;

    PqAuthSet.Set internal set;
    PqAuth.Signer internal solo;
    uint256 public counter;
    uint256 public cancels;
    uint256 public soloBumps;

    constructor(address[] memory initialMembers, uint256 initialThreshold, address soloSigner) {
        set.init(initialMembers, initialThreshold);
        solo.init(soloSigner);
    }

    function bump(uint256 by, uint256 deadline, address[] calldata signers, bytes[] calldata sigs) external {
        set.authorizeQuorum(ACTION_BUMP, keccak256(abi.encode(by)), deadline, MAX_TTL, signers, sigs);
        counter += by;
    }

    function setMembers(
        address[] calldata nextMembers,
        uint256 nextThreshold,
        uint256 deadline,
        address[] calldata signers,
        bytes[] calldata sigs
    ) external {
        set.authorizeQuorum(
            ACTION_SET, keccak256(abi.encode(nextMembers, nextThreshold)), deadline, MAX_TTL, signers, sigs
        );
        set.setMembers(nextMembers, nextThreshold);
    }

    function cancel(uint256 id, uint256 deadline, address signer, bytes calldata sig) external {
        set.authorizeAny(ACTION_CANCEL, keccak256(abi.encode(id)), deadline, MAX_TTL, signer, sig);
        cancels += 1;
    }

    function soloBump(uint256 by, uint256 deadline, bytes calldata sig) external {
        solo.authorize(ACTION_BUMP, keccak256(abi.encode(by)), deadline, MAX_TTL, sig);
        soloBumps += by;
    }

    function nonce() external view returns (uint256) {
        return set.nonce;
    }

    function soloNonce() external view returns (uint256) {
        return solo.nonce;
    }

    function threshold() external view returns (uint256) {
        return set.threshold;
    }

    function members() external view returns (address[] memory) {
        return set.members;
    }

    function isMember(address a) external view returns (bool) {
        return set.isMember(a);
    }
}

/// Deploys a set from outside, so constructor reverts can be expected.
contract SetFactory {
    function make(address[] memory members, uint256 threshold, address soloSigner) external returns (address) {
        return address(new PqAuthSetHarness(members, threshold, soloSigner));
    }
}

contract PqAuthSetTest is PqTestBase {
    uint256 internal constant N = 7;
    address[N] internal acct;
    bytes32[N] internal secret;

    PqAuthSetHarness internal h; // 2-of-3 over the three lowest addresses
    SetFactory internal factory;

    function setUp() public {
        vm.warp(1_800_000_000);
        installPqcMocks();
        // Seven accounts with keys, sorted ascending so tests can index them in order.
        address[N] memory a;
        bytes32[N] memory sec;
        for (uint256 i = 0; i < N; ++i) {
            sec[i] = keccak256(abi.encode("member secret", i));
            a[i] = vm.addr(uint256(keccak256(abi.encode("member", i))));
        }
        for (uint256 i = 0; i < N; ++i) {
            for (uint256 j = i + 1; j < N; ++j) {
                if (a[j] < a[i]) {
                    (a[i], a[j]) = (a[j], a[i]);
                    (sec[i], sec[j]) = (sec[j], sec[i]);
                }
            }
        }
        for (uint256 i = 0; i < N; ++i) {
            acct[i] = a[i];
            secret[i] = sec[i];
            registerPqKey(a[i], sec[i]);
        }
        h = new PqAuthSetHarness(_list3(0, 1, 2), 2, acct[0]);
        factory = new SetFactory();
    }

    // ------------------------------------------------------------------ helpers

    function _list3(uint256 i, uint256 j, uint256 k) internal view returns (address[] memory r) {
        r = new address[](3);
        (r[0], r[1], r[2]) = (acct[i], acct[j], acct[k]);
    }

    function _list2(uint256 i, uint256 j) internal view returns (address[] memory r) {
        r = new address[](2);
        (r[0], r[1]) = (acct[i], acct[j]);
    }

    function _list1(uint256 i) internal view returns (address[] memory r) {
        r = new address[](1);
        r[0] = acct[i];
    }

    function _quorumMsg(address verifier, address member, bytes32 action, uint256 nonce, uint256 deadline, bytes32 args)
        internal
        view
        returns (bytes memory)
    {
        // Built independently of the library: the PqAuth message over the domain-folded action.
        bytes32 qAction = keccak256(abi.encode(keccak256("qore-pq-kit.PqAuthSet.quorum.v1"), action));
        return pqMessage(verifier, member, qAction, nonce, deadline, args);
    }

    function _bumpSigs(uint256[] memory who, uint256 by, uint256 nonce, uint256 deadline)
        internal
        view
        returns (address[] memory signers, bytes[] memory sigs)
    {
        signers = new address[](who.length);
        sigs = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; ++i) {
            signers[i] = acct[who[i]];
            sigs[i] = pqSign(
                secret[who[i]],
                _quorumMsg(address(h), acct[who[i]], h.ACTION_BUMP(), nonce, deadline, keccak256(abi.encode(by)))
            );
        }
    }

    function _idx(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _idx(uint256 a, uint256 b) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (a, b);
    }

    function _idx(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        (r[0], r[1], r[2]) = (a, b, c);
    }

    // ------------------------------------------------------------------ happy path

    function test_initialState() public view {
        assertEq(h.threshold(), 2);
        assertEq(h.members().length, 3);
        assertTrue(h.isMember(acct[1]));
        assertFalse(h.isMember(acct[3]));
        assertEq(h.nonce(), 0);
    }

    function test_twoOfThreeAuthorisesAndConsumesNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 2), 5, 0, deadline);
        vm.expectEmit(address(h));
        emit PqAuthSet.PqQuorumAuthorized(h.ACTION_BUMP(), 0, keccak256(abi.encode(uint256(5))), s);
        vm.prank(makeAddr("anyRelayer"));
        h.bump(5, deadline, s, sigs);
        assertEq(h.counter(), 5);
        assertEq(h.nonce(), 1);
    }

    function test_everyPairWorks() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256[3][3] memory pairs = [[uint256(0), 1, 0], [uint256(0), 2, 0], [uint256(1), 2, 0]];
        for (uint256 p = 0; p < 3; ++p) {
            (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(pairs[p][0], pairs[p][1]), 1, p, deadline);
            h.bump(1, deadline, s, sigs);
        }
        assertEq(h.counter(), 3);
    }

    function test_allThreeAlsoWork() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1, 2), 7, 0, deadline);
        h.bump(7, deadline, s, sigs);
        assertEq(h.counter(), 7);
    }

    // ------------------------------------------------------------------ refusals

    function test_oneSignatureIsNotEnough() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(1), 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetTooFewSignatures.selector, 1, 2));
        h.bump(5, deadline, s, sigs);
    }

    function test_noSignaturesAreNotEnough() public {
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetTooFewSignatures.selector, 0, 2));
        h.bump(5, block.timestamp + 1 hours, new address[](0), new bytes[](0));
    }

    function test_theSameMemberTwiceIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(1, 1), 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotAscending.selector, 1));
        h.bump(5, deadline, s, sigs);
    }

    function test_descendingOrderIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(2, 0), 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotAscending.selector, 1));
        h.bump(5, deadline, s, sigs);
    }

    function test_nonMemberIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 3), 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotMember.selector, acct[3]));
        h.bump(5, deadline, s, sigs);
    }

    /// A member's genuine signature presented under another member's name.
    function test_signatureUnderAnotherMembersNameIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        s[1] = acct[2]; // acct[1]'s signature, claimed for acct[2]
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, s, sigs);
    }

    function test_replayIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        h.bump(5, deadline, s, sigs);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, s, sigs);
    }

    function test_otherArgumentsAreRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(6, deadline, s, sigs);
    }

    function test_otherDeadlineIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline + 1, s, sigs);
    }

    function test_otherContractIsRefused() public {
        PqAuthSetHarness h2 = new PqAuthSetHarness(_list3(0, 1, 2), 2, acct[0]);
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline); // made for h
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h2.bump(5, deadline, s, sigs);
    }

    function test_otherChainIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.chainId(block.chainid + 1);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, s, sigs);
    }

    function test_expiredIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqExpired.selector, deadline, deadline + 1));
        h.bump(5, deadline, s, sigs);
    }

    function test_deadlineTooFarIsRefused() public {
        uint256 deadline = block.timestamp + 1 days + 1;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqDeadlineTooFar.selector, deadline, block.timestamp + 1 days));
        h.bump(5, deadline, s, sigs);
    }

    function test_badSignatureLengthIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        sigs[1] = new bytes(100);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqBadSignatureLength.selector, 100));
        h.bump(5, deadline, s, sigs);
    }

    function test_lengthMismatchIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        bytes[] memory one = new bytes[](1);
        one[0] = sigs[0];
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetLengthMismatch.selector, 2, 1));
        h.bump(5, deadline, s, one);
    }

    /// A plain PqAuth (single signer) signature over the same action, nonce and
    /// arguments is not a quorum share, and a quorum share is not a PqAuth signature.
    function test_singleSignerAndQuorumSignaturesDoNotMix() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 args = keccak256(abi.encode(uint256(5)));
        // acct[0] is both the solo signer and a member; both nonces are 0.
        bytes memory soloSig = pqSign(secret[0], pqMessage(address(h), acct[0], h.ACTION_BUMP(), 0, deadline, args));
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        bytes[] memory mixed = new bytes[](2);
        (mixed[0], mixed[1]) = (soloSig, sigs[1]);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, s, mixed);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.soloBump(5, deadline, sigs[0]);
        h.soloBump(5, deadline, soloSig); // and the genuine one works
        assertEq(h.soloBumps(), 5);
    }

    // ------------------------------------------------------------------ authorizeAny

    function _cancelSig(uint256 who, uint256 id, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        bytes32 anyAction = keccak256(abi.encode(keccak256("qore-pq-kit.PqAuthSet.any.v1"), h.ACTION_CANCEL()));
        return
            pqSign(secret[who], pqMessage(address(h), acct[who], anyAction, nonce, deadline, keccak256(abi.encode(id))));
    }

    function test_anyOneMemberCanCancel() public {
        uint256 deadline = block.timestamp + 1 hours;
        h.cancel(9, deadline, acct[2], _cancelSig(2, 9, 0, deadline));
        assertEq(h.cancels(), 1);
        assertEq(h.nonce(), 1);
    }

    function test_cancelByNonMemberIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _cancelSig(4, 9, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotMember.selector, acct[4]));
        h.cancel(9, deadline, acct[4], sig);
    }

    function test_quorumShareIsNotACancel() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory share = pqSign(
            secret[0],
            _quorumMsg(address(h), acct[0], h.ACTION_CANCEL(), 0, deadline, keccak256(abi.encode(uint256(9))))
        );
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.cancel(9, deadline, acct[0], share);
    }

    function test_cancelSignatureIsNotAQuorumShare() public {
        uint256 deadline = block.timestamp + 1 hours;
        // Two "any" signatures for ACTION_BUMP can never make a quorum for ACTION_BUMP.
        bytes32 anyBump = keccak256(abi.encode(keccak256("qore-pq-kit.PqAuthSet.any.v1"), h.ACTION_BUMP()));
        bytes32 args = keccak256(abi.encode(uint256(5)));
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = pqSign(secret[0], pqMessage(address(h), acct[0], anyBump, 0, deadline, args));
        sigs[1] = pqSign(secret[1], pqMessage(address(h), acct[1], anyBump, 0, deadline, args));
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, _list2(0, 1), sigs);
    }

    // ------------------------------------------------------------------ membership changes

    function _setSigs(address[] memory members, uint256 t, uint256[] memory who, uint256 nonce, uint256 deadline)
        internal
        view
        returns (address[] memory signers, bytes[] memory sigs)
    {
        signers = new address[](who.length);
        sigs = new bytes[](who.length);
        bytes32 args = keccak256(abi.encode(members, t));
        for (uint256 i = 0; i < who.length; ++i) {
            signers[i] = acct[who[i]];
            sigs[i] =
                pqSign(secret[who[i]], _quorumMsg(address(h), acct[who[i]], h.ACTION_SET(), nonce, deadline, args));
        }
    }

    function test_rotationReplacesMembersAndKeepsCounting() public {
        uint256 deadline = block.timestamp + 1 hours;
        address[] memory next = _list3(1, 2, 3); // acct[0] leaves, acct[3] joins
        (address[] memory s, bytes[] memory sigs) = _setSigs(next, 2, _idx(0, 1), 0, deadline);
        h.setMembers(next, 2, deadline, s, sigs);
        assertFalse(h.isMember(acct[0]));
        assertTrue(h.isMember(acct[3]));
        assertEq(h.nonce(), 1);

        // the old member is out
        (s, sigs) = _bumpSigs(_idx(0, 1), 5, 1, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotMember.selector, acct[0]));
        h.bump(5, deadline, s, sigs);
        // the new member is in
        (s, sigs) = _bumpSigs(_idx(1, 3), 5, 1, deadline);
        h.bump(5, deadline, s, sigs);
        assertEq(h.counter(), 5);
    }

    function test_rotationCanRaiseTheThreshold() public {
        uint256 deadline = block.timestamp + 1 hours;
        address[] memory same = _list3(0, 1, 2);
        (address[] memory s, bytes[] memory sigs) = _setSigs(same, 3, _idx(0, 2), 0, deadline);
        h.setMembers(same, 3, deadline, s, sigs);
        assertEq(h.threshold(), 3);
        (s, sigs) = _bumpSigs(_idx(0, 1), 5, 1, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetTooFewSignatures.selector, 2, 3));
        h.bump(5, deadline, s, sigs);
    }

    function test_rotationToABadSetReverts() public {
        uint256 deadline = block.timestamp + 1 hours;
        address[] memory unsorted = new address[](2);
        (unsorted[0], unsorted[1]) = (acct[2], acct[1]);
        (address[] memory s, bytes[] memory sigs) = _setSigs(unsorted, 1, _idx(0, 1), 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotAscending.selector, 1));
        h.setMembers(unsorted, 1, deadline, s, sigs);
        assertEq(h.nonce(), 0, "the nonce is not consumed when the whole call reverts");
    }

    /// A member rotates its ML-DSA key on chain: the set follows it at once.
    function test_onChainKeyRotationIsFollowed() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory oldSigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        bytes32 fresh = keccak256("rotated secret");
        registerPqKey(acct[1], fresh);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, s, oldSigs);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = oldSigs[0];
        sigs[1] = pqSign(
            fresh, _quorumMsg(address(h), acct[1], h.ACTION_BUMP(), 0, deadline, keccak256(abi.encode(uint256(5))))
        );
        h.bump(5, deadline, s, sigs);
        assertEq(h.counter(), 5);
    }

    function test_memberWhoseKeyLostPossessionBlocksOnlyItself() public {
        uint256 deadline = block.timestamp + 1 hours;
        pqcKeyStatusMock.set(acct[1], true, PqAuth.ALGORITHM_ML_DSA_87, new bytes(2592), false);
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(
                PqAuth.PqKeyUnusable.selector, acct[1], true, PqAuth.ALGORITHM_ML_DSA_87, false, 2592
            )
        );
        h.bump(5, deadline, s, sigs);
        (s, sigs) = _bumpSigs(_idx(0, 2), 5, 0, deadline);
        h.bump(5, deadline, s, sigs);
        assertEq(h.counter(), 5);
    }

    function test_failsClosedWhenVerifyAnswersEmpty() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        pqcVerifyMock.setMode(MockPqcVerify.Mode.EmptyReturn);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_VERIFY));
        h.bump(5, deadline, s, sigs);
    }

    function test_failsClosedWhenKeyStatusAnswersEmpty() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        pqcKeyStatusMock.setEmptyReturn(true);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_KEY_STATUS));
        h.bump(5, deadline, s, sigs);
    }

    // ------------------------------------------------------------------ init rules

    function test_initRefusesBadSets() public {
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetBadThreshold.selector, 0, 3));
        factory.make(_list3(0, 1, 2), 0, acct[0]);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetBadThreshold.selector, 4, 3));
        factory.make(_list3(0, 1, 2), 4, acct[0]);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetBadThreshold.selector, 1, 0));
        factory.make(new address[](0), 1, acct[0]);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotAscending.selector, 2));
        factory.make(_list3(0, 2, 1), 2, acct[0]);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetNotAscending.selector, 1));
        factory.make(_list3(1, 1, 2), 2, acct[0]);
        address[] memory withZero = _list3(0, 1, 2);
        withZero[0] = address(0);
        vm.expectRevert(PqAuth.PqZeroSigner.selector);
        factory.make(withZero, 2, acct[0]);
        address[] memory big = new address[](17);
        vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetTooLarge.selector, 17));
        factory.make(big, 2, acct[0]);
    }

    function test_initRefusesAMemberWithoutAKey() public {
        address nokey = address(uint160(acct[2]) + 1);
        address[] memory m = _list3(0, 1, 2);
        m[2] = nokey > acct[2] ? nokey : m[2];
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, nokey, false, 0, false, 0));
        factory.make(m, 2, acct[0]);
    }

    // ------------------------------------------------------------------ fuzz

    /// Any t-or-more ascending subset of an n-member set authorises; t - 1 never does.
    function testFuzz_anyQuorumAuthorises(uint8 nRaw, uint8 tRaw, uint256 pickSeed) public {
        uint256 n = bound(nRaw, 1, N);
        uint256 t = bound(tRaw, 1, n);
        address[] memory members = new address[](n);
        for (uint256 i = 0; i < n; ++i) {
            members[i] = acct[i];
        }
        h = new PqAuthSetHarness(members, t, acct[0]);
        // choose k in [t, n] members, kept ascending
        uint256 k = t + (pickSeed % (n - t + 1));
        uint256[] memory chosen = new uint256[](k);
        uint256 c = 0;
        for (uint256 i = 0; i < n && c < k; ++i) {
            // take member i if we still need as many as remain
            bool take = (n - i) <= (k - c) || uint256(keccak256(abi.encode(pickSeed, i))) % 2 == 0;
            if (take) chosen[c++] = i;
        }
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(chosen, 3, 0, deadline);
        h.bump(3, deadline, s, sigs);
        assertEq(h.counter(), 3);

        if (t > 1) {
            uint256[] memory few = new uint256[](t - 1);
            for (uint256 i = 0; i < t - 1; ++i) {
                few[i] = chosen[i];
            }
            (s, sigs) = _bumpSigs(few, 3, 1, deadline);
            vm.expectRevert(abi.encodeWithSelector(PqAuthSet.PqSetTooFewSignatures.selector, t - 1, t));
            h.bump(3, deadline, s, sigs);
        }
    }

    // ------------------------------------------------------------------ gas

    function test_gas_twoOfThree() public {
        uint256 deadline = block.timestamp + 1 hours;
        (address[] memory s, bytes[] memory sigs) = _bumpSigs(_idx(0, 1), 5, 0, deadline);
        uint256 g = gasleft();
        h.bump(5, deadline, s, sigs);
        emit log_named_uint("2-of-3 bump, execution gas with mock precompiles", g - gasleft());
    }
}
