// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqAuth} from "../src/PqAuth.sol";
import {PqTestBase} from "./PqTestBase.sol";
import {MockPqcVerify} from "./mocks/MockPqcVerify.sol";
import {MockPqcSigner} from "./mocks/MockPqcSigner.sol";

/// A minimal contract guarded by PqAuth: one gated counter and a signer rotation.
contract PqAuthHarness {
    using PqAuth for PqAuth.Signer;

    bytes32 public constant ACTION_BUMP = keccak256("Harness.bump");
    bytes32 public constant ACTION_ROTATE = keccak256("Harness.rotate");
    uint256 public constant MAX_TTL = 1 days;

    PqAuth.Signer internal s;
    uint256 public counter;

    constructor(address firstSigner) {
        s.init(firstSigner);
    }

    function bump(uint256 by, uint256 deadline, bytes calldata sig) external {
        s.authorize(ACTION_BUMP, keccak256(abi.encode(by)), deadline, MAX_TTL, sig);
        counter += by;
    }

    function rotate(address next, uint256 deadline, bytes calldata sig) external {
        s.authorize(ACTION_ROTATE, keccak256(abi.encode(next)), deadline, MAX_TTL, sig);
        s.setSigner(next);
    }

    function signer() external view returns (address) {
        return s.account;
    }

    function nonce() external view returns (uint256) {
        return s.nonce;
    }

    function keyOf(address a) external view returns (bytes memory) {
        return PqAuth.keyOf(a);
    }

    function verify(bytes calldata pk, bytes calldata sig, bytes calldata m) external view returns (bool) {
        return PqAuth.verify(pk, sig, m);
    }
}

contract PqAuthTest is PqTestBase {
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal attacker = makeAddr("attacker");
    bytes32 internal constant ALICE_SECRET = keccak256("alice pq secret");
    bytes32 internal constant BOB_SECRET = keccak256("bob pq secret");

    PqAuthHarness internal h;

    function setUp() public {
        vm.warp(1_800_000_000);
        installPqcMocks();
        registerPqKey(alice, ALICE_SECRET);
        registerPqKey(bob, BOB_SECRET);
        h = new PqAuthHarness(alice);
    }

    function _bumpSig(bytes32 secret, address signer_, uint256 by, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes memory m = pqMessage(address(h), signer_, h.ACTION_BUMP(), nonce, deadline, keccak256(abi.encode(by)));
        return pqSign(secret, m);
    }

    // ------------------------------------------------------------------ happy path

    function test_validSignatureAuthorisesAndConsumesNonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.prank(attacker); // the sender is irrelevant: anyone may relay
        h.bump(5, deadline, sig);
        assertEq(h.counter(), 5);
        assertEq(h.nonce(), 1);
    }

    function test_messageLayoutIs256Bytes() public view {
        bytes memory m = pqMessage(address(h), alice, bytes32(0), 0, 0, bytes32(0));
        assertEq(m.length, 256);
    }

    // ------------------------------------------------------------------ replay and binding

    function test_replayIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        h.bump(5, deadline, sig);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    function test_differentArgumentsAreRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(6, deadline, sig);
    }

    function test_differentDeadlineIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline + 1, sig);
    }

    function test_signatureForAnotherActionIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        // A signature over the rotate action with the same argument word.
        bytes memory m = pqMessage(address(h), alice, h.ACTION_ROTATE(), 0, deadline, keccak256(abi.encode(uint256(5))));
        bytes memory sig = pqSign(ALICE_SECRET, m);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    function test_signatureForAnotherContractIsRefused() public {
        PqAuthHarness other = new PqAuthHarness(alice);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline); // made for `h`
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        other.bump(5, deadline, sig);
    }

    function test_signatureForAnotherChainIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.chainId(9801); // mainnet's EVM chain id
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    function test_anotherKeyIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(BOB_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    // ------------------------------------------------------------------ freshness

    function test_expiredIsRefused() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqExpired.selector, deadline, deadline + 1));
        h.bump(5, deadline, sig);
    }

    function test_deadlineTooFarIsRefused() public {
        uint256 deadline = block.timestamp + 1 days + 1;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(PqAuth.PqDeadlineTooFar.selector, deadline, block.timestamp + 1 days)
        );
        h.bump(5, deadline, sig);
    }

    function test_badSignatureLengthIsRefused() public {
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqBadSignatureLength.selector, 64));
        h.bump(5, block.timestamp + 1, new bytes(64));
    }

    // ------------------------------------------------------------------ the key registry

    function test_constructorRefusesAccountWithoutKey() public {
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, attacker, false, 0, false, 0));
        new PqAuthHarness(attacker);
    }

    function test_constructorRefusesZeroSigner() public {
        vm.expectRevert(PqAuth.PqZeroSigner.selector);
        new PqAuthHarness(address(0));
    }

    function test_keyWithoutProofOfPossessionIsRefused() public {
        bytes memory pk = MockPqcSigner.publicKey(ALICE_SECRET);
        pqcKeyStatusMock.set(alice, true, 1, pk, false);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, alice, true, 1, false, 2592));
        h.keyOf(alice);
    }

    function test_otherAlgorithmIsRefused() public {
        bytes memory pk = MockPqcSigner.publicKey(ALICE_SECRET);
        pqcKeyStatusMock.set(alice, true, 2, pk, true);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, alice, true, 2, true, 2592));
        h.keyOf(alice);
    }

    function test_wrongKeyLengthIsRefused() public {
        pqcKeyStatusMock.set(alice, true, 1, new bytes(32), true);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, alice, true, 1, true, 32));
        h.keyOf(alice);
    }

    function test_keyStatusEmptyReturnFailsClosed() public {
        pqcKeyStatusMock.setEmptyReturn(true);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_KEY_STATUS));
        h.bump(5, deadline, sig);
    }

    function test_keyStatusMissingCodeFailsClosed() public {
        vm.etch(PqAuth.PQC_KEY_STATUS, "");
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_KEY_STATUS));
        h.keyOf(alice);
    }

    function test_onChainKeyRotationIsFollowed() public {
        // The chain's registry now holds a new key for alice (MsgRotatePQCKey).
        bytes32 rotated = keccak256("alice rotated");
        registerPqKey(alice, rotated);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory oldSig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, oldSig);
        h.bump(5, deadline, _bumpSig(rotated, alice, 5, 0, deadline));
        assertEq(h.counter(), 5);
    }

    // ------------------------------------------------------------------ the verifier

    function test_verifyEmptyReturnFailsClosed() public {
        pqcVerifyMock.setMode(MockPqcVerify.Mode.EmptyReturn);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_VERIFY));
        h.bump(5, deadline, sig);
    }

    function test_verifyMissingCodeFailsClosed() public {
        vm.etch(PqAuth.PQC_VERIFY, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqPrecompileUnavailable.selector, PqAuth.PQC_VERIFY));
        h.bump(5, deadline, sig);
    }

    function test_verifyRevertIsInvalid() public {
        pqcVerifyMock.setMode(MockPqcVerify.Mode.Revert);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    function test_verifyShortReturnIsInvalid() public {
        pqcVerifyMock.setMode(MockPqcVerify.Mode.ShortReturn);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    function test_verifyNonBooleanWordIsInvalid() public {
        pqcVerifyMock.setMode(MockPqcVerify.Mode.BadWord);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, 5, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(5, deadline, sig);
    }

    // ------------------------------------------------------------------ rotation

    function test_rotateToNewSigner() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory m = pqMessage(address(h), alice, h.ACTION_ROTATE(), 0, deadline, keccak256(abi.encode(bob)));
        h.rotate(bob, deadline, pqSign(ALICE_SECRET, m));
        assertEq(h.signer(), bob);
        // alice can no longer act; bob can, at the next nonce.
        bytes memory aliceSig = _bumpSig(ALICE_SECRET, alice, 1, 1, deadline);
        bytes memory bobSig = _bumpSig(BOB_SECRET, bob, 1, 1, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(1, deadline, aliceSig);
        h.bump(1, deadline, bobSig);
        assertEq(h.counter(), 1);
    }

    function test_rotateRefusesAccountWithoutKey() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory m = pqMessage(address(h), alice, h.ACTION_ROTATE(), 0, deadline, keccak256(abi.encode(attacker)));
        bytes memory sig = pqSign(ALICE_SECRET, m);
        vm.expectRevert(abi.encodeWithSelector(PqAuth.PqKeyUnusable.selector, attacker, false, 0, false, 0));
        h.rotate(attacker, deadline, sig);
        assertEq(h.signer(), alice);
        assertEq(h.nonce(), 0, "a reverted rotation must not consume the nonce");
    }

    // ------------------------------------------------------------------ fuzz

    /// Without the secret, no signature bytes authorise anything.
    function testFuzz_forgedSignatureNeverAuthorises(bytes32 seed, uint256 by, address sender) public {
        bytes memory sig = new bytes(4627);
        for (uint256 i = 0; i < 4627; i += 32) {
            bytes32 w = keccak256(abi.encode(seed, i));
            for (uint256 j = 0; j < 32 && i + j < 4627; ++j) {
                sig[i + j] = w[j];
            }
        }
        vm.prank(sender);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(by % 1e18, block.timestamp + 1 hours, sig);
    }

    /// A signature made with any secret other than the signer's never verifies.
    function testFuzz_wrongSecretNeverAuthorises(bytes32 secret, uint96 by) public {
        vm.assume(secret != ALICE_SECRET && secret != bytes32(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(secret, alice, by, 0, deadline);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(by, deadline, sig);
    }

    /// The signer's signature works whoever relays it, and exactly once.
    function testFuzz_anyRelayerExactlyOnce(address relayer, uint96 by) public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _bumpSig(ALICE_SECRET, alice, by, 0, deadline);
        vm.prank(relayer);
        h.bump(by, deadline, sig);
        assertEq(h.counter(), by);
        vm.prank(relayer);
        vm.expectRevert(PqAuth.PqSignatureInvalid.selector);
        h.bump(by, deadline, sig);
    }
}
