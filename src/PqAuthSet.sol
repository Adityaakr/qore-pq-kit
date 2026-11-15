// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqAuth} from "./PqAuth.sol";

/// @title PqAuthSet
/// @notice A t-of-n set of post-quantum signers: a post-quantum multisig for
///         QoreChain EVM contracts, built on `PqAuth`.
///
/// Each member is an account with a registered ML-DSA-87 key (proven
/// possession, read live from `pqcKeyStatus` at every check, so on-chain key
/// rotation is followed). An action needs signatures from at least `threshold`
/// distinct members over the ordinary `PqAuth.message`, with `signer` set to
/// that member:
///
///   PqAuth.message(this contract, member, quorumAction(action), set nonce, deadline, argsHash)
///
/// - All members sign the same set nonce, which is consumed once per authorised
///   action, so no signature can be replayed and none made before a membership
///   change still counts after it.
/// - `quorumAction` puts the action under this library's own domain. A contract
///   that also guards something with a single `PqAuth.Signer` therefore cannot
///   have a single-signer signature accepted as a quorum share, or the reverse,
///   even if a member is that signer and the nonces coincide.
/// - Signers are passed in strictly ascending address order, which proves they
///   are distinct without a mapping.
/// - `msg.sender` authorises nothing: anyone may relay a signed action.
///
/// `authorizeAny` accepts one member's signature under a separate action
/// domain. It is meant for actions any single member may take alone, such as
/// cancelling a queued action in a timelock.
library PqAuthSet {
    /// @notice The largest set. A quorum of 16 costs about 16 x 170k gas.
    uint256 internal constant MAX_MEMBERS = 16;

    /// @notice Domain tags folded into the action of quorum and single-member signatures.
    bytes32 internal constant QUORUM_DOMAIN = keccak256("qore-pq-kit.PqAuthSet.quorum.v1");
    bytes32 internal constant ANY_DOMAIN = keccak256("qore-pq-kit.PqAuthSet.any.v1");

    struct Set {
        address[] members; // strictly ascending
        uint8 threshold;
        uint64 nonce;
    }

    event PqSetChanged(address[] members, uint256 threshold);
    event PqQuorumAuthorized(bytes32 indexed action, uint256 nonce, bytes32 argsHash, address[] signers);
    event PqMemberAuthorized(bytes32 indexed action, uint256 nonce, bytes32 argsHash, address indexed signer);

    error PqSetBadThreshold(uint256 threshold, uint256 members);
    error PqSetTooLarge(uint256 members);
    error PqSetNotAscending(uint256 index);
    error PqSetNotMember(address account);
    error PqSetTooFewSignatures(uint256 given, uint256 threshold);
    error PqSetLengthMismatch(uint256 signers, uint256 signatures);
    error PqSetUninitialised();

    // ---------------------------------------------------------------------
    // Setting the set
    // ---------------------------------------------------------------------

    /// @notice Set the first members. Each must have a usable ML-DSA-87 key.
    function init(Set storage s, address[] memory members, uint256 threshold) internal {
        _set(s, members, threshold);
    }

    /// @notice Replace the members and threshold (call it only after an
    ///         authorisation). The nonce keeps counting.
    function setMembers(Set storage s, address[] memory members, uint256 threshold) internal {
        _set(s, members, threshold);
    }

    function _set(Set storage s, address[] memory members, uint256 threshold) private {
        uint256 n = members.length;
        if (n > MAX_MEMBERS) revert PqSetTooLarge(n);
        if (threshold == 0 || threshold > n) revert PqSetBadThreshold(threshold, n);
        for (uint256 i = 0; i < n; ++i) {
            address m = members[i];
            if (m == address(0)) revert PqAuth.PqZeroSigner();
            if (i > 0 && m <= members[i - 1]) revert PqSetNotAscending(i);
            PqAuth.keyOf(m); // reverts unless the key is usable now
        }
        s.members = members;
        s.threshold = uint8(threshold);
        emit PqSetChanged(members, threshold);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function isMember(Set storage s, address account) internal view returns (bool) {
        address[] storage m = s.members;
        for (uint256 i = 0; i < m.length; ++i) {
            if (m[i] == account) return true;
        }
        return false;
    }

    /// @notice The action id a quorum signs for `action`.
    function quorumAction(bytes32 action) internal pure returns (bytes32) {
        return keccak256(abi.encode(QUORUM_DOMAIN, action));
    }

    /// @notice The action id a single member signs for `action` in `authorizeAny`.
    function anyAction(bytes32 action) internal pure returns (bytes32) {
        return keccak256(abi.encode(ANY_DOMAIN, action));
    }

    /// @notice The exact bytes `member` signs for a quorum action at the current nonce.
    function quorumMessage(Set storage s, address member, bytes32 action, uint256 deadline, bytes32 argsHash)
        internal
        view
        returns (bytes memory)
    {
        return PqAuth.message(address(this), member, quorumAction(action), s.nonce, deadline, argsHash);
    }

    // ---------------------------------------------------------------------
    // Authorising
    // ---------------------------------------------------------------------

    /// @notice Check at least `threshold` member signatures for `action` with
    ///         arguments `argsHash`, then consume the nonce. Reverts on anything
    ///         short of that.
    /// @param signers     members who signed, strictly ascending
    /// @param signatures  signatures[i] by signers[i], 4,627 bytes each
    /// @param maxTtl      the furthest in the future a deadline may be, in seconds
    function authorizeQuorum(
        Set storage s,
        bytes32 action,
        bytes32 argsHash,
        uint256 deadline,
        uint256 maxTtl,
        address[] calldata signers,
        bytes[] calldata signatures
    ) internal {
        _fresh(deadline, maxTtl);
        uint256 t = s.threshold;
        if (t == 0) revert PqSetUninitialised();
        if (signers.length != signatures.length) revert PqSetLengthMismatch(signers.length, signatures.length);
        if (signers.length < t) revert PqSetTooFewSignatures(signers.length, t);
        uint256 nonce = s.nonce;
        _checkAll(s, quorumAction(action), argsHash, deadline, signers, signatures);
        s.nonce = uint64(nonce + 1);
        emit PqQuorumAuthorized(action, nonce, argsHash, signers);
    }

    /// @notice Check one member's signature for `action` (under its own
    ///         domain), then consume the nonce.
    function authorizeAny(
        Set storage s,
        bytes32 action,
        bytes32 argsHash,
        uint256 deadline,
        uint256 maxTtl,
        address signer,
        bytes calldata signature
    ) internal {
        _fresh(deadline, maxTtl);
        if (s.threshold == 0) revert PqSetUninitialised();
        if (!isMember(s, signer)) revert PqSetNotMember(signer);
        uint256 nonce = s.nonce;
        _check(signer, anyAction(action), nonce, deadline, argsHash, signature);
        s.nonce = uint64(nonce + 1);
        emit PqMemberAuthorized(action, nonce, argsHash, signer);
    }

    function _checkAll(
        Set storage s,
        bytes32 qAction,
        bytes32 argsHash,
        uint256 deadline,
        address[] calldata signers,
        bytes[] calldata signatures
    ) private view {
        uint256 nonce = s.nonce;
        for (uint256 i = 0; i < signers.length; ++i) {
            address signer = signers[i];
            if (i > 0 && signer <= signers[i - 1]) revert PqSetNotAscending(i);
            if (!isMember(s, signer)) revert PqSetNotMember(signer);
            _check(signer, qAction, nonce, deadline, argsHash, signatures[i]);
        }
    }

    function _fresh(uint256 deadline, uint256 maxTtl) private view {
        if (block.timestamp > deadline) revert PqAuth.PqExpired(deadline, block.timestamp);
        if (deadline > block.timestamp + maxTtl) {
            revert PqAuth.PqDeadlineTooFar(deadline, block.timestamp + maxTtl);
        }
    }

    function _check(
        address signer,
        bytes32 signedAction,
        uint256 nonce,
        uint256 deadline,
        bytes32 argsHash,
        bytes calldata signature
    ) private view {
        if (signature.length != PqAuth.ML_DSA_87_SIGNATURE_LENGTH) {
            revert PqAuth.PqBadSignatureLength(signature.length);
        }
        bytes memory signed = PqAuth.message(address(this), signer, signedAction, nonce, deadline, argsHash);
        if (!PqAuth.verify(PqAuth.keyOf(signer), signature, signed)) revert PqAuth.PqSignatureInvalid();
    }
}
