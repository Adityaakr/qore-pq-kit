// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Shamir} from "./Shamir.sol";

/// @title SealedSlot
/// @notice One 32-byte secret ("slot") a sender commits to on chain, sealed so
///         that only a threshold of a committee can open it, and opened by the
///         contract itself once enough key shares are posted.
///
/// The sender (in a browser, with `scripts/threshold.ts`):
///
///   1. draws a random key K in F_P (P = 2^255 - 19);
///   2. encrypts its 32-byte plaintext:      ct = pt XOR keystream(K);
///   3. splits K t-of-n (Shamir), share j = f(j);
///   4. seals each share to committee member j with QoreSeal (ML-KEM-1024);
///   5. commits ct, keyHash(K) and shareHash_j for every j.
///
/// Members later post their opened shares; the contract checks each against its
/// shareHash, recombines K from any t of them, checks K against keyHash and
/// decrypts ct. Nobody, the committee included, can change what was committed.
///
/// Every hash is `keccak256(abi.encode(DOMAIN, block.chainid, app, sender, seq, ...))`:
/// - `app` is the contract the slot belongs to (an auction, say);
/// - `sender` is who committed it;
/// - `seq` is the sender's own counter in that app, so two slots by one sender
///   never share a key stream or a share hash.
///
/// The key stream is a single keccak block: the plaintext is exactly 32 bytes.
/// K is only ever used for one slot, because every hash binds (app, sender, seq).
library SealedSlot {
    bytes32 internal constant KEY_DOMAIN = keccak256("qore-pq-kit.SealedSlot.key.v1");
    bytes32 internal constant SHARE_DOMAIN = keccak256("qore-pq-kit.SealedSlot.share.v1");
    bytes32 internal constant DEM_DOMAIN = keccak256("qore-pq-kit.SealedSlot.dem.v1");

    /// @notice Commitment to the slot key K.
    function keyHash(address app, address sender, uint256 seq, uint256 key) internal view returns (bytes32) {
        return keccak256(abi.encode(KEY_DOMAIN, block.chainid, app, sender, seq, key));
    }

    /// @notice Commitment to share `index` (1-based) of the slot key.
    function shareHash(address app, address sender, uint256 seq, uint256 index, uint256 share)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(SHARE_DOMAIN, block.chainid, app, sender, seq, index, share));
    }

    /// @notice The 32-byte key stream the plaintext is XORed with.
    function keystream(address app, address sender, uint256 seq, uint256 key) internal view returns (bytes32) {
        return keccak256(abi.encode(DEM_DOMAIN, block.chainid, app, sender, seq, key));
    }

    /// @notice Decrypt (or encrypt: it is an XOR) one slot.
    function open(address app, address sender, uint256 seq, uint256 key, bytes32 ct) internal view returns (bytes32) {
        return ct ^ keystream(app, sender, seq, key);
    }

    /// @notice True if `share` is the committed share `index` of the slot.
    function checkShare(address app, address sender, uint256 seq, uint256 index, uint256 share, bytes32 committed)
        internal
        view
        returns (bool)
    {
        return shareHash(app, sender, seq, index, share) == committed;
    }

    /// @notice Recombine K from shares and check it against the committed keyHash.
    /// @dev    Returns (false, 0) rather than reverting when the recombined key
    ///         does not match, which is what inconsistent shares from a
    ///         dishonest sender produce: the caller can then exclude the slot
    ///         instead of failing. Malformed input (duplicate or zero indices,
    ///         values out of range) still reverts, as in `Shamir`.
    ///         The caller must check each share against its shareHash first;
    ///         this function does not, because the caller already holds them.
    function recover(
        address app,
        address sender,
        uint256 seq,
        uint256[] memory indices,
        uint256[] memory shares,
        bytes32 committedKeyHash
    ) internal view returns (bool ok, uint256 key) {
        key = Shamir.combineAtZero(indices, shares);
        if (keyHash(app, sender, seq, key) != committedKeyHash) return (false, 0);
        return (true, key);
    }
}
