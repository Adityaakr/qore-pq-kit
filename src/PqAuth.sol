// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title PqAuth
/// @notice Post-quantum authorisation for QoreChain EVM contracts.
///
/// A contract that uses this library names one *signer account*. Each sensitive
/// action must carry a fresh ML-DSA-87 signature, made with the post-quantum key
/// that account has registered on chain, over a message that binds:
///
///   DOMAIN ‖ chain id ‖ this contract ‖ signer ‖ action ‖ nonce ‖ deadline ‖ argument hash
///
/// The key is read from the chain's own registry (`pqcKeyStatus`, 0x…0A02) at
/// every check, so a key rotation on chain is followed automatically, and it is
/// only accepted if it is ML-DSA-87 AND was registered with a verified proof of
/// possession. The signature is checked by `pqcVerify` (0x…0A01).
///
/// Who sends the transaction does not matter. `msg.sender` authorises nothing:
/// anyone may relay a signed action, and nobody can act without one, including
/// whoever holds the signer account's classical secp256k1 key.
///
/// ## Failure is closed
///
/// - An inactive precompile answers with success and EMPTY data. Both helpers
///   refuse that: `keyOf` reverts with `PqPrecompileUnavailable`, and `verify`
///   reverts with it too, so a chain where the precompile is switched off cannot
///   be mistaken for "signature valid" or "no key".
/// - A failed call, a return of the wrong length, or any word other than exactly
///   1 is "invalid".
/// - The nonce is consumed only after the signature verifies, and each nonce is
///   accepted once, so a signature cannot be replayed. The deadline bounds how
///   long a signed-but-unused authorisation stays usable; `maxTtl` lets the
///   contract refuse signatures that were made to last too long.
library PqAuth {
    /// @dev Written lower-case on purpose. The docs and the SDK spell them
    ///      `0x…0A01`, which is not a valid EIP-55 checksum: solc refuses that
    ///      literal and viem refuses that string.
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_KEY_STATUS = 0x0000000000000000000000000000000000000a02;

    uint8 internal constant ALGORITHM_ML_DSA_87 = 1;
    uint256 internal constant ML_DSA_87_PUBLIC_KEY_LENGTH = 2592;
    uint256 internal constant ML_DSA_87_SIGNATURE_LENGTH = 4627;

    /// @notice Domain tag at the start of every signed message.
    bytes32 internal constant DOMAIN = keccak256("qore-pq-kit.PqAuth.v1");

    /// @dev The smallest well-formed pqcKeyStatus answer: four head words plus the
    ///      length word of an empty `bytes`.
    uint256 private constant KEY_STATUS_MIN_RETURN = 160;

    /// @notice The authorising account and its next nonce.
    struct Signer {
        address account;
        uint64 nonce;
    }

    event PqAuthorized(address indexed signer, bytes32 indexed action, uint256 nonce, bytes32 argsHash);
    event PqSignerChanged(address indexed previous, address indexed next);

    error PqPrecompileUnavailable(address precompile);
    error PqKeyUnusable(address account, bool registered, uint8 algorithmId, bool possessionProven, uint256 keyLength);
    error PqBadSignatureLength(uint256 length);
    error PqSignatureInvalid();
    error PqExpired(uint256 deadline, uint256 timestamp);
    error PqDeadlineTooFar(uint256 deadline, uint256 latestAllowed);
    error PqZeroSigner();

    // ---------------------------------------------------------------------
    // Reading the chain
    // ---------------------------------------------------------------------

    /// @notice The account's registered ML-DSA-87 public key, or a revert if it has
    ///         none usable (not registered, another algorithm, possession not
    ///         proven, or a key of the wrong length).
    function keyOf(address account) internal view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) =
            PQC_KEY_STATUS.staticcall(abi.encodeWithSignature("pqcKeyStatus(address)", account));
        if (!ok || ret.length < KEY_STATUS_MIN_RETURN) revert PqPrecompileUnavailable(PQC_KEY_STATUS);
        // abi.decode reverts on malformed data (and on a bool word other than 0 or 1).
        (bool registered, uint8 algorithmId, bytes memory key, bool possessionProven) =
            abi.decode(ret, (bool, uint8, bytes, bool));
        if (
            !registered || algorithmId != ALGORITHM_ML_DSA_87 || !possessionProven
                || key.length != ML_DSA_87_PUBLIC_KEY_LENGTH
        ) {
            revert PqKeyUnusable(account, registered, algorithmId, possessionProven, key.length);
        }
        return key;
    }

    /// @notice True only if `pqcVerify` answered exactly `true`.
    /// @dev Reverts with `PqPrecompileUnavailable` on empty return data: that is
    ///      what an inactive precompile answers, and it must never read as a
    ///      verdict either way.
    function verify(bytes memory pubkey, bytes memory signature, bytes memory signedMessage)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory ret) = PQC_VERIFY.staticcall(
            abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", pubkey, signature, signedMessage)
        );
        if (ok && ret.length == 0) revert PqPrecompileUnavailable(PQC_VERIFY);
        if (!ok || ret.length != 32) return false;
        return abi.decode(ret, (uint256)) == 1;
    }

    // ---------------------------------------------------------------------
    // The signed message
    // ---------------------------------------------------------------------

    /// @notice The exact bytes the signer's ML-DSA-87 key signs (256 bytes).
    function message(
        address verifier,
        address signer,
        bytes32 action,
        uint256 nonce,
        uint256 deadline,
        bytes32 argsHash
    ) internal view returns (bytes memory) {
        return abi.encode(DOMAIN, block.chainid, verifier, signer, action, nonce, deadline, argsHash);
    }

    // ---------------------------------------------------------------------
    // Using it
    // ---------------------------------------------------------------------

    /// @notice Set the first signer. Reverts unless it has a usable ML-DSA-87 key.
    function init(Signer storage s, address account) internal {
        if (account == address(0)) revert PqZeroSigner();
        keyOf(account);
        s.account = account;
        emit PqSignerChanged(address(0), account);
    }

    /// @notice Replace the signer (call it only after `authorize`). The nonce keeps
    ///         counting, so no signature made for the old signer can be replayed.
    function setSigner(Signer storage s, address next) internal {
        if (next == address(0)) revert PqZeroSigner();
        keyOf(next);
        address previous = s.account;
        s.account = next;
        emit PqSignerChanged(previous, next);
    }

    /// @notice Check a fresh signature for `action` with arguments `argsHash`, then
    ///         consume the nonce. Reverts on anything short of a valid signature.
    /// @param maxTtl  the furthest in the future a deadline may be, in seconds
    function authorize(
        Signer storage s,
        bytes32 action,
        bytes32 argsHash,
        uint256 deadline,
        uint256 maxTtl,
        bytes calldata signature
    ) internal {
        if (block.timestamp > deadline) revert PqExpired(deadline, block.timestamp);
        if (deadline > block.timestamp + maxTtl) revert PqDeadlineTooFar(deadline, block.timestamp + maxTtl);
        if (signature.length != ML_DSA_87_SIGNATURE_LENGTH) revert PqBadSignatureLength(signature.length);
        address account = s.account;
        if (account == address(0)) revert PqZeroSigner();
        uint256 nonce = s.nonce;

        bytes memory signed = message(address(this), account, action, nonce, deadline, argsHash);
        if (!verify(keyOf(account), signature, signed)) revert PqSignatureInvalid();

        s.nonce = uint64(nonce + 1);
        emit PqAuthorized(account, action, nonce, argsHash);
    }
}
