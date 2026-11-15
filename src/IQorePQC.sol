// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title IQorePQC
/// @notice The QoreChain post-quantum precompiles, as their node answers them on
///         the testnet `qorechain-diana` (EVM chain id 9800).
/// @dev    pqcVerify lives at 0x…0A01, pqcKeyStatus at 0x…0A02. Both are active on
///         the testnet only. An address that is not in the chain's
///         `active_static_precompiles` list answers a call with success and EMPTY
///         return data instead of reverting, so never trust a call that returned
///         no data. `PqAuth` handles this; use it instead of calling these directly.
interface IQorePQC {
    /// @notice Verify an ML-DSA-87 signature (2,592-byte key, 4,627-byte signature).
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool valid);

    /// @notice The account's registered post-quantum key.
    /// @return registered        true if a key is registered
    /// @return algorithmId       1 = ML-DSA-87
    /// @return pubkey            the key bytes (empty if none)
    /// @return possessionProven  true only if the key was registered with a verified
    ///                           proof of possession (chain v3.2.4 and later)
    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}
