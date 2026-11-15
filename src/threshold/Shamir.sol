// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Shamir
/// @notice Recombines Shamir secret shares over the prime field F_P,
///         P = 2^255 - 19, by Lagrange interpolation at x = 0.
///
/// A dealer picks a random polynomial f of degree t - 1 with f(0) = K and hands
/// out the points (x, f(x)) for x = 1..n. Any t distinct points give back K;
/// fewer give no information about it. `scripts/threshold.ts` deals the shares
/// and `vectors/threshold.json` pins both sides to the same bytes.
///
/// ## Cost
///
/// The sum of Lagrange terms is kept as one fraction N / D, so recombining t
/// shares costs about t^2 `mulmod`s and exactly one modular inverse, done by
/// the modexp precompile at 0x05 (Fermat: D^(P-2)).
///
/// ## Failure is closed
///
/// - Every x must be in [1, P - 1] and distinct, and every y must be below P;
///   anything else reverts, so a caller cannot make a share count twice.
/// - A modexp call that fails, answers with the wrong length (an inactive
///   precompile answers with success and EMPTY data), or answers with a value
///   that is not the inverse reverts with `ShamirModexpUnavailable`. The
///   inverse is checked by one extra `mulmod`, so a broken precompile cannot
///   make this return a wrong key.
library Shamir {
    /// @notice The field modulus, 2^255 - 19.
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

    /// @dev The modexp precompile (EIP-198) lives at 0x05.
    uint256 private constant MODEXP = 0x05;

    error ShamirLengthMismatch(uint256 xs, uint256 ys);
    error ShamirNoShares();
    error ShamirBadIndex(uint256 x);
    error ShamirBadValue(uint256 y);
    error ShamirDuplicateIndex(uint256 x);
    error ShamirModexpUnavailable();

    /// @notice f(0) for the unique polynomial of degree < xs.length through the
    ///         points (xs[i], ys[i]).
    /// @dev    With t points of a degree t - 1 dealing this is the secret. With
    ///         more points than the dealing's degree + 1 it is still the secret;
    ///         with fewer it is an unrelated field element, so callers must check
    ///         the result against a commitment (see `SealedSlot.recover`).
    function combineAtZero(uint256[] memory xs, uint256[] memory ys) internal view returns (uint256) {
        uint256 t = xs.length;
        if (t != ys.length) revert ShamirLengthMismatch(t, ys.length);
        if (t == 0) revert ShamirNoShares();

        // sum of y_i * l_i(0), where l_i(0) = prod_{j != i} x_j / (x_j - x_i),
        // accumulated as one fraction num / den.
        uint256 num = 0;
        uint256 den = 1;
        for (uint256 i = 0; i < t; ++i) {
            uint256 xi = xs[i];
            uint256 yi = ys[i];
            if (xi == 0 || xi >= P) revert ShamirBadIndex(xi);
            if (yi >= P) revert ShamirBadValue(yi);
            uint256 ni = 1;
            uint256 di = 1;
            for (uint256 j = 0; j < t; ++j) {
                if (j == i) continue;
                uint256 xj = xs[j];
                if (xj == xi) revert ShamirDuplicateIndex(xi);
                ni = mulmod(ni, xj, P);
                // xj - xi mod P; both are below P, so P - xi + xj does not overflow.
                di = mulmod(di, addmod(xj, P - xi, P), P);
            }
            // num/den + yi*ni/di = (num*di + yi*ni*den) / (den*di)
            num = addmod(mulmod(num, di, P), mulmod(mulmod(yi, ni, P), den, P), P);
            den = mulmod(den, di, P);
        }
        return mulmod(num, inverse(den), P);
    }

    /// @notice a^(-1) mod P, for a in [1, P - 1], through the modexp precompile.
    function inverse(uint256 a) internal view returns (uint256 inv) {
        // `den` above is a product of non-zero differences mod a prime, so it is
        // never zero; this guards direct callers.
        if (a == 0 || a >= P) revert ShamirBadValue(a);
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 0x20) // length of base
            mstore(add(p, 0x20), 0x20) // length of exponent
            mstore(add(p, 0x40), 0x20) // length of modulus
            mstore(add(p, 0x60), a) // base
            mstore(add(p, 0x80), sub(P, 2)) // exponent
            mstore(add(p, 0xa0), P) // modulus
            ok := staticcall(gas(), MODEXP, p, 0xc0, p, 0x20)
            size := returndatasize()
            inv := mload(p)
        }
        if (!ok || size != 32 || mulmod(a, inv, P) != 1) revert ShamirModexpUnavailable();
    }
}
