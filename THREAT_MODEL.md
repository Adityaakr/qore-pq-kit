# Threat model: qore-pq-kit

Scope: the threshold module (`src/threshold/`, `scripts/threshold.ts`). The
single-signer ML-DSA-87 library `PqAuth` came unchanged from `peal-tender/kit/`;
peal-tender's own `THREAT_MODEL.md` covers it. Its rules (key read live from
`pqcKeyStatus`, possession proven, fail closed on an empty precompile answer)
were checked live by the drill worker (peal-tender `kit/README.md`).

## What the threshold module promises

A sender commits a 32-byte plaintext as `(ct, keyHash, shareHash_1..n)` and
seals share j to committee member j. Given an application that stores those
commitments and accepts each share only if it matches its hash:

1. **Confidentiality before release.** Reading the plaintext needs K. K needs t
   shares (fewer than t shares of a random polynomial say nothing about K), or
   breaking ML-KEM-1024 *and* X25519 for t members' envelopes, or inverting a
   keccak key stream over a 255-bit key. Envelopes recorded today stay safe
   against a future quantum computer under the ML-KEM-1024 assumption.
2. **Integrity.** Everything is fixed at commit. A wrong share fails
   `checkShare`. A key recombined from consistent shares of a different
   polynomial fails `keyHash`, and `recover` reports that as `false` so the
   application can exclude the slot rather than fail.
3. **Binding.** Every hash and the key stream bind `block.chainid`, the app
   contract, the sender and the sender's sequence number. Each envelope's AAD
   binds the same plus the share index and its committed hash, and QoreSeal
   binds the Cosmos chain id and the application's purpose string. An envelope
   copied into another slot, app, chain or index does not open (tested).
4. **Key checks before sealing.** `verifyMember` takes the ML-DSA-87 key from
   the chain by `eth_call` (not REST), and accepts the ML-KEM-1024 key and the
   recipient card from REST only if they match hashes the member signed on
   chain. REST and any proxy in front of it are untrusted.

## What it does not promise

- **t colluding members can read early**, or withhold a chosen slot. This is
  inherent in threshold sealing; the application decides what a withheld slot
  costs.
- **A sender colluding with one member** learns that member's share early and
  can decide whether to deal it inconsistently; applications that care add a
  bond or a commit-then-reveal release.
- **Metadata is public**: who committed, when, and anything the application
  stores in clear (escrow amounts, for example).
- **The plaintext is exactly 32 bytes**, and each K is used for one slot only.
  Reusing (app, sender, seq) with a new K would reuse nothing (the key stream
  depends on K) but would let two commitments share a seq; applications must
  derive `seq` from an on-chain counter.
- **Randomness.** K and the polynomial come from the Web Crypto random source.
  A broken RNG in the sender's browser breaks that sender's slots only.
- **The precompiles.** `Shamir.inverse` uses modexp at `0x05`; it is checked
  (`a * inv == 1`) and fails closed. On QoreChain it was verified live
  (`docs/spikes.md`).
- **QoreSeal 0.1.0 is a draft** pending external review, and pins QoreSign
  0.1.0 while 0.2.0 is current. Cards signed on either version verify on the
  other (`test-ts/qoresign-compat.test.ts`).
- **No audit.** Nothing here has been audited.

## Keys and secrets

The kit never prints or logs a mnemonic, a seed or a private key. Test keys in
`test-ts/fixtures.ts` are derived from public labels and are for tests only.
Testnet accounts used for spikes live outside the repository with 0600
permissions.
