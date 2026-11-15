# qore-pq-kit

Shared post-quantum toolkit for QoreChain EVM apps, built for the QoreChain
"Build Before Q-Day" hackathon. It is used by Peal Tender, Peal Sealed Auction
and Peal Bidder, and it can be used by any contract on `qorechain-diana`
(EVM chain id 9800).

| Module | What it is | Status |
| --- | --- | --- |
| `src/threshold/Shamir.sol` | Recombines t-of-n Shamir shares over F_P, P = 2^255 - 19, with one modular inverse through the modexp precompile | **This release** |
| `src/threshold/SealedSlot.sol` | Domain-separated hashes and a one-block keccak cipher for a 32-byte secret only a committee threshold can open, opened by the contract itself | **This release** |
| `scripts/threshold.ts` | Deals the key, seals each share to one committee member with QoreSeal (ML-KEM-1024 + X25519), opens shares, and checks a member's on-chain keys before sealing to it | **This release** |
| `src/PqAuth.sol`, `src/IQorePQC.sol`, precompile mocks, account / register / window / pqauth / secrets / probe scripts | ML-DSA-87 authorisation over `pqcKeyStatus` and `pqcVerify`, plus testnet scripts | v0.1.0, from `peal-tender/kit/` with its history |
| `src/PqAuthSet.sol` | t-of-n ML-DSA-87 signer set | Next |
| `scripts/messaging.ts`, `scripts/rest.ts`, `scripts/smart-account.ts` | Signed and sealed instructions; REST reader with a proxy; linked keys and spending rules | Later |

## ML-DSA-87 authorisation (from `peal-tender/kit/`)

This part of the kit was written for the Peal Tender drill and moved here unchanged with its history (`git subtree split --prefix=kit`).

### Solidity: `src/PqAuth.sol`

```solidity
import {PqAuth} from "qore-pq-kit/PqAuth.sol";

contract Vault {
    using PqAuth for PqAuth.Signer;
    bytes32 constant ACTION_SWEEP = keccak256("Vault.sweep");
    PqAuth.Signer internal signer;

    constructor(address account) { signer.init(account); } // needs a proven ML-DSA-87 key

    function sweep(address to, uint256 amount, uint256 deadline, bytes calldata sig) external {
        signer.authorize(ACTION_SWEEP, keccak256(abi.encode(to, amount)), deadline, 1 days, sig);
        // ... move funds. msg.sender is irrelevant.
    }
}
```

`authorize` reads the signer's key with `pqcKeyStatus` (`0x…0a02`), requires
ML-DSA-87 (algorithm 1), `possessionProven` and a 2,592-byte key, verifies the
4,627-byte signature with `pqcVerify` (`0x…0a01`) over

```
abi.encode(keccak256("qore-pq-kit.PqAuth.v1"), chainid, contract, signer, action, nonce, deadline, argsHash)
```

(256 bytes) and consumes the nonce. It fails closed: an inactive precompile
answers success with **empty data**, which reverts `PqPrecompileUnavailable`
instead of reading as a verdict; a revert, short answer or any word other than 1
is "invalid".

### Tests: mocks of the precompiles

Foundry cannot run QoreChain's precompiles, so `test/mocks/` has stand-ins that
`test/PqTestBase.sol` etches at the real addresses: a keyed-hash "signature" with
ML-DSA-87's byte lengths that only the holder of a test secret can produce, and
switches to imitate an inactive, reverting or misbehaving precompile.
`test/PqAuth.t.sol` (30 tests, three of them fuzzed) covers replay, binding of
every message field, freshness, the key registry rules, on-chain key rotation and
every failure mode.

### TypeScript: `scripts/`

| Command (`npm run pq -- …`) | What it does |
| --- | --- |
| `new-account <name>` | new mnemonic into `~/.qore-drill/<name>.env` (0600); prints addresses only |
| `status <name>` | balances, PQ key status, EVM window |
| `register <name>` | registers the ML-DSA-87 key with a proof of possession (the one classically-signed message); never registers blind |
| `open-window <name> <blocks> <txs> <gasPerTx> [targets]` | `MsgOpenEVMWindow`, scoped to `targets` when given |
| `close-window <name>` | `MsgCloseEVMWindow` |
| `probe <name>` | live, read-only probes of both precompiles and of `PqAuth.sol` itself (via `eth_call` of `test/live/PqAuthProbe.sol`'s creation code) |
| `rehearse <name> [contract] [token]` | the Q-Day Drill attacker: tries everything the classical key alone can do, and reports each answer and any fee charged |
| `swap-fusd`, `convert-fusd` | AMM swap to fUSD, and `MsgConvertCoin` of a fest bank coin straight into a contract's ERC-20 balance |

Library modules: `qore.ts` (network, accounts, hybrid broadcast), `window.ts`,
`evm.ts` (EVM sends with node-side gas estimation), `pqauth.ts` (`authMessage`,
`signAuth`), `fest.ts`, `rehearse.ts`, `probe.ts`.

### What we found by experiment (testnet `qorechain-diana`, v3.2.8, 15 Nov 2026)

- `pqcKeyStatus` returns four values `(bool, uint8, bytes, bool)`; for an account
  without a key the answer is 160 bytes (`false, 0, 0x, false`).
- `pqcVerify` of a real signature over a 256-byte message: true; one nibble changed or
  another nonce: false. About 317,000 gas as a whole transaction (calldata included);
  a vault `sweep` that runs the full check used 247,607 gas.
- Solidity refuses the docs' spelling `0x…0A01` as a bad checksum, like viem does.
  Write precompile addresses lower-case.
- `forge script` cannot deploy a contract whose constructor checks a PQ key: the
  local simulation has no precompiles. Deploy with a script that uses the node's
  `eth_estimateGas`.
- A classical-only second key registration is refused **at admission** (`pqc` code
  234) and charges no fee, contrary to the docs.
- A scoped window refuses contract creation; opening a window advances the nonce.
- The faucet paid 90 QOR per claim, and the fest-token transfer did not arrive.

## Threshold sealing

A sender seals one 32-byte plaintext (for example a bid's quantity and price)
so that no single party can read it before a committee releases, and so that
the contract, not the committee, decrypts it:

```
K           random element of F_P
ct          = plaintext XOR keccak(DEM_DOMAIN, chainid, app, sender, seq, K)
keyHash     = keccak(KEY_DOMAIN, chainid, app, sender, seq, K)
share j     = f(j), f random of degree t - 1, f(0) = K        (j = 1..n)
shareHash_j = keccak(SHARE_DOMAIN, chainid, app, sender, seq, j, share_j)
envelope_j  = QoreSeal seal of share_j to member j (ML-KEM-1024 + X25519),
              AAD = abi.encode(app, sender, seq, j, shareHash_j)
```

The sender commits `ct`, `keyHash` and every `shareHash_j` on chain and emits
the envelopes. After the close, each member opens its own envelope in its own
browser or daemon and posts the share. The contract checks each share against
its hash, recombines K from any t of them, checks K against `keyHash`, and
decrypts.

### Solidity

```solidity
import {SealedSlot} from "qore-pq-kit/threshold/SealedSlot.sol";

// at commit:  store ct, keyHash, shareHashes[] for (msg.sender, seq)
// at release: require(SealedSlot.checkShare(address(this), sender, seq, j, share, shareHashes[j - 1]));
// at open:
(bool ok, uint256 key) = SealedSlot.recover(address(this), sender, seq, indices, shares, keyHash);
if (!ok) { /* the sender dealt inconsistent shares: exclude the slot, do not fail */ }
bytes32 plaintext = SealedSlot.open(address(this), sender, seq, key, ct);
```

`Shamir.combineAtZero` refuses an index of 0 or at least P, a duplicate index,
and a value of at least P, so a share cannot count twice. It fails closed if the
modexp precompile is missing or wrong: the inverse is checked with one extra
`mulmod`. Recombining costs about 3,700 gas for 2 shares and 19,000 for 7, as
measured on the testnet (`docs/spikes.md`).

### TypeScript

```ts
import { sealSlot, openShare, openSlot, verifyMember } from "qore-pq-kit/threshold";

// sender: check each member's on-chain keys, then seal
const recipients = await Promise.all(committee.map((m) => verifyMember({ ...m, client, rest, sealChainId: "qorechain-diana" })));
const { ct, keyHash, shareHashes, envelopes } = sealSlot({
  binding: { chainId: 9800n, app: auction, sender: bidder, seq },
  plaintext, committee: recipients, threshold: 2,
  sealChainId: "qorechain-diana", purpose: "peal-sealed-auction/share/v1",
});

// member j, after the close
const share = openShare({ envelope, keys, binding, index: j, shareHash: shareHashes[j - 1], sealChainId, purpose });
```

`verifyMember` reads the member's ML-DSA-87 key from the chain itself
(`eth_call` to `pqcKeyStatus`), reads its ML-KEM-1024 key over REST and requires
its SHA3-256 to equal the hash the member signed into the app's registry, and
checks the member's QoreSeal recipient card against both keys and its committed
hash. A lying REST endpoint or proxy therefore cannot swap in its own key.

### Shared vectors

`npm run vectors` writes `vectors/threshold.json` deterministically.
`test/threshold/ThresholdVectors.t.sol` checks every hash, ciphertext and
recombination in it against the Solidity libraries byte for byte, and
`test-ts/threshold.test.ts` fails if the file differs from what the
TypeScript writes. `npm run probe:threshold` runs the Solidity libraries on the
live testnet against the same vectors with a single `eth_call` (no account, no
deployment, no gas).

## Install

Nothing is published to npm. Pin a git tag.

```sh
forge install Adityaakr/qore-pq-kit@v0.1.0-threshold.1     # Solidity
npm install github:Adityaakr/qore-pq-kit#v0.1.0-threshold.1  # TypeScript
```

Remap `qore-pq-kit/=lib/qore-pq-kit/src/` in `foundry.toml`. The TypeScript is
shipped as source (`.ts`), for Vite, tsx or another bundler.
`@qorechain/*` packages are pinned to exact versions.

## Develop

```sh
npm install
npm run setup          # forge-std into lib/
forge test             # Solidity: unit, fuzz and the shared vectors
npm run test:ts        # TypeScript: vitest
npm run typecheck
npm run probe:threshold
```

## Security

See `THREAT_MODEL.md`. QoreSeal 0.1.0 is a draft pending external review.
Nothing here has been audited.

## Prior work

The design of sealed bids opened on chain, the shared-vectors test pattern
(`contracts/test/auctionkit/CommitmentVectors.t.sol`) and the design rules
"bind every seal to its context" and "exclude, never fail" come from the
author's own earlier project, Peal (private, started 6 July 2026,
Apache-2.0), in particular `docs/plans/017-peal-redesign.md` section 4 and
`docs/pq/14-hybrid-seals.md`. Peal used pairing-based threshold encryption;
this kit replaces it with Shamir shares sealed with ML-KEM-1024, which is new
code. Every file in this repository was written during the hackathon.

## Licence

Apache-2.0. See `LICENSE`.
