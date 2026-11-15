# qore-pq-kit

Post-quantum authorisation for QoreChain EVM contracts, and the scripts to drive
it: ML-DSA-87 key registration, hybrid-signed native transactions, scoped EVM
windows, live precompile probes and a Q-Day Drill rehearsal.

This directory is self-contained (its own `foundry.toml`, `package.json` and
tests) so it can move unchanged into its own repository.

## Solidity: `src/PqAuth.sol`

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

## Tests: mocks of the precompiles

Foundry cannot run QoreChain's precompiles, so `test/mocks/` has stand-ins that
`test/PqTestBase.sol` etches at the real addresses: a keyed-hash "signature" with
ML-DSA-87's byte lengths that only the holder of a test secret can produce, and
switches to imitate an inactive, reverting or misbehaving precompile.
`test/PqAuth.t.sol` (30 tests, three of them fuzzed) covers replay, binding of
every message field, freshness, the key registry rules, on-chain key rotation and
every failure mode.

## TypeScript: `scripts/`

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

## What we found by experiment (testnet `qorechain-diana`, v3.2.8, 15 Nov 2026)

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

## Credits

Built with `@qorechain/sdk` and `@qorechain/evm` 0.14.0, viem, cosmjs and
forge-std. The precompile interfaces follow the QoreChain documentation.

Licence: Apache-2.0.
