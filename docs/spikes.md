# Spikes on the testnet

Facts about `qorechain-diana` (EVM chain id 9800) that the design depends on,
settled by experiment rather than by the docs, which contradict themselves.
Each entry says what was run, when, and what it printed. Spikes S1 to S6 are
from section 9 of the combined design; K-numbered entries are the kit's own.

Endpoints: EVM RPC `https://evm-testnet.qore.host`, REST
`https://api-testnet.qore.host`.

| # | Question | Status |
| --- | --- | --- |
| K1 | Does the modexp precompile (`0x05`) work, and do `Shamir.sol` / `SealedSlot.sol` give the vectors' answers on the real chain? | **Settled: yes** (16 Nov) |
| S1 | Does `pqcKeyStatus`'s fourth word mean "possession proven" (compare with REST `possession_proven` on a fresh registration)? | Open: needs a funded throwaway account |
| S2 | Does `MsgExecuteEVM` with a linked key and a spending rule work end to end; does it need the owner's EVM window? | Open: needs funded accounts |
| S3 | QoreSeal in a Vite browser bundle; KEM registration; cards across QoreSign 0.1.0 / 0.2.0 | Cards: **settled offline** (16 Nov). Bundle and registration: open |
| S4 | CORS on REST and EVM RPC from a browser | Open |
| S5 | Faucet: fUSD as ERC-20 balance or bank coin; scripted address | Open: owner's dashboard sign-in |
| S6 | Gas of `pqcVerify` at 256-byte messages | Open |

## K1. modexp and the threshold libraries on the live chain (16 November 2026)

**Run:** `cast call 0x…05` with base 3, exponent 2, modulus 7, then
`npm run probe:threshold`, which sends `test/live/ThresholdProbe.sol`'s creation
code as an `eth_call` with no `to`. The constructor recombines a vector case's
shares with `Shamir.combineAtZero`, computes `SealedSlot.keyHash` and decrypts
`ct`, and returns the results. Nothing is deployed and no account is used.

**Printed** (block 10,159,564):

```
modexp(3, 2, 7) = 0x…02
rpc https://evm-testnet.qore.host, chain id 9800, block 10159564
ok   2-of-3 on qorechain-diana: shares 2,3 -> key matches, combineAtZero 3730 gas
ok   2-of-3, next seq: shares 2,3 -> key matches, combineAtZero 3730 gas
ok   3-of-5: shares 3,4,5 -> key matches, combineAtZero 5510 gas
ok   1-of-1 (share is the key): shares 1 -> key matches, combineAtZero 2580 gas
ok   7-of-7: shares 1,2,3,4,5,6,7 -> key matches, combineAtZero 18955 gas
ok   key P - 1: shares 2,3 -> key matches, combineAtZero 3730 gas
ok   key 0: shares 2,3 -> key matches, combineAtZero 3730 gas
```

**Conclusion:** modexp is active on QoreChain's EVM, and the on-chain
recombination, key hash and decryption agree with the TypeScript dealer on the
live chain. Recombining is cheap next to `pqcVerify` (about 313k gas, per the
design; S6 measures it).

## S3 (cards part). QoreSign 0.1.0 and 0.2.0 (16 November 2026)

**Run:** `test-ts/qoresign-compat.test.ts`, with `@qorechain/qoreseal@0.1.0`
(which pulls `@qorechain/qoresign@0.1.0`), `@qorechain/qoresign@0.2.0`, and
0.1.0 again under an alias so both can be called directly.

**Result:** both versions build identical message sign bytes; a card signed by
QoreSeal (0.1.0 inside) verifies with 0.2.0 `verifyMessage({requirePq: true})`;
a card signed with 0.2.0 `signMessage` verifies in QoreSeal's
`verifyRecipientCard`; a card signed with the wrong ML-DSA key fails on both.
So risk R4 does not block cards. The browser bundle and a live KEM
registration remain open.
