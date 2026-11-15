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
| S1 | Does `pqcKeyStatus`'s fourth word mean "possession proven" (compare with REST `possession_proven` on a fresh registration)? | Open: needs a funded throwaway account. The shape is confirmed (S6) |
| S2 | Does `MsgExecuteEVM` with a linked key and a spending rule work end to end; does it need the owner's EVM window? | Open: needs funded accounts |
| S3 | QoreSeal in a Vite browser bundle; KEM registration; cards across QoreSign 0.1.0 / 0.2.0 | Cards: **settled offline** (16 Nov). Bundle and registration: open |
| S4 | CORS on REST and EVM RPC from a browser | **Settled** (16 Nov): EVM RPC allows any origin; REST and CometBFT RPC send no CORS headers |
| S5 | Faucet: fUSD as ERC-20 balance or bank coin; scripted address | Open: owner's dashboard sign-in |
| S6 | Gas of `pqcVerify` at 256-byte messages | **Settled** (16 Nov): about 92k gas for the precompile; about 318k for a whole transaction carrying one signature |

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

## S4. CORS from a browser (16 November 2026)

**Run:** `curl` with `Origin: http://localhost:5173`, once as a plain request
and once as a CORS preflight (`OPTIONS` with `Access-Control-Request-Method`).

| Endpoint | Plain request | Preflight |
| --- | --- | --- |
| EVM RPC `https://evm-testnet.qore.host` (`POST eth_chainId`) | 200, `access-control-allow-origin: *` | 204, allows `POST` and `content-type` from `*` |
| REST `https://api-testnet.qore.host` (`GET /qorechain/pqc/v1/params`) | 200, **no** `access-control-*` header | **501** |
| CometBFT RPC `https://rpc-testnet.qore.host` (`GET /status`) | 200, **no** `access-control-*` header | not tried |

**Conclusion:** a browser page can talk to the EVM RPC directly, including
`eth_call` to `pqcKeyStatus`, so the ML-DSA key a bidder checks needs no proxy.
REST (ML-KEM keys, accounts, windows) needs a proxy, which the design already
plans and treats as untrusted: `verifyMember` checks what it returns against
hashes on chain. Native transactions from a browser would also need a proxy for
the CometBFT RPC.

## S6. What `pqcVerify` and `pqcKeyStatus` cost (16 November 2026)

**Run:** `forge build && npx tsx scripts/pqc-gas-probe.ts`. Each line is one
`eth_call` of `test/live/StaticcallGasProbe.sol`'s creation code, which makes
one STATICCALL and returns the gas it used. The ML-DSA-87 key is a throwaway
made for the run and never registered. Nothing is sent.

**Printed** (block 10,159,719):

```
valid signature, 32-byte message                 ok=true returnBytes=32 word=1 staticcallGas=90302
valid signature, 256-byte message                ok=true returnBytes=32 word=1 staticcallGas=92190
valid signature, 1024-byte message               ok=true returnBytes=32 word=1 staticcallGas=98669
bit-flipped signature                            ok=true returnBytes=32 word=0 staticcallGas=92190
other message                                    ok=true returnBytes=32 word=0 staticcallGas=92190
other key                                        ok=true returnBytes=32 word=0 staticcallGas=92190
short key (100 bytes)                            ok=true returnBytes=32 word=0 staticcallGas=71478
short signature (100 bytes)                      ok=true returnBytes=32 word=0 staticcallGas=54350
arguments as (pubkey, message, signature)        ok=true returnBytes=32 word=0 staticcallGas=92190
inactive precompile address 0x…0a09              ok=true returnBytes=0 word=- staticcallGas=4826
pqcKeyStatus, account with a key                 ok=true returnBytes=2752 word=1 staticcallGas=6017
  -> registered=true algorithm=1 keyBytes=2592 fourthWord=true
pqcKeyStatus, fresh address (no key)             ok=true returnBytes=160 word=0 staticcallGas=5512
  -> registered=false algorithm=0 keyBytes=0 fourthWord=false
eth_estimateGas, direct transaction to pqcVerify (7684 bytes calldata): 317680
```

**Conclusions:**

- `pqcVerify` itself costs about **92k gas** at 256 bytes, rising slowly with
  message length. Most of the "about 313k" the design quotes is calldata: a
  direct transaction carrying the key, the signature and the message
  estimates at 317,680. In a contract that reads the key with `pqcKeyStatus`,
  the calldata is the 4,627-byte signature (about 74k gas at 16 gas per byte)
  plus the 92k verification and about 6k for the key read. So **one PqAuth
  check is about 170k gas** on top of the transaction, and a 2-of-3 PqAuthSet
  action about 340k. Committee joins and multisig actions fit well inside a
  block.
- `pqcVerify` takes `(pubkey, signature, message)`. Swapping message and
  signature gives `0`, not an error.
- Every invalid input answers a clean 32-byte `0`: it never reverts.
- An address that is not an active precompile answers **success with empty
  data**, exactly as `PqAuth` assumes, so treating empty data as "unavailable"
  (fail closed) is right.
- `pqcKeyStatus` for an address with no key answers 160 bytes, which is
  `PqAuth`'s `KEY_STATUS_MIN_RETURN`. For a registered account it answers the
  four-value shape `(bool, uint8, bytes, bool)` with a 2,592-byte key and the
  fourth word `true`. Whether that word means "possession proven" for a fresh
  registration is spike S1.
