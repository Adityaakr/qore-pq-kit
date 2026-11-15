/**
 * threshold.ts - seal a 32-byte secret so that only t of n committee members
 * can open it, and so that a contract can open it on chain once they post their
 * key shares. The Solidity side is `src/threshold/Shamir.sol` and
 * `src/threshold/SealedSlot.sol`; `vectors/threshold.json` pins the two to the
 * same bytes.
 *
 *   K            random element of F_P, P = 2^255 - 19
 *   ct           = plaintext XOR keccak(DEM_DOMAIN, chainId, app, sender, seq, K)
 *   keyHash      = keccak(KEY_DOMAIN, chainId, app, sender, seq, K)
 *   share j      = f(j), f random of degree t - 1 with f(0) = K, j = 1..n
 *   shareHash_j  = keccak(SHARE_DOMAIN, chainId, app, sender, seq, j, share_j)
 *   envelope_j   = QoreSeal.seal(share_j to member j, ML-KEM-1024 + X25519,
 *                  aad = abi.encode(app, sender, seq, j, shareHash_j))
 *
 * Every hash is keccak256 of `abi.encode` of 32-byte words, exactly as the
 * Solidity library computes it.
 *
 * This module runs in browsers as well as Node: it uses only viem, QoreSeal,
 * noble hashes and the Web Crypto random source.
 */
import {
  open as qoresealOpen,
  recipientCardSignBytes,
  seal as qoresealSeal,
  validateMlkemPublicKey,
  verifyRecipientCard,
  type RecipientCard,
  type SealKeyPair,
  type SealMode,
  type SealRecipient,
} from "@qorechain/qoreseal";
import { fetchKemKey } from "@qorechain/qoreseal/network";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { bech32 } from "@scure/base";
import {
  bytesToHex,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hexToBytes,
  keccak256,
  toBytes,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";

// ---------------------------------------------------------------------------
// The field
// ---------------------------------------------------------------------------

/** The field modulus, 2^255 - 19 (`Shamir.P`). */
export const FIELD_P = (1n << 255n) - 19n;

/** The largest committee `split` deals to. Indices are 1..n. */
export const MAX_SHARES = 255;

function mod(a: bigint): bigint {
  const r = a % FIELD_P;
  return r < 0n ? r + FIELD_P : r;
}

function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % FIELD_P;
    b = (b * b) % FIELD_P;
    e >>= 1n;
  }
  return result;
}

/** a^(-1) mod P (Fermat), for a in [1, P - 1]. */
export function fieldInverse(a: bigint): bigint {
  if (a <= 0n || a >= FIELD_P) throw new Error("fieldInverse: value out of range");
  return modPow(a, FIELD_P - 2n);
}

/** A uniformly random element of F_P, from the Web Crypto random source. */
export function randomFieldElement(): bigint {
  for (;;) {
    const b = new Uint8Array(32);
    globalThis.crypto.getRandomValues(b);
    b[0]! &= 0x7f; // below 2^255; P is 19 short of that, so a retry is very rare
    const v = BigInt(bytesToHex(b));
    if (v < FIELD_P) return v;
  }
}

// ---------------------------------------------------------------------------
// Shamir
// ---------------------------------------------------------------------------

/** One point of the dealing polynomial: `index` is x (1-based), `value` is f(x). */
export interface Share {
  index: number;
  value: bigint;
}

/**
 * Split `secret` into n shares, any t of which give it back.
 * `random` draws the polynomial's coefficients; leave it out except for test vectors.
 */
export function split(secret: bigint, t: number, n: number, random: () => bigint = randomFieldElement): Share[] {
  if (secret < 0n || secret >= FIELD_P) throw new Error("split: secret out of range");
  if (!Number.isInteger(t) || !Number.isInteger(n) || t < 1 || t > n || n > MAX_SHARES) {
    throw new Error(`split: need 1 <= t <= n <= ${MAX_SHARES} (t=${t}, n=${n})`);
  }
  const coefficients = [secret];
  for (let i = 1; i < t; i++) {
    const c = random();
    if (c < 0n || c >= FIELD_P) throw new Error("split: random coefficient out of range");
    coefficients.push(c);
  }
  const shares: Share[] = [];
  for (let x = 1; x <= n; x++) {
    let y = 0n;
    for (let i = coefficients.length - 1; i >= 0; i--) y = (y * BigInt(x) + coefficients[i]!) % FIELD_P;
    shares.push({ index: x, value: y });
  }
  return shares;
}

/**
 * f(0) through the given points: the secret, when they are at least t shares
 * of one dealing. Same rules as `Shamir.combineAtZero`: indices in [1, P - 1]
 * and distinct, values below P.
 */
export function combine(shares: readonly Share[]): bigint {
  if (shares.length === 0) throw new Error("combine: no shares");
  const xs = shares.map((s) => BigInt(s.index));
  for (const [i, s] of shares.entries()) {
    if (!Number.isInteger(s.index) || xs[i]! <= 0n || xs[i]! >= FIELD_P) throw new Error(`combine: bad index ${s.index}`);
    if (s.value < 0n || s.value >= FIELD_P) throw new Error(`combine: value of share ${s.index} out of range`);
  }
  if (new Set(xs).size !== xs.length) throw new Error("combine: duplicate index");
  let num = 0n;
  let den = 1n;
  for (let i = 0; i < shares.length; i++) {
    let ni = 1n;
    let di = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (j === i) continue;
      ni = (ni * xs[j]!) % FIELD_P;
      di = (di * mod(xs[j]! - xs[i]!)) % FIELD_P;
    }
    num = (num * di + shares[i]!.value * ni % FIELD_P * den) % FIELD_P;
    den = (den * di) % FIELD_P;
  }
  return (num * fieldInverse(den)) % FIELD_P;
}

// ---------------------------------------------------------------------------
// The slot hashes (SealedSlot.sol)
// ---------------------------------------------------------------------------

export const KEY_DOMAIN = keccak256(toBytes("qore-pq-kit.SealedSlot.key.v1"));
export const SHARE_DOMAIN = keccak256(toBytes("qore-pq-kit.SealedSlot.share.v1"));
export const DEM_DOMAIN = keccak256(toBytes("qore-pq-kit.SealedSlot.dem.v1"));

/** What every hash of a slot binds: the EVM chain, the contract, the sender and the sender's counter. */
export interface SlotBinding {
  chainId: bigint;
  app: Address;
  sender: Address;
  seq: bigint;
}

const W = { type: "uint256" } as const;
const B32 = { type: "bytes32" } as const;
const ADDR = { type: "address" } as const;

function word(v: bigint): Hex {
  if (v < 0n || v >= 1n << 256n) throw new Error("value does not fit in a word");
  return `0x${v.toString(16).padStart(64, "0")}`;
}

export function keyHash(b: SlotBinding, key: bigint): Hex {
  return keccak256(encodeAbiParameters([B32, W, ADDR, ADDR, W, W], [KEY_DOMAIN, b.chainId, b.app, b.sender, b.seq, key]));
}

export function shareHash(b: SlotBinding, index: number, share: bigint): Hex {
  return keccak256(
    encodeAbiParameters([B32, W, ADDR, ADDR, W, W, W], [SHARE_DOMAIN, b.chainId, b.app, b.sender, b.seq, BigInt(index), share]),
  );
}

export function keystream(b: SlotBinding, key: bigint): Hex {
  return keccak256(encodeAbiParameters([B32, W, ADDR, ADDR, W, W], [DEM_DOMAIN, b.chainId, b.app, b.sender, b.seq, key]));
}

function xor32(a: Hex, b: Hex): Hex {
  return word(BigInt(a) ^ BigInt(b));
}

function asBlock(plaintext: Hex | Uint8Array): Hex {
  const bytes = typeof plaintext === "string" ? hexToBytes(plaintext) : plaintext;
  if (bytes.length !== 32) throw new Error(`a slot holds exactly 32 bytes (got ${bytes.length})`);
  return bytesToHex(bytes);
}

/** ct = plaintext XOR keystream(K). The same call decrypts (`SealedSlot.open`). */
export function xorSlot(b: SlotBinding, key: bigint, block: Hex | Uint8Array): Hex {
  return xor32(asBlock(block), keystream(b, key));
}

/** The AAD every share envelope is sealed under: abi.encode(app, sender, seq, index, shareHash). */
export function shareAad(b: SlotBinding, index: number, committedShareHash: Hex): Uint8Array {
  return hexToBytes(encodeAbiParameters([ADDR, ADDR, W, W, B32], [b.app, b.sender, b.seq, BigInt(index), committedShareHash]));
}

// ---------------------------------------------------------------------------
// Sealing and opening
// ---------------------------------------------------------------------------

export interface SealSlotArgs {
  binding: SlotBinding;
  /** Exactly 32 bytes. */
  plaintext: Hex | Uint8Array;
  /** Member j (1-based) is `committee[j - 1]`, already checked with `verifyMember`. */
  committee: readonly SealRecipient[];
  /** Shares needed to open, 1 <= t <= committee.length. */
  threshold: number;
  /** The QoreSeal (Cosmos) chain id, e.g. `qorechain-diana`. */
  sealChainId: string;
  /** The application's QoreSeal purpose, e.g. `peal-sealed-auction/share/v1`. */
  purpose: string;
  /** Default `hybrid` (ML-KEM-1024 + X25519). */
  mode?: SealMode;
  /** Test vectors only: the slot key and the polynomial's coefficients. */
  key?: bigint;
  random?: () => bigint;
}

export interface SealedSlotData {
  ct: Hex;
  keyHash: Hex;
  /** shareHashes[j - 1] commits to share j. */
  shareHashes: Hex[];
  /** envelopes[j - 1] is share j sealed to member j. */
  envelopes: Uint8Array[];
}

/** Encrypt one slot, deal its key t-of-n and seal each share to its member. */
export function sealSlot(a: SealSlotArgs): SealedSlotData {
  const n = a.committee.length;
  const random = a.random ?? randomFieldElement;
  const key = a.key ?? random();
  const shares = split(key, a.threshold, n, random);
  const shareHashes = shares.map((s) => shareHash(a.binding, s.index, s.value));
  const envelopes = shares.map((s, i) =>
    qoresealSeal({
      chainId: a.sealChainId,
      purpose: a.purpose,
      recipients: [a.committee[i]!],
      plaintext: hexToBytes(word(s.value)),
      aad: shareAad(a.binding, s.index, shareHashes[i]!),
      mode: a.mode ?? "hybrid",
    }),
  );
  return { ct: xorSlot(a.binding, key, a.plaintext), keyHash: keyHash(a.binding, key), shareHashes, envelopes };
}

export interface OpenShareArgs {
  envelope: Uint8Array;
  keys: SealKeyPair;
  binding: SlotBinding;
  /** This member's index (1-based). */
  index: number;
  /** The share hash the sender committed on chain for this index. */
  shareHash: Hex;
  sealChainId: string;
  purpose: string;
}

/**
 * Open a member's share and check it against the committed hash. Throws a
 * QoreSeal error if the envelope is not for these keys or was sealed under
 * another binding, and an Error if the share does not match its hash; a member
 * marks such a share invalid rather than posting it.
 */
export function openShare(a: OpenShareArgs): bigint {
  const pt = qoresealOpen({
    chainId: a.sealChainId,
    purpose: a.purpose,
    envelope: a.envelope,
    keys: a.keys,
    aad: shareAad(a.binding, a.index, a.shareHash),
  });
  if (pt.length !== 32) throw new Error(`share ${a.index}: expected 32 bytes, got ${pt.length}`);
  const value = BigInt(bytesToHex(pt));
  if (value >= FIELD_P) throw new Error(`share ${a.index}: value out of range`);
  if (shareHash(a.binding, a.index, value).toLowerCase() !== a.shareHash.toLowerCase()) {
    throw new Error(`share ${a.index}: does not match its committed hash`);
  }
  return value;
}

/** Recombine the slot key from opened shares, check it against keyHash and decrypt. */
export function openSlot(b: SlotBinding, shares: readonly Share[], committedKeyHash: Hex, ct: Hex): Hex {
  const key = combine(shares);
  if (keyHash(b, key).toLowerCase() !== committedKeyHash.toLowerCase()) {
    throw new Error("openSlot: recombined key does not match keyHash");
  }
  return xorSlot(b, key, ct);
}

// ---------------------------------------------------------------------------
// Checking a committee member before sealing to it
// ---------------------------------------------------------------------------

/** pqcKeyStatus at 0x…0A02, with the fourth output the SDK's ABI leaves out. */
const PQC_KEY_STATUS = "0x0000000000000000000000000000000000000a02" as Address;
const PQC_KEY_STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

/** SHA3-256 of an ML-KEM-1024 key, the form QoreSeal cards and registries commit to. */
export function kemKeySha3(mlkemPublicKey: Uint8Array): Hex {
  return bytesToHex(sha3_256(mlkemPublicKey));
}

/** keccak256 of the exact text a recipient card's owner signed. */
export function cardHash(card: RecipientCard): Hex {
  const { signature: _signature, version: _version, ...fields } = card;
  return keccak256(recipientCardSignBytes(fields));
}

/** The `qor1` form of an EVM address (same 20 bytes). */
export function qorAddress(evm: Address, prefix = "qor"): string {
  return bech32.encode(prefix, bech32.toWords(hexToBytes(getAddress(evm))));
}

/** The account's ML-DSA-87 key, read from the chain itself by `eth_call` (no REST, no proxy). */
export async function readPqKey(client: PublicClient, account: Address): Promise<Uint8Array> {
  const data = encodeFunctionData({ abi: PQC_KEY_STATUS_ABI, functionName: "pqcKeyStatus", args: [account] });
  const res = await client.call({ to: PQC_KEY_STATUS, data });
  if (!res.data || res.data === "0x") throw new Error("pqcKeyStatus answered with empty data (precompile inactive)");
  const [registered, algorithmId, pubkey, possessionProven] = decodeFunctionResult({
    abi: PQC_KEY_STATUS_ABI,
    functionName: "pqcKeyStatus",
    data: res.data,
  });
  const key = hexToBytes(pubkey);
  if (!registered || algorithmId !== 1 || !possessionProven || key.length !== 2592) {
    throw new Error(
      `${account} has no usable ML-DSA-87 key (registered=${registered}, algorithm=${algorithmId}, possession=${possessionProven}, length=${key.length})`,
    );
  }
  return key;
}

export interface VerifyMemberArgs {
  /** The member's EVM address, as the registry lists it. */
  address: Address;
  /** SHA3-256 of the member's ML-KEM key, as the member signed it into the registry. */
  expectKemSha3: Hex;
  card: RecipientCard;
  /** `cardHash(card)` as the member signed it into the registry. */
  expectCardHash: Hex;
  sealChainId: string;
  /** EVM RPC client: the ML-DSA key is read here. */
  client: PublicClient;
  /** REST base URL for the ML-KEM key; may be an untrusted proxy, because the key is checked against the hash. */
  rest: string;
  fetch?: typeof globalThis.fetch;
}

/**
 * Check a committee member's three bindings and return the recipient to seal to:
 * the ML-DSA key from the chain, the ML-KEM key from REST matching the hash the
 * member signed, and the card matching its hash and verifying against both keys.
 * A lying REST endpoint cannot substitute a key, because the registry's hashes
 * were signed by the member's ML-DSA key on chain.
 */
export async function verifyMember(a: VerifyMemberArgs): Promise<SealRecipient> {
  const qor = qorAddress(a.address);
  const pqPublicKey = await readPqKey(a.client, a.address);
  const kem = await fetchKemKey({ rest: a.rest, address: qor, ...(a.fetch ? { fetch: a.fetch } : {}) });
  if (!kem.registered || !kem.publicKey) throw new Error(`${qor} has no ML-KEM key registered`);
  if (kem.algorithmId !== undefined && kem.algorithmId !== 2) throw new Error(`${qor}: KEM algorithm ${kem.algorithmId} is not ML-KEM-1024`);
  validateMlkemPublicKey(kem.publicKey);
  if (kemKeySha3(kem.publicKey).toLowerCase() !== a.expectKemSha3.toLowerCase()) {
    throw new Error(`${qor}: the registered ML-KEM key does not match the committed hash`);
  }
  if (cardHash(a.card).toLowerCase() !== a.expectCardHash.toLowerCase()) {
    throw new Error(`${qor}: the recipient card does not match the committed hash`);
  }
  return verifyRecipientCard({ card: a.card, chainId: a.sealChainId, address: qor, pqPublicKey, mlkemPublicKey: kem.publicKey });
}
