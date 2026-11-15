/**
 * messaging.ts - authenticated, confidential instructions between QoreChain
 * accounts: signed with the sender's hybrid key (QoreSign, secp256k1 +
 * ML-DSA-87), sealed to the recipient's registered ML-KEM-1024 key (QoreSeal).
 *
 * Peal Bidder uses it for mandates: the owner signs and seals, the agent opens
 * and verifies against the owner's ML-DSA key *read from the chain*, and
 * refuses anything forged, altered, expired, replayed, for another chain, for
 * another recipient or for another purpose before acting on it.
 *
 * What is signed (`instructionBytes`) is one line of text then a JSON array of
 * the fields in a fixed order, so there is exactly one encoding:
 *
 *   qore-pq-kit instruction v1
 *   ["<chainId>","<from>","<to>","<purpose>","<nonce>","<issuedAt>","<expiresAt>","<body>"]
 *
 * The signature is a QoreSign message signature (the `qorechain-msg-v1|`
 * domain, so it cannot be mistaken for a transaction or a PqAuth message).
 * The envelope's AAD binds the recipient and the purpose, so an envelope
 * cannot be re-filed under another purpose without failing to open.
 *
 * Browser-safe.
 */
import { open as qoresealOpen, seal as qoresealSeal, type SealKeyPair, type SealRecipient } from "@qorechain/qoreseal";
import { signMessage, verifyMessage, type ClassicalKey, type MessageSignature, type PqKeyPair } from "@qorechain/qoresign";
import { bech32 } from "@scure/base";
import { bytesToHex, type Address, type PublicClient } from "viem";
import { readPqKey } from "./threshold.ts";

export const INSTRUCTION_HEADER = "qore-pq-kit instruction v1";
/** The QoreSeal purpose of every sealed instruction; the application's own purpose is in the AAD and the signed fields. */
export const SEAL_PURPOSE = "qore-pq-kit/instruction/v1";

export interface InstructionFields {
  /** Cosmos chain id, e.g. `qorechain-diana`. */
  chainId: string;
  /** Sender's `qor1` account. */
  from: string;
  /** Recipient's `qor1` account. */
  to: string;
  /** What the instruction is, e.g. `peal-bidder/mandate/v1`. */
  purpose: string;
  /** Unique per sender; the recipient refuses a nonce it has seen. */
  nonce: string;
  /** `YYYY-MM-DDTHH:MM:SSZ`. */
  issuedAt: string;
  /** `YYYY-MM-DDTHH:MM:SSZ`. */
  expiresAt: string;
  /** The payload: free text, usually canonical JSON. */
  body: string;
}

export interface SignedInstruction {
  version: 1;
  fields: InstructionFields;
  signature: MessageSignature;
}

const FIELD_ORDER = ["chainId", "from", "to", "purpose", "nonce", "issuedAt", "expiresAt", "body"] as const;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

/** The exact bytes the sender signs. */
export function instructionBytes(f: InstructionFields): Uint8Array {
  for (const k of FIELD_ORDER) {
    if (typeof f[k] !== "string") throw new Error(`instruction field ${k} must be a string`);
  }
  for (const k of ["issuedAt", "expiresAt"] as const) {
    if (!TIME.test(f[k]) || Number.isNaN(Date.parse(f[k]))) throw new Error(`instruction field ${k} must be YYYY-MM-DDTHH:MM:SSZ`);
  }
  return enc.encode(`${INSTRUCTION_HEADER}\n${JSON.stringify(FIELD_ORDER.map((k) => f[k]))}`);
}

/** `YYYY-MM-DDTHH:MM:SSZ` for a Date (seconds precision). */
export function isoSeconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** A fresh random nonce (128 bits, hex). */
export function randomNonce(): string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16))).slice(2);
}

/** The `0x` form of a `qor1` address. */
export function qorToEvm(qor: string): Address {
  const d = bech32.decode(qor.toLowerCase() as `${string}1${string}`);
  if (d.prefix !== "qor") throw new Error(`not a qor address: ${qor}`);
  return bytesToHex(bech32.fromWords(d.words)) as Address;
}

// ---------------------------------------------------------------------------
// Signing and verifying
// ---------------------------------------------------------------------------

/** Sign an instruction with the sender's classical and ML-DSA-87 keys. */
export function signInstruction(args: {
  fields: InstructionFields;
  classicalKey: ClassicalKey;
  pqKey: Pick<PqKeyPair, "secretKey">;
}): SignedInstruction {
  const data = instructionBytes(args.fields);
  const signature = signMessage({ chainId: args.fields.chainId, signer: args.fields.from, data, classicalKey: args.classicalKey, pqKey: args.pqKey });
  return { version: 1, fields: { ...args.fields }, signature };
}

export interface VerifyExpectations {
  chainId: string;
  /** The recipient doing the check: an instruction for anyone else is refused. */
  to: string;
  purpose: string;
  /** If set, only this sender is accepted. */
  from?: string;
  /** Default: the current time. */
  now?: Date;
  /** Clock skew allowed on `issuedAt`, seconds. Default 120. */
  skewSeconds?: number;
  /** Longest accepted lifetime (expiresAt - issuedAt), seconds. Default 7 days. */
  maxLifetimeSeconds?: number;
  /** Return true if (from, nonce) was already used: the instruction is then refused as a replay. */
  seen?: (from: string, nonce: string) => boolean;
}

export class InstructionRefused extends Error {
  constructor(readonly reason: string) {
    super(`instruction refused: ${reason}`);
    this.name = "InstructionRefused";
  }
}

function checkFields(s: SignedInstruction, e: VerifyExpectations): void {
  const f = s.fields;
  if (s.version !== 1) throw new InstructionRefused(`unsupported version ${String(s.version)}`);
  if (f.chainId !== e.chainId) throw new InstructionRefused(`for chain ${f.chainId}, not ${e.chainId}`);
  if (f.to.toLowerCase() !== e.to.toLowerCase()) throw new InstructionRefused(`addressed to ${f.to}, not ${e.to}`);
  if (f.purpose !== e.purpose) throw new InstructionRefused(`purpose ${f.purpose}, not ${e.purpose}`);
  if (e.from && f.from.toLowerCase() !== e.from.toLowerCase()) throw new InstructionRefused(`from ${f.from}, not ${e.from}`);
  try {
    instructionBytes(f);
  } catch (err) {
    throw new InstructionRefused((err as Error).message);
  }
  const now = (e.now ?? new Date()).getTime();
  const issued = Date.parse(f.issuedAt);
  const expires = Date.parse(f.expiresAt);
  if (issued > now + (e.skewSeconds ?? 120) * 1000) throw new InstructionRefused(`issued in the future (${f.issuedAt})`);
  if (now >= expires) throw new InstructionRefused(`expired at ${f.expiresAt}`);
  if (expires <= issued) throw new InstructionRefused("expires before it is issued");
  if (expires - issued > (e.maxLifetimeSeconds ?? 7 * 86400) * 1000) throw new InstructionRefused("lifetime too long");
  if (e.seen?.(f.from, f.nonce)) throw new InstructionRefused(`nonce ${f.nonce} already used`);
}

/**
 * Check an instruction against what the recipient expects and against the
 * sender's ML-DSA-87 key. Both signature halves must verify (`requirePq`).
 * Returns the fields; throws `InstructionRefused` otherwise. The caller marks
 * the nonce used after acting.
 */
export function verifyInstruction(s: SignedInstruction, pqPublicKey: Uint8Array, e: VerifyExpectations): InstructionFields {
  checkFields(s, e);
  try {
    verifyMessage({ chainId: s.fields.chainId, signer: s.fields.from, data: instructionBytes(s.fields), signature: s.signature, pqPublicKey, requirePq: true });
  } catch (err) {
    throw new InstructionRefused(`bad signature: ${(err as Error).message}`);
  }
  return { ...s.fields };
}

/** `verifyInstruction` with the sender's ML-DSA-87 key read from the chain (`eth_call` to pqcKeyStatus). */
export async function verifyInstructionWithChain(s: SignedInstruction, client: PublicClient, e: VerifyExpectations): Promise<InstructionFields> {
  checkFields(s, e); // refuse cheaply before any network call
  let key: Uint8Array;
  try {
    key = await readPqKey(client, qorToEvm(s.fields.from));
  } catch (err) {
    throw new InstructionRefused(`sender key: ${(err as Error).message}`);
  }
  return verifyInstruction(s, key, e);
}

// ---------------------------------------------------------------------------
// Sealing and opening
// ---------------------------------------------------------------------------

function aad(to: string, purpose: string): Uint8Array {
  return enc.encode(`${SEAL_PURPOSE}|${to.toLowerCase()}|${purpose}`);
}

/** Seal a signed instruction to its recipient (ML-KEM-1024 + X25519 by default). */
export function sealInstruction(s: SignedInstruction, recipient: SealRecipient, mode: "hybrid" | "mlkem" = "hybrid"): Uint8Array {
  return qoresealSeal({
    chainId: s.fields.chainId,
    purpose: SEAL_PURPOSE,
    recipients: [recipient],
    plaintext: enc.encode(JSON.stringify(s)),
    aad: aad(s.fields.to, s.fields.purpose),
    mode,
  });
}

/**
 * Open a sealed instruction with the recipient's keys. Returns it UNVERIFIED:
 * pass the result to `verifyInstruction` or `verifyInstructionWithChain`
 * before acting on it.
 */
export function openInstruction(args: { envelope: Uint8Array; keys: SealKeyPair; chainId: string; to: string; purpose: string }): SignedInstruction {
  const pt = qoresealOpen({ chainId: args.chainId, purpose: SEAL_PURPOSE, envelope: args.envelope, keys: args.keys, aad: aad(args.to, args.purpose) });
  let parsed: unknown;
  try {
    parsed = JSON.parse(dec.decode(pt));
  } catch {
    throw new InstructionRefused("sealed payload is not a JSON instruction");
  }
  const s = parsed as SignedInstruction;
  if (!s || typeof s !== "object" || !s.fields || !s.signature) throw new InstructionRefused("sealed payload is not an instruction");
  return s;
}

/** Open and verify in one step, against the sender's key on chain. */
export async function receiveInstruction(args: {
  envelope: Uint8Array;
  keys: SealKeyPair;
  client: PublicClient;
  expect: VerifyExpectations;
}): Promise<InstructionFields> {
  const s = openInstruction({ envelope: args.envelope, keys: args.keys, chainId: args.expect.chainId, to: args.expect.to, purpose: args.expect.purpose });
  return verifyInstructionWithChain(s, args.client, args.expect);
}
