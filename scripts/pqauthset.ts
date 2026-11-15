/**
 * pqauthset.ts - build and sign the messages `PqAuthSet.sol` verifies.
 *
 * A quorum share is an ordinary PqAuth message (see pqauth.ts) whose action is
 * folded under the set's own domain, and whose signer is the member:
 *
 *   quorumAction(a) = keccak256(abi.encode(keccak256("qore-pq-kit.PqAuthSet.quorum.v1"), a))
 *   anyAction(a)    = keccak256(abi.encode(keccak256("qore-pq-kit.PqAuthSet.any.v1"), a))
 *   share           = ML-DSA-87 signature over authMessage({ ..., signer: member, action: quorumAction(a), nonce: set nonce })
 *
 * The contract wants the signers in strictly ascending address order;
 * `orderShares` sorts them.
 *
 * Browser-safe and light: it builds the PqAuth message itself (the same bytes
 * as `pqauth.ts` `authMessage`, checked by a test and by vectors/pqauthset.json)
 * and signs with QoreSign, so it does not pull in the whole QoreChain SDK.
 */
import { pqSign, pqVerify } from "@qorechain/qoresign";
import { encodeAbiParameters, hexToBytes, keccak256, toBytes, toHex, type Address, type Hex } from "viem";

export const PQ_AUTH_DOMAIN = keccak256(toBytes("qore-pq-kit.PqAuth.v1"));

/** The fields of a PqAuth message (as in pqauth.ts). */
export interface AuthFields {
  chainId: bigint;
  verifier: Address;
  signer: Address;
  action: Hex;
  nonce: bigint;
  deadline: bigint;
  argsHash: Hex;
}

/** Any ML-DSA-87 key pair: the SDK's `PqcKeypair` and QoreSign's `PqKeyPair` both fit. */
export interface MlDsaKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** abi.encode(DOMAIN, chainId, verifier, signer, action, nonce, deadline, argsHash): 256 bytes. */
export function authMessage(f: AuthFields): Hex {
  return encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "uint256" },
      { type: "address" },
      { type: "address" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "bytes32" },
    ],
    [PQ_AUTH_DOMAIN, f.chainId, f.verifier, f.signer, f.action, f.nonce, f.deadline, f.argsHash],
  );
}

function signAuth(keypair: MlDsaKeypair, f: AuthFields): Hex {
  const m = hexToBytes(authMessage(f));
  const sig = pqSign(keypair.secretKey, m);
  if (!pqVerify(keypair.publicKey, m, sig)) throw new Error("local ML-DSA-87 verification failed");
  return toHex(sig);
}

export const QUORUM_DOMAIN = keccak256(toBytes("qore-pq-kit.PqAuthSet.quorum.v1"));
export const ANY_DOMAIN = keccak256(toBytes("qore-pq-kit.PqAuthSet.any.v1"));

export function quorumAction(action: Hex): Hex {
  return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [QUORUM_DOMAIN, action]));
}

export function anyAction(action: Hex): Hex {
  return keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [ANY_DOMAIN, action]));
}

/** What a set action binds; `action` is the plain action id (e.g. actionId("PealTender.sweep")). */
export type SetFields = Omit<AuthFields, "signer">;

/** The 256 bytes `member` signs as its share of a quorum for `f.action`. */
export function quorumMessage(f: SetFields, member: Address): Hex {
  return authMessage({ ...f, signer: member, action: quorumAction(f.action) });
}

/** The 256 bytes `member` signs to act alone through `authorizeAny`. */
export function anyMessage(f: SetFields, member: Address): Hex {
  return authMessage({ ...f, signer: member, action: anyAction(f.action) });
}

export interface Share {
  signer: Address;
  signature: Hex;
}

/** Sign one member's quorum share (and check it locally). */
export function signQuorumShare(keypair: MlDsaKeypair, member: Address, f: SetFields): Share {
  return { signer: member, signature: signAuth(keypair, { ...f, signer: member, action: quorumAction(f.action) }) };
}

/** Sign a single-member action for `authorizeAny`. */
export function signAnyAction(keypair: MlDsaKeypair, member: Address, f: SetFields): Share {
  return { signer: member, signature: signAuth(keypair, { ...f, signer: member, action: anyAction(f.action) }) };
}

/** Sort shares into the strictly ascending signer order the contract requires; refuses duplicates. */
export function orderShares(shares: readonly Share[]): { signers: Address[]; signatures: Hex[] } {
  const sorted = [...shares].sort((a, b) => (BigInt(a.signer) < BigInt(b.signer) ? -1 : BigInt(a.signer) > BigInt(b.signer) ? 1 : 0));
  for (let i = 1; i < sorted.length; i++) {
    if (BigInt(sorted[i]!.signer) === BigInt(sorted[i - 1]!.signer)) throw new Error(`duplicate signer ${sorted[i]!.signer}`);
  }
  return { signers: sorted.map((s) => s.signer), signatures: sorted.map((s) => s.signature) };
}
