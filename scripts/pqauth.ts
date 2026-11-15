/**
 * pqauth.ts - build and sign the messages `PqAuth.sol` verifies.
 *
 *   message = abi.encode(DOMAIN, chainId, verifier, signer, action, nonce, deadline, argsHash)
 *   DOMAIN  = keccak256("qore-pq-kit.PqAuth.v1")
 *
 * Every field is one 32-byte word, so the message is exactly 256 bytes. The
 * signature is a plain ML-DSA-87 signature (4,627 bytes) by the signer
 * account's registered key, as `pqcVerify` (0x…0A01) checks it.
 */
import { pqcSign, pqcVerify, type PqcKeypair } from "@qorechain/sdk";
import { encodeAbiParameters, keccak256, toBytes, toHex, type Address, type Hex } from "viem";

export const PQ_AUTH_DOMAIN = keccak256(toBytes("qore-pq-kit.PqAuth.v1"));

/** keccak256 of an action name, e.g. actionId("PealTender.sweep"). */
export function actionId(name: string): Hex {
  return keccak256(toBytes(name));
}

export interface AuthFields {
  chainId: bigint;
  verifier: Address;
  signer: Address;
  action: Hex;
  nonce: bigint;
  deadline: bigint;
  argsHash: Hex;
}

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

/** Sign an authorisation with the ML-DSA-87 key, and check it locally before returning. */
export function signAuth(keypair: PqcKeypair, f: AuthFields): Hex {
  const m = toBytes(authMessage(f));
  const sig = pqcSign(keypair.secretKey, m);
  if (!pqcVerify(keypair.publicKey, m, sig)) throw new Error("local ML-DSA-87 verification failed");
  return toHex(sig);
}
