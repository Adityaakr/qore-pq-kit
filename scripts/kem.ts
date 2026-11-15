/**
 * kem.ts - publish an account's ML-KEM-1024 key on chain and sign its QoreSeal
 * recipient card, so others can seal data to it (committee members of a sealed
 * auction, a Bidder agent receiving mandates).
 *
 * The seal keys are derived from the account's mnemonic (QoreSeal
 * `deriveSealKeys`, BIP-39 seed, `index` 0 by default), so they need no
 * separate backup. `MsgRegisterKEMKey` is hybrid-signed: QoreX cannot send it,
 * which is why this is a script. Registering again REPLACES the key, which
 * would break every registry entry and card that committed to the old one, so
 * `registerKem` refuses to replace a different key unless asked to.
 */
import { deriveSealKeys, signRecipientCard, type RecipientCard, type SealKeyPair } from "@qorechain/qoreseal";
import { classicalKeyFromPrivate } from "@qorechain/qoresign";
import { msg as sdkMsg, type UnifiedAccount } from "@qorechain/sdk";
import type { EncodeObject } from "@cosmjs/proto-signing";
import { hexToBytes, type Hex } from "viem";
import { broadcast, loadAccount, network } from "./qore.ts";
import { createRest } from "./rest.ts";
import { cardHash, kemKeySha3 } from "./threshold.ts";

/** The account's QoreSeal keys (ML-KEM-1024 + X25519), from its mnemonic. Secret: never print them. */
export function sealKeysOf(acc: UnifiedAccount, index = 0): SealKeyPair {
  if (!acc.mnemonic) throw new Error("this account was not derived from a mnemonic; cannot derive seal keys");
  return deriveSealKeys({ mnemonic: acc.mnemonic, index });
}

/** `MsgRegisterKEMKey { sender, algorithm_id: 2 (ML-KEM-1024), public_key }`. */
export function registerKemMsg(sender: string, mlkemPublicKey: Uint8Array): EncodeObject {
  if (mlkemPublicKey.length !== 1568) throw new Error(`an ML-KEM-1024 key is 1568 bytes (got ${mlkemPublicKey.length})`);
  return sdkMsg.pqc.registerKemKey({ sender, algorithmId: 2, publicKey: mlkemPublicKey });
}

export interface RegisterKemResult {
  action: "registered" | "already-registered" | "replaced";
  mlkemKeySha3: Hex;
  txHash?: string;
}

/** Publish the account's ML-KEM-1024 key. Idempotent; refuses to replace another key unless `replace`. */
export async function registerKem(name: string, opts: { index?: number; replace?: boolean } = {}): Promise<RegisterKemResult> {
  const net = network();
  const acc = await loadAccount(name);
  const keys = sealKeysOf(acc, opts.index ?? 0);
  const sha3 = kemKeySha3(keys.mlkemPublicKey);
  const current = await createRest({ base: net.rest }).kemKey(acc.cosmos);
  if (current.found && current.publicKey) {
    const onChain = kemKeySha3(current.publicKey);
    if (onChain === sha3) return { action: "already-registered", mlkemKeySha3: sha3 };
    if (!opts.replace) {
      throw new Error(`${acc.cosmos} already publishes a DIFFERENT ML-KEM key (sha3 ${onChain}); pass --replace to replace it`);
    }
  }
  const res = await broadcast(acc, [registerKemMsg(acc.cosmos, keys.mlkemPublicKey)]);
  return { action: current.found ? "replaced" : "registered", mlkemKeySha3: sha3, txHash: res.transactionHash };
}

/** The signed recipient card for the account's seal keys, with the two hashes a registry commits to. */
export function recipientCard(acc: UnifiedAccount, opts: { index?: number; issuedAt?: Date | string } = {}): {
  card: RecipientCard;
  cardHash: Hex;
  mlkemKeySha3: Hex;
} {
  const keys = sealKeysOf(acc, opts.index ?? 0);
  const card = signRecipientCard({
    chainId: network().chainId,
    address: acc.cosmos,
    keys,
    classicalKey: classicalKeyFromPrivate(hexToBytes(acc.privateKey as Hex), "eth_secp256k1"),
    pqKey: acc.pqc,
    ...(opts.issuedAt ? { issuedAt: opts.issuedAt } : {}),
  });
  return { card, cardHash: cardHash(card), mlkemKeySha3: kemKeySha3(keys.mlkemPublicKey) };
}
