/** Test-only members: fixed seeds, so failures are reproducible. Never use these keys on a network. */
import { sealKeysFromSeed, signRecipientCard, type RecipientCard, type SealKeyPair } from "@qorechain/qoreseal";
import { addressFromPublicKey, classicalKeyFromPrivate, pqKeyFromSeed, type ClassicalKey, type PqKeyPair } from "@qorechain/qoresign";
import { keccak256, toBytes, type Address } from "viem";

export const SEAL_CHAIN_ID = "qorechain-diana";
export const PURPOSE = "qore-pq-kit/test/share/v1";

export interface TestMember {
  evm: Address;
  qor: string;
  classical: ClassicalKey;
  pq: PqKeyPair;
  seal: SealKeyPair;
  card: RecipientCard;
}

function seed(label: string): Uint8Array {
  return toBytes(keccak256(toBytes(label)));
}

export function testMember(i: number): TestMember {
  const classical = classicalKeyFromPrivate(seed(`qore-pq-kit/test/classical/${i}`), "eth_secp256k1");
  const addr = addressFromPublicKey(classical.publicKey, "eth_secp256k1");
  const pq = pqKeyFromSeed(seed(`qore-pq-kit/test/mldsa/${i}`));
  const seal = sealKeysFromSeed(seed(`qore-pq-kit/test/seal/${i}`));
  const card = signRecipientCard({
    chainId: SEAL_CHAIN_ID,
    address: addr.bech32,
    keys: seal,
    classicalKey: classical,
    pqKey: pq,
    issuedAt: "2026-11-16T00:00:00Z",
  });
  return { evm: addr.hex as Address, qor: addr.bech32, classical, pq, seal, card };
}
