/**
 * register.ts - bind the account's ML-DSA-87 key on chain, with a proof of possession.
 *
 * `MsgRegisterPQCKeyV2` is the one message the chain accepts signed classically:
 * before it there is no post-quantum key on record to check a second signature
 * against. Once a key is bound, every native transaction needs both signatures.
 *
 * The chain refuses a second registration but STILL CHARGES ITS FEE, so this
 * reads the account first and never registers blind.
 */
import {
  buildRegisterPqcKeyMsg,
  fetchPqcStatus,
  isRegisteredPqcKey,
  signProofOfPossession,
  verifyProofOfPossession,
} from "@qorechain/sdk";
import { broadcast, loadAccount, network } from "./qore.ts";

export async function register(name = "drill"): Promise<void> {
  const net = network();
  const acc = await loadAccount(name);
  const before = await fetchPqcStatus({ rest: net.rest, address: acc.cosmos });
  if (before.registered) {
    const mine = isRegisteredPqcKey(before, acc.pqc.publicKey);
    if (mine === false) throw new Error(`${acc.cosmos} already has a DIFFERENT PQC key registered; not sending`);
    console.log(`${acc.cosmos} already has this ML-DSA-87 key registered; nothing to do`);
    return;
  }
  const proofOfPossession = signProofOfPossession({ chainId: net.chainId, account: acc.cosmos, keypair: acc.pqc });
  const ok = verifyProofOfPossession({
    chainId: net.chainId,
    account: acc.cosmos,
    publicKey: acc.pqc.publicKey,
    proof: proofOfPossession,
  });
  if (!ok) throw new Error("the proof of possession does not verify locally; not sending");
  const msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession });
  const res = await broadcast(acc, [msg], "classical");
  console.log(`registered ML-DSA-87 key for ${acc.cosmos}: tx ${res.transactionHash}`);
}
