/**
 * spikes/s1-s3.ts - spikes S1 (what pqcKeyStatus's fourth word means) and S3
 * (a live ML-KEM-1024 registration, and threshold.ts verifyMember against the
 * real chain), with the throwaway spike accounts from accounts.ts.
 *
 *   npx tsx scripts/spikes/s1-s3.ts
 *
 * Every step reads the chain first and skips itself when already done, so a
 * re-run costs nothing extra. Prints addresses, tx hashes and public data only.
 *
 *   1. bank registers its ML-DSA-87 key WITH a proof of possession.
 *   2. bank sends 1 QOR to s1.
 *   3. s1 registers its ML-DSA-87 key WITHOUT a proof of possession
 *      (allowed "not required yet" per the SDK's MsgRegisterPQCKeyV2 docs).
 *   After each registration: REST `possession_proven` next to the fourth word
 *   of `pqcKeyStatus` read by eth_call.
 *   4. bank registers an ML-KEM-1024 key (hybrid-signed MsgRegisterKEMKey),
 *      signs a QoreSeal recipient card, and runs verifyMember live.
 */
import { deriveSealKeys, signRecipientCard } from "@qorechain/qoreseal";
import { classicalKeyFromPrivate } from "@qorechain/qoresign";
import {
  buildRegisterPqcKeyMsg,
  msg as sdkMsg,
  signProofOfPossession,
  verifyProofOfPossession,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { createPublicClient, decodeFunctionResult, encodeFunctionData, hexToBytes, http, type Address, type Hex } from "viem";
import { broadcast, network } from "../qore.ts";
import { createRest } from "../rest.ts";
import { cardHash, kemKeySha3, verifyMember } from "../threshold.ts";
import { loadSpikeAccount } from "./accounts.ts";

const net = network();
const rest = createRest({ base: net.rest });
const client = createPublicClient({ transport: http(net.evmRpc) });

const KEY_STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ type: "address" }],
    outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }],
  },
] as const;

async function keyStatus(evm: string) {
  const res = await client.call({
    to: "0x0000000000000000000000000000000000000a02",
    data: encodeFunctionData({ abi: KEY_STATUS_ABI, functionName: "pqcKeyStatus", args: [evm as Address] }),
  });
  const [registered, alg, key, fourth] = decodeFunctionResult({ abi: KEY_STATUS_ABI, functionName: "pqcKeyStatus", data: res.data! });
  return { registered, alg, keyBytes: (key.length - 2) / 2, fourth };
}

async function report(label: string, acc: UnifiedAccount) {
  const r = await rest.pqcAccount(acc.cosmos);
  const k = await keyStatus(acc.evm);
  console.log(
    `  ${label}: REST found=${r.found} algorithm=${r.algorithmId ?? "-"} key_type=${r.keyType ?? "-"} possession_proven=${r.possessionProven ?? "-"}` +
      ` | pqcKeyStatus registered=${k.registered} algorithm=${k.alg} keyBytes=${k.keyBytes} fourthWord=${k.fourth}`,
  );
  return { rest: r, chain: k };
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, tries = 20): Promise<T> {
  for (let i = 0; i < tries; i++) {
    const v = await f();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function balance(addr: string): Promise<bigint> {
  return (await rest.balances(addr)).uqor ?? 0n;
}

async function registerPq(acc: UnifiedAccount, withProof: boolean): Promise<void> {
  const before = await rest.pqcAccount(acc.cosmos);
  if (before.found) {
    console.log(`  ${acc.cosmos} already has a PQC key; skipping registration`);
    return;
  }
  let msg;
  if (withProof) {
    const proofOfPossession = signProofOfPossession({ chainId: net.chainId, account: acc.cosmos, keypair: acc.pqc });
    if (!verifyProofOfPossession({ chainId: net.chainId, account: acc.cosmos, publicKey: acc.pqc.publicKey, proof: proofOfPossession })) {
      throw new Error("proof of possession does not verify locally");
    }
    msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession });
  } else {
    msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc });
  }
  const b0 = await balance(acc.cosmos);
  try {
    const res = await broadcast(acc, [msg], "classical");
    console.log(`  registered (${withProof ? "with" : "WITHOUT"} proof of possession): tx ${res.transactionHash}`);
  } catch (e) {
    console.log(`  registration (${withProof ? "with" : "without"} proof) REFUSED: ${(e as Error).message.slice(0, 300)}`);
  }
  await new Promise((r) => setTimeout(r, 6000));
  console.log(`  fee charged: ${b0 - (await balance(acc.cosmos))} uqor`);
}

async function main(): Promise<void> {
  const bank = await loadSpikeAccount("bank");
  const s1 = await loadSpikeAccount("s1");
  console.log(`chain ${net.chainId}, bank ${bank.cosmos} (${await balance(bank.cosmos)} uqor), s1 ${s1.cosmos}`);

  console.log("S1 step 1: bank registers with a proof of possession");
  await registerPq(bank, true);
  await waitFor("bank key on REST", async () => ((await rest.pqcAccount(bank.cosmos)).found ? true : undefined));
  await report("bank", bank);

  console.log("S1 step 2: fund s1 with 1 QOR (hybrid-signed send)");
  if ((await balance(s1.cosmos)) === 0n) {
    const res = await broadcast(bank, [
      { typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: bank.cosmos, toAddress: s1.cosmos, amount: [{ denom: "uqor", amount: "1000000" }] } },
    ]);
    console.log(`  sent: tx ${res.transactionHash}`);
    await waitFor("s1 funds", async () => ((await balance(s1.cosmos)) > 0n ? true : undefined));
  } else {
    console.log("  s1 already funded; skipping");
  }

  console.log("S1 step 3: s1 registers WITHOUT a proof of possession");
  await registerPq(s1, false);
  await report("s1", s1);

  console.log("S3: bank registers an ML-KEM-1024 key, signs a card, and verifyMember runs against the live chain");
  const sealKeys = deriveSealKeys({ mnemonic: bank.mnemonic!, index: 0 });
  const kem = await rest.kemKey(bank.cosmos);
  if (!kem.found) {
    const b0 = await balance(bank.cosmos);
    const m = sdkMsg.pqc.registerKemKey({ sender: bank.cosmos, algorithmId: 2, publicKey: sealKeys.mlkemPublicKey });
    const res = await broadcast(bank, [m]);
    console.log(`  MsgRegisterKEMKey: tx ${res.transactionHash}`);
    await waitFor("KEM key on REST", async () => ((await rest.kemKey(bank.cosmos)).found ? true : undefined));
    console.log(`  fee charged: ${b0 - (await balance(bank.cosmos))} uqor`);
  } else {
    console.log("  bank already has a KEM key; skipping registration");
  }
  const onChain = await rest.kemKey(bank.cosmos);
  console.log(
    `  REST kem: algorithm=${onChain.algorithmId} bytes=${onChain.publicKey?.length} height=${onChain.registeredHeight} sha3 matches local key: ${
      kemKeySha3(onChain.publicKey!) === kemKeySha3(sealKeys.mlkemPublicKey)
    }`,
  );
  const card = signRecipientCard({
    chainId: net.chainId,
    address: bank.cosmos,
    keys: sealKeys,
    classicalKey: classicalKeyFromPrivate(hexToBytes(bank.privateKey as Hex), "eth_secp256k1"),
    pqKey: bank.pqc,
  });
  const recipient = await verifyMember({
    address: bank.evm as Address,
    expectKemSha3: kemKeySha3(sealKeys.mlkemPublicKey),
    card,
    expectCardHash: cardHash(card),
    sealChainId: net.chainId,
    client: client as never,
    rest: net.rest,
  });
  console.log(`  verifyMember against the live chain: OK (x25519 ${Buffer.from(recipient.x25519PublicKey!).toString("hex").slice(0, 16)}...)`);
  console.log(`bank left: ${await balance(bank.cosmos)} uqor; s1 left: ${await balance(s1.cosmos)} uqor`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
