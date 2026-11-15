/**
 * spikes/s2.ts - spike S2: does `MsgExecuteEVM` with a linked key and a
 * spending rule work end to end on qorechain-diana, and does it need the
 * owner account's EVM window?
 *
 *   forge build && npx tsx scripts/spikes/s2.ts
 *
 * Throwaway accounts only (accounts.ts): bank funds s2-owner and s2-relay;
 * s2-agent's secp256k1 key is linked to s2-owner by its 20-byte address
 * (the MetaMask-style link, EIP-191 signatures) with a spending rule that
 * allowlists one function of a throwaway target contract. The relayer then
 * broadcasts MsgExecuteEVM calls the agent signed:
 *
 *   A. the allowlisted function, value 0, with NO window open on the owner
 *   B. the allowlisted function with a value above the per-execution limit
 *   C. a function that is not allowlisted
 *   D. A's exact message again (replay)
 *   (E. A again inside a scoped owner window, only if A failed for want of one)
 *
 * The agent side uses scripts/smart-account.ts. Every step reads chain state
 * first and skips itself when done. Prints
 * addresses, tx hashes and outcomes only.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildRegisterPqcKeyMsg,
  closeEvmWindowMsg,
  fetchAuthNonce,
  openEvmWindowMsg,
  resolveEvmAuthDigestVersion,
  signProofOfPossession,
  type UnifiedAccount,
} from "@qorechain/sdk";
import type { EncodeObject } from "@cosmjs/proto-signing";
import { encodeFunctionData, hexToBytes, type Address, type Hex } from "viem";
import { broadcast, network, publicClient } from "../qore.ts";
import { sendEvm } from "../evm.ts";
import { createRest } from "../rest.ts";
import { agentLinkProof, buildAgentCall, linkAgentMsgs, relay } from "../smart-account.ts";
import { loadSpikeAccount } from "./accounts.ts";

const net = network();
const rest = createRest({ base: net.rest });
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TARGET_ABI = [
  { type: "function", name: "commitBid", stateMutability: "payable", inputs: [{ type: "uint256" }], outputs: [] },
  { type: "function", name: "other", stateMutability: "nonpayable", inputs: [{ type: "uint256" }], outputs: [] },
  { type: "function", name: "commits", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
] as const;
const COMMIT_SELECTOR = encodeFunctionData({ abi: TARGET_ABI, functionName: "commitBid", args: [0n] }).slice(0, 10);
/** Spending rule amounts, in uqor (the native denom's base unit). */
const PER_TX_LIMIT_UQOR = 1000n; // 0.001 QOR
const DAILY_LIMIT_UQOR = 5000n;
const STATE_FILE = join(process.env.HOME ?? "", ".qore-pq-kit", "spikes", "s2-state.json");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const uqor = async (a: string) => (await rest.balances(a)).uqor ?? 0n;

function loadState(): { target?: Address } {
  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf8"));
  } catch {
    return {};
  }
}

async function fund(bank: UnifiedAccount, to: UnifiedAccount, amount: bigint) {
  if ((await uqor(to.cosmos)) > 0n) return console.log(`  ${to.cosmos} already funded`);
  const res = await broadcast(bank, [
    { typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: bank.cosmos, toAddress: to.cosmos, amount: [{ denom: "uqor", amount: amount.toString() }] } },
  ]);
  console.log(`  funded ${to.cosmos} with ${amount} uqor: tx ${res.transactionHash}`);
  for (let i = 0; i < 20 && (await uqor(to.cosmos)) === 0n; i++) await sleep(3000);
}

async function registerWithProof(acc: UnifiedAccount) {
  if ((await rest.pqcAccount(acc.cosmos)).found) return console.log(`  ${acc.cosmos} already registered`);
  const proofOfPossession = signProofOfPossession({ chainId: net.chainId, account: acc.cosmos, keypair: acc.pqc });
  const res = await broadcast(acc, [buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession })], "classical");
  console.log(`  registered ML-DSA key of ${acc.cosmos}: tx ${res.transactionHash}`);
  for (let i = 0; i < 20 && !(await rest.pqcAccount(acc.cosmos)).found; i++) await sleep(3000);
}

async function deployTarget(owner: UnifiedAccount): Promise<Address> {
  const st = loadState();
  if (st.target && (await publicClient().getCode({ address: st.target }))) {
    console.log(`  target already deployed at ${st.target}`);
    return st.target;
  }
  const art = JSON.parse(readFileSync(join(root, "out/SpikeTarget.sol/SpikeTarget.json"), "utf8"));
  const open = openEvmWindowMsg({ sender: owner.cosmos, blocks: 120, maxTxs: 1, maxValue: 200_000n }); // uqor: 0.2 QOR cap on value + max fees
  const o = await broadcast(owner, [open]);
  console.log(`  opened an unscoped window on the owner for the deploy: tx ${o.transactionHash}`);
  await sleep(6000);
  const receipt = await sendEvm(owner, { data: art.bytecode.object as Hex });
  const target = receipt.contractAddress as Address;
  console.log(`  deployed SpikeTarget at ${target}: EVM tx ${receipt.transactionHash}, gas ${receipt.gasUsed}`);
  const c = await broadcast(owner, [closeEvmWindowMsg(owner.cosmos)]);
  console.log(`  closed the owner's window: tx ${c.transactionHash}`);
  const { mkdirSync, writeFileSync } = await import("node:fs");
  mkdirSync(dirname(STATE_FILE), { recursive: true, mode: 0o700 });
  writeFileSync(STATE_FILE, JSON.stringify({ target }), { mode: 0o600 });
  return target;
}

async function link(owner: UnifiedAccount, agent: UnifiedAccount, target: Address) {
  const existing = await rest.abstractAccount(owner.cosmos, "authenticators");
  if (existing && JSON.stringify(existing).toLowerCase().includes(agent.evm.slice(2).toLowerCase())) {
    return console.log("  agent key already linked");
  }
  const proof = agentLinkProof({ chainId: net.chainId, owner: owner.cosmos, agentPrivateKey: agent.privateKey as Hex });
  const msgs = linkAgentMsgs({
    chainId: net.chainId,
    owner: owner.cosmos,
    proof,
    expiryUnix: BigInt(Math.floor(Date.now() / 1000) + 3 * 86400),
    label: "qore-pq-kit spike S2 agent",
    rule: {
      id: "s2-agent",
      perTxLimit: PER_TX_LIMIT_UQOR,
      dailyLimit: DAILY_LIMIT_UQOR,
      allowedEvmCalls: [{ target, selector: COMMIT_SELECTOR as Hex }],
    },
  });
  console.log(`  link messages: ${msgs.map((m) => m.typeUrl).join(", ")}`);
  const res = await broadcast(owner, msgs);
  console.log(`  linked agent ${agent.evm} to ${owner.cosmos}: tx ${res.transactionHash}`);
  await sleep(6000);
}

async function execute(label: string, relayer: UnifiedAccount, msg: EncodeObject): Promise<{ ok: boolean; hash?: string }> {
  const out = await relay(relayer, [msg]);
  if (!out.delivered) {
    console.log(`  ${label}: REFUSED ${out.error?.slice(0, 400)}`);
    return { ok: false };
  }
  const r = out.results[0];
  console.log(
    `  ${label}: tx ${out.txHash} code 0 -> success=${r?.success} gasUsed=${r?.gasUsed} ${r?.success ? "" : `reason="${r?.reason}"`}`,
  );
  return { ok: r?.success === true, hash: out.txHash };
}

async function main(): Promise<void> {
  const [bank, owner, agent, relayAcc] = await Promise.all(["bank", "s2-owner", "s2-agent", "s2-relay"].map(loadSpikeAccount));
  console.log(`owner ${owner.cosmos} ${owner.evm}\nagent ${agent.evm} (key linked by address)\nrelay ${relayAcc.cosmos}`);
  console.log(`bank ${await uqor(bank.cosmos)} uqor`);

  console.log("setup: fund, register, deploy, link");
  await fund(bank, owner, 2_500_000n);
  await fund(bank, relayAcc, 2_000_000n);
  await registerWithProof(owner);
  await registerWithProof(relayAcc);
  const target = await deployTarget(owner);
  await link(owner, agent, target);
  console.log(`  authenticators: ${JSON.stringify(await rest.abstractAccount(owner.cosmos, "authenticators")).slice(0, 600)}`);
  console.log(`  spending rules: ${JSON.stringify(await rest.abstractAccount(owner.cosmos, "spending_rules")).slice(0, 600)}`);

  const digestVersion = await resolveEvmAuthDigestVersion({ rest: net.rest });
  const pubkey = hexToBytes(agent.evm as Hex);
  const nonceOf = async () => (await fetchAuthNonce({ rest: net.rest, address: owner.cosmos, pubkey })).nonce;
  const w = await rest.evmWindow(owner.cosmos);
  console.log(`digest ${digestVersion}; owner window found=${w.found} live=${w.live}; agent nonce ${await nonceOf()}`);

  const build = async (fn: "commitBid" | "other", value: bigint) =>
    buildAgentCall({
      rest: net.rest,
      chainId: net.chainId,
      owner: owner.cosmos,
      relayer: relayAcc.cosmos,
      agentPrivateKey: agent.privateKey as Hex,
      to: target,
      value,
      data: encodeFunctionData({ abi: TARGET_ABI, functionName: fn, args: [7n] }),
      gasLimit: 200_000,
      digestVersion,
    });

  console.log("A. allowlisted call, value 0, no owner window");
  const msgA = await build("commitBid", 0n);
  const a = await execute("A", relayAcc, msgA);
  console.log(`  nonce now ${await nonceOf()}; commits(owner) = ${await publicClient().readContract({ address: target, abi: TARGET_ABI, functionName: "commits", args: [owner.evm as Address] })}`);

  console.log(`B. allowlisted call with value 0.01 QOR (above the ${PER_TX_LIMIT_UQOR} uqor per-execution limit)`);
  await execute("B", relayAcc, await build("commitBid", 10_000_000_000_000_000n));
  console.log(`  nonce now ${await nonceOf()}`);

  console.log("C. call to a function that is not allowlisted");
  await execute("C", relayAcc, await build("other", 0n));
  console.log(`  nonce now ${await nonceOf()}`);

  console.log("D. replay of A's exact message");
  await execute("D", relayAcc, msgA);
  console.log(`  nonce now ${await nonceOf()}`);

  if (!a.ok) {
    console.log("E. A failed: retry inside a window on the owner scoped to the target");
    const o = await broadcast(owner, [openEvmWindowMsg({ sender: owner.cosmos, blocks: 120, maxTxs: 2, maxValue: 100_000n, allowedTargets: [target.toLowerCase()] })]);
    console.log(`  opened scoped owner window: tx ${o.transactionHash}`);
    await sleep(6000);
    await execute("E", relayAcc, await build("commitBid", 0n));
    const c = await broadcast(owner, [closeEvmWindowMsg(owner.cosmos)]);
    console.log(`  closed: tx ${c.transactionHash}`);
  }
  console.log(`commits(owner) = ${await publicClient().readContract({ address: target, abi: TARGET_ABI, functionName: "commits", args: [owner.evm as Address] })}`);
  console.log(`balances: bank ${await uqor(bank.cosmos)}, owner ${await uqor(owner.cosmos)}, relay ${await uqor(relayAcc.cosmos)} uqor`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
