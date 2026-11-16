/**
 * spikes/s2-fusd.ts - the fUSD part of spike S2: do a spending rule's
 * per-denom limits (`denomLimits` on `erc20/<fUSD>`) bound a linked agent key's
 * ERC-20 outflow, including allowance changes?
 *
 *   QORE_SECRETS_DIR=~/.qore-pq-kit/spikes npx tsx scripts/spikes/s2-fusd.ts
 *
 * Runs after s2.ts (same accounts, the agent already linked). Minimal spend:
 * at most 0.5 fUSD leaves the owner (to the relayer's 0x address).
 *
 *   0. if the owner holds fUSD as a bank coin, convert it to its ERC-20 form
 *   1. owner replaces its rule: fUSD per execution 1 fUSD, per day 1.2 fUSD;
 *      native QOR 1000 uqor per execution; fUSD listed in allowed_denoms so
 *      transfer/approve need no allowed_evm_calls entry
 *   F1. agent: fUSD.transfer(relayer, 0.5)   -> expect success
 *   F2. agent: fUSD.transfer(relayer, 2)     -> expect per-execution refusal
 *   F3. agent: fUSD.approve(target, 5)       -> does an allowance count as outflow?
 *   F4. agent: fUSD.transfer(relayer, 0.9)   -> expect daily refusal (0.5 + 0.9 > 1.2)
 */
import { createPublicClient, encodeFunctionData, erc20Abi, http, type Address, type Hex } from "viem";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { linkAgentMsgs, agentLinkProof, buildAgentCall, relay } from "../smart-account.ts";
import { broadcast, balances, FUSD, FUSD_DENOM, network } from "../qore.ts";
import { convertTo } from "../fest.ts";
import { loadSpikeAccount } from "./accounts.ts";

const net = network();
const client = createPublicClient({ transport: http(net.evmRpc) });
const TARGET = JSON.parse(readFileSync(join(process.env.HOME ?? "", ".qore-pq-kit", "spikes", "s2-state.json"), "utf8")).target as Address;
const COMMIT_SELECTOR = "0x2b926184" as Hex;
const FUSD_RULE_DENOM = `erc20/${FUSD}`;
const ONE = 1_000_000n; // fUSD has 6 decimals

const fusdOf = (a: Address) => client.readContract({ address: FUSD, abi: erc20Abi, functionName: "balanceOf", args: [a] });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const [owner, agent, relayAcc] = await Promise.all(["s2-owner", "s2-agent", "s2-relay"].map(loadSpikeAccount));
  const bank = (await balances(owner.cosmos))[FUSD_DENOM] ?? 0n;
  console.log(`owner ${owner.cosmos}: bank fUSD ${bank}, ERC-20 fUSD ${await fusdOf(owner.evm as Address)}`);

  if (bank > 0n) {
    console.log("0. convert the bank fUSD to ERC-20 (MsgConvertCoin)");
    await convertTo("s2-owner", owner.evm, FUSD_DENOM, bank);
    for (let i = 0; i < 20 && (await fusdOf(owner.evm as Address)) === 0n; i++) await sleep(3000);
    console.log(`   ERC-20 fUSD now ${await fusdOf(owner.evm as Address)}`);
  }
  if ((await fusdOf(owner.evm as Address)) < ONE) throw new Error("owner holds less than 1 fUSD as ERC-20; nothing to test");

  console.log("1. owner replaces its spending rule (per-denom fUSD limits)");
  const proof = agentLinkProof({ chainId: net.chainId, owner: owner.cosmos, agentPrivateKey: agent.privateKey as Hex });
  const [updateRules] = linkAgentMsgs({
    chainId: net.chainId,
    owner: owner.cosmos,
    proof,
    expiryUnix: BigInt(Math.floor(Date.now() / 1000) + 3 * 86400),
    rule: {
      id: "s2-agent-fusd",
      perTxLimit: 1000n,
      dailyLimit: 5000n,
      allowedDenoms: ["uqor", FUSD_RULE_DENOM],
      denomLimits: [{ denom: FUSD_RULE_DENOM, perTxLimit: ONE, dailyLimit: (ONE * 12n) / 10n }],
      allowedEvmCalls: [{ target: TARGET, selector: COMMIT_SELECTOR }],
    },
  });
  // The agent is already linked: send only MsgUpdateSpendingRules (it replaces the rules wholesale).
  const r = await broadcast(owner, [updateRules!]);
  console.log(`   rules replaced: tx ${r.transactionHash}`);
  await sleep(6000);
  const rules = await fetch(`${net.rest}/qorechain/abstractaccount/v1/accounts/${owner.cosmos}/spending_rules`).then((x) => x.json());
  console.log(`   ${JSON.stringify(rules)}`);

  const call = async (label: string, fn: "transfer" | "approve", to: Address, amount: bigint) => {
    const msg = await buildAgentCall({
      rest: net.rest,
      chainId: net.chainId,
      owner: owner.cosmos,
      relayer: relayAcc.cosmos,
      agentPrivateKey: agent.privateKey as Hex,
      to: FUSD,
      data: encodeFunctionData({ abi: erc20Abi, functionName: fn, args: [to, amount] }),
      gasLimit: 200_000,
    });
    const out = await relay(relayAcc, [msg]);
    const x = out.results[0];
    console.log(
      `${label}: ${out.delivered ? `tx ${out.txHash} code 0 -> success=${x?.success} gasUsed=${x?.gasUsed}${x?.success ? "" : ` reason="${x?.reason}"`}` : `REFUSED ${out.error?.slice(0, 300)}`}`,
    );
    console.log(
      `   owner fUSD ${await fusdOf(owner.evm as Address)}, relayer fUSD ${await fusdOf(relayAcc.evm as Address)}, allowance(owner->target) ${await client.readContract({ address: FUSD, abi: erc20Abi, functionName: "allowance", args: [owner.evm as Address, TARGET] })}`,
    );
  };

  await call("F1 transfer 0.5 fUSD", "transfer", relayAcc.evm as Address, ONE / 2n);
  await call("F2 transfer 2 fUSD (above 1 fUSD per execution)", "transfer", relayAcc.evm as Address, 2n * ONE);
  await call("F3 approve 5 fUSD to the target", "approve", TARGET, 5n * ONE);
  await call("F4 transfer 0.9 fUSD (0.5 + 0.9 above the 1.2 fUSD daily limit)", "transfer", relayAcc.evm as Address, (ONE * 9n) / 10n);
  console.log(`QOR left: owner ${(await balances(owner.cosmos)).uqor}, relayer ${(await balances(relayAcc.cosmos)).uqor}`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
