/**
 * rehearse.ts - a Q-Day Drill rehearsal: what can the CLASSICAL key alone do?
 *
 *   npm run pq -- rehearse <account> [vault] [token]
 *
 * Plays the drill's attacker bot against one of our own accounts. It reads
 * ONLY that account's classical secp256k1 private key (PRIVATE_KEY in the
 * secrets file) and never its mnemonic, so it cannot make the account's real
 * ML-DSA-87 signature. Where an attack needs a post-quantum half it uses a
 * freshly generated ML-DSA-87 key of its own, as a real attacker would.
 *
 * Each attempt is reported with the chain's answer and with the account's
 * native balance before and after, because a refused transaction can still be
 * charged its fee. Run it against an account holding little QOR.
 */
import { randomBytes } from "node:crypto";
import { StargateClient } from "@cosmjs/stargate";
import {
  EthNativeSigner,
  buildRegisterPqcKeyMsg,
  msg as sdkMsg,
  openEvmWindowMsg,
  signProofOfPossession,
  unifiedAccountFromSeed,
  type UnifiedAccount,
} from "@qorechain/sdk";
import type { EncodeObject } from "@cosmjs/proto-signing";
import { encodeFunctionData, erc20Abi, maxUint256, type Address, type Hex } from "viem";
import { loadSecrets, secretsPath } from "./secrets.ts";
import { accountSequence, balances, network, publicClient } from "./qore.ts";
import { walletFor, MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS } from "./evm.ts";

interface Outcome {
  attack: string;
  refused: boolean;
  answer: string;
  feeCharged: bigint;
}

/** The attacker's view of the account: the real classical key, a made-up PQ key. */
function attackerAccount(name: string): UnifiedAccount {
  const secrets = loadSecrets(secretsPath(name));
  const pk = secrets.PRIVATE_KEY;
  if (!pk || !/^0x[0-9a-fA-F]{64}$/.test(pk)) throw new Error("PRIVATE_KEY missing");
  return unifiedAccountFromSeed(Uint8Array.from(Buffer.from(pk.slice(2), "hex")), {
    pqcSecret: Uint8Array.from(randomBytes(32)),
  });
}

const SMALL_FEE = { amount: [{ denom: "uqor", amount: "150000" }], gas: "1000000" };

async function nativeAttempt(
  acc: UnifiedAccount,
  mode: "classical" | "hybrid",
  messages: EncodeObject[],
): Promise<string> {
  const net = network();
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: net.rest });
  const transport = await StargateClient.connect(net.rpc);
  try {
    const res = await signer.signAndBroadcast(transport, {
      chainId: net.chainId,
      accountNumber,
      sequence,
      fee: SMALL_FEE,
      messages,
    });
    return res.code === 0 ? `ACCEPTED tx ${res.transactionHash}` : `code ${res.code}: ${(res.rawLog ?? "").slice(0, 160)}`;
  } catch (err) {
    return `refused: ${(err instanceof Error ? err.message : String(err)).replace(/\s+/g, " ").slice(0, 200)}`;
  } finally {
    transport.disconnect();
  }
}

async function evmAttempt(acc: UnifiedAccount, to: Address, data?: Hex, value = 0n): Promise<string> {
  const wallet = walletFor(acc);
  try {
    const nonce = await publicClient().getTransactionCount({ address: acc.evm as Address, blockTag: "pending" });
    const hash = await wallet.sendTransaction({
      account: wallet.account!,
      chain: wallet.chain,
      to,
      data,
      value,
      gas: data && data.length > 2_000 ? 600_000n : 100_000n,
      nonce,
      maxFeePerGas: MAX_FEE_PER_GAS,
      maxPriorityFeePerGas: MAX_PRIORITY_FEE_PER_GAS,
    });
    const r = await publicClient().waitForTransactionReceipt({ hash, timeout: 60_000 });
    return `ACCEPTED tx ${hash} status ${r.status}`;
  } catch (err) {
    const m = err instanceof Error ? (err as { details?: string }).details ?? err.message : String(err);
    return `refused: ${m.replace(/\s+/g, " ").slice(0, 200)}`;
  }
}

async function measured(acc: UnifiedAccount, attack: string, run: () => Promise<string>): Promise<Outcome> {
  const before = (await balances(acc.cosmos)).uqor ?? 0n;
  const answer = await run();
  await new Promise((r) => setTimeout(r, 3000));
  const after = (await balances(acc.cosmos)).uqor ?? 0n;
  return { attack, refused: !answer.startsWith("ACCEPTED"), answer, feeCharged: before - after };
}

export async function rehearse(name = "ops", vault?: string, token?: string): Promise<boolean> {
  const acc = attackerAccount(name);
  const sink = "0x000000000000000000000000000000000000dEaD" as Address;
  const outcomes: Outcome[] = [];

  outcomes.push(
    await measured(acc, "native transfer, classical signature only", () =>
      nativeAttempt(acc, "classical", [
        sdkMsg.bank.send({ fromAddress: acc.cosmos, toAddress: acc.cosmos, amount: [{ denom: "uqor", amount: "1" }] }),
      ]),
    ),
  );
  outcomes.push(
    await measured(acc, "native transfer, hybrid with the attacker's own ML-DSA-87 key", () =>
      nativeAttempt(acc, "hybrid", [
        sdkMsg.bank.send({ fromAddress: acc.cosmos, toAddress: acc.cosmos, amount: [{ denom: "uqor", amount: "1" }] }),
      ]),
    ),
  );
  outcomes.push(
    await measured(acc, "open an EVM window, classical signature only", () =>
      nativeAttempt(acc, "classical", [openEvmWindowMsg({ sender: acc.cosmos, blocks: 100, maxTxs: 10, maxValue: 1_000_000n })]),
    ),
  );
  outcomes.push(
    await measured(acc, "open an EVM window, hybrid with the attacker's own key", () =>
      nativeAttempt(acc, "hybrid", [openEvmWindowMsg({ sender: acc.cosmos, blocks: 100, maxTxs: 10, maxValue: 1_000_000n })]),
    ),
  );
  outcomes.push(
    await measured(acc, "re-register the PQ key to the attacker's key (classical)", () => {
      const net = network();
      const pop = signProofOfPossession({ chainId: net.chainId, account: acc.cosmos, keypair: acc.pqc });
      return nativeAttempt(acc, "classical", [buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession: pop })]);
    }),
  );
  outcomes.push(await measured(acc, "EVM native transfer (no window)", () => evmAttempt(acc, sink, undefined, 1n)));
  if (token) {
    const approve = encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [sink, maxUint256] });
    outcomes.push(await measured(acc, `EVM token approval on ${token} (no window)`, () => evmAttempt(acc, token as Address, approve)));
  }
  if (vault) {
    // A drain call: sweep everything to the attacker with a forged signature.
    const sweepAbi = [
      {
        type: "function",
        name: "sweep",
        stateMutability: "nonpayable",
        inputs: [
          { name: "token", type: "address" },
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "sig", type: "bytes" },
        ],
        outputs: [],
      },
    ] as const;
    const block = await publicClient().getBlock();
    const data = encodeFunctionData({
      abi: sweepAbi,
      functionName: "sweep",
      args: ["0x0000000000000000000000000000000000000000", sink, 1n, block.timestamp + 600n, `0x${randomBytes(4627).toString("hex")}`],
    });
    outcomes.push(await measured(acc, "drain call: vault.sweep with a forged signature (sent)", () => evmAttempt(acc, vault as Address, data)));
    outcomes.push({
      attack: "drain call: vault.sweep with a forged signature (eth_call)",
      ...(await publicClient()
        .call({ account: acc.evm as Address, to: vault as Address, data })
        .then(
          () => ({ refused: false, answer: "ACCEPTED (call returned)" }),
          (e: unknown) => ({ refused: true, answer: `reverted: ${String((e as Error).message).split("\n")[0]?.slice(0, 160)}` }),
        )),
      feeCharged: 0n,
    });
  }

  let ok = true;
  for (const o of outcomes) {
    ok &&= o.refused;
    console.log(`${o.refused ? "REFUSED " : "SUCCEEDED"}  ${o.attack}`);
    console.log(`           answer: ${o.answer}`);
    console.log(`           fee charged to the account: ${o.feeCharged} uqor`);
  }
  console.log(ok ? "every attack was refused" : "AT LEAST ONE ATTACK SUCCEEDED");
  return ok;
}
