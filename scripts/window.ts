/**
 * window.ts - open and close EVM authorisation windows.
 *
 * An Ethereum-style transaction cannot carry a post-quantum signature, so on
 * QoreChain an account first sends a hybrid-signed `MsgOpenEVMWindow` that
 * admits a bounded amount of EVM activity: a block count, a transaction count,
 * a total spend (value PLUS each transaction's maximum fee, in uqor), and
 * optionally a list of at most 16 recipient addresses (the scope).
 *
 * Facts found by experiment and in the docs (chain v3.2.8 on qorechain-diana):
 * - A scoped window (allowedTargets) refuses contract creation. Deploy under an
 *   unscoped window, then close it.
 * - Opening a window advances the account's nonce: open first, read the nonce, sign.
 * - Opening replaces any earlier window. Closing takes effect in the same block.
 * - The spend cap counts native QOR only; token amounts must be capped in contracts.
 */
import { closeEvmWindowMsg, fetchEvmWindow, openEvmWindowMsg } from "@qorechain/sdk";
import { evmWindowCost } from "@qorechain/evm";
import { broadcast, loadAccount, network } from "./qore.ts";

export interface OpenOptions {
  /** Block count (1 to 17,280; the testnet makes roughly one block a second). */
  blocks: number;
  /** Number of EVM transactions admitted (1 to 1,000). */
  maxTxs: number;
  /** Gas limit each transaction is sized for. */
  gasPerTx: bigint;
  /** Fee cap each transaction is sized for, in wei per gas. */
  maxFeePerGas?: bigint;
  /** Native value each transaction may carry, in wei. */
  valuePerTx?: bigint;
  /** Extra native value the whole window may carry, in wei (e.g. one funding transfer). */
  extraValueWei?: bigint;
  /** Restrict recipients to these contracts (no contract creation). Empty = unscoped. */
  targets?: string[];
}

export async function openWindow(name: string, o: OpenOptions): Promise<string> {
  const acc = await loadAccount(name);
  const perTx = evmWindowCost({
    gas: o.gasPerTx,
    maxFeePerGas: o.maxFeePerGas ?? 250_000_000_000n,
    value: o.valuePerTx ?? 0n,
  });
  const extra = o.extraValueWei ? evmWindowCost({ gas: 0n, maxFeePerGas: 0n, value: o.extraValueWei }) : 0n;
  const maxValue = perTx * BigInt(o.maxTxs) + extra;
  const targets = (o.targets ?? []).map((t) => t.toLowerCase());
  const msg = openEvmWindowMsg({
    sender: acc.cosmos,
    blocks: o.blocks,
    maxTxs: o.maxTxs,
    maxValue,
    ...(targets.length > 0 ? { allowedTargets: targets } : {}),
  });
  const res = await broadcast(acc, [msg]);
  console.log(
    `opened window: tx ${res.transactionHash}; ${o.blocks} blocks, ${o.maxTxs} txs, ${maxValue} uqor` +
      (targets.length ? `, targets ${targets.join(" ")}` : ", UNSCOPED"),
  );
  return res.transactionHash;
}

export async function closeWindow(name: string): Promise<string | undefined> {
  const acc = await loadAccount(name);
  const w = await fetchEvmWindow({ rest: network().rest, address: acc.cosmos });
  if (!w.found) {
    console.log("no window to close");
    return undefined;
  }
  const res = await broadcast(acc, [closeEvmWindowMsg(acc.cosmos)]);
  console.log(`closed window: tx ${res.transactionHash}`);
  return res.transactionHash;
}
