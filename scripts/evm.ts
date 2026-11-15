/**
 * evm.ts - send EVM transactions from a unified account, inside a live window.
 *
 * Gas is estimated by the QoreChain node itself (eth_estimateGas), never by a
 * local simulator: Foundry and Hardhat cannot run the QoreChain precompiles, so
 * any contract that checks a post-quantum key in its constructor or functions
 * fails a local simulation (the precompile address is empty there, which
 * PqAuth correctly treats as "unavailable"). This is also why the deployment
 * scripts here use viem rather than `forge script`.
 */
import type { UnifiedAccount } from "@qorechain/sdk";
import { createWalletClient, http, type Hex, type TransactionReceipt, type WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { network, publicClient } from "./qore.ts";

/** Fee settings: the testnet answers eth_gasPrice with 112.5 gwei (100 base + 12.5 tip). */
export const MAX_FEE_PER_GAS = 200_000_000_000n;
export const MAX_PRIORITY_FEE_PER_GAS = 12_500_000_000n;

export function walletFor(acc: UnifiedAccount): WalletClient {
  const net = network();
  return createWalletClient({
    account: privateKeyToAccount(acc.privateKey as Hex),
    chain: {
      id: net.evmChainId,
      name: "QoreChain Testnet",
      nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
      rpcUrls: { default: { http: [net.evmRpc] } },
    },
    transport: http(net.evmRpc),
  });
}

export interface EvmTx {
  to?: Hex;
  data?: Hex;
  value?: bigint;
  /** Gas limit; estimated by the node with 25% headroom when omitted. */
  gas?: bigint;
}

/** Estimate a transaction's gas on the node, with 25% headroom. */
export async function estimate(acc: UnifiedAccount, tx: EvmTx): Promise<bigint> {
  const g = await publicClient().estimateGas({
    account: acc.evm as Hex,
    to: tx.to,
    data: tx.data,
    value: tx.value,
  });
  return (g * 125n) / 100n;
}

/** Send one EVM transaction and wait for its receipt. Throws if it reverted. */
export async function sendEvm(acc: UnifiedAccount, tx: EvmTx): Promise<TransactionReceipt> {
  const wallet = walletFor(acc);
  const gas = tx.gas ?? (await estimate(acc, tx));
  const nonce = await publicClient().getTransactionCount({ address: acc.evm as Hex, blockTag: "pending" });
  const hash = await wallet.sendTransaction({
    account: wallet.account!,
    chain: wallet.chain,
    to: tx.to ?? null,
    data: tx.data,
    value: tx.value ?? 0n,
    gas,
    nonce,
    maxFeePerGas: MAX_FEE_PER_GAS,
    maxPriorityFeePerGas: MAX_PRIORITY_FEE_PER_GAS,
  });
  const receipt = await publicClient().waitForTransactionReceipt({ hash, timeout: 120_000 });
  if (receipt.status !== "success") throw new Error(`EVM transaction ${hash} reverted`);
  return receipt;
}
