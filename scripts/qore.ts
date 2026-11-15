/**
 * qore.ts - the network, the account and hybrid-signed native transactions.
 *
 * Every native-lane transaction from an account with a registered ML-DSA-87
 * key is signed twice (secp256k1 + ML-DSA-87). The one exception is the key
 * registration itself, which the chain accepts signed classically.
 */
import { StargateClient } from "@cosmjs/stargate";
import type { EncodeObject, Registry } from "@cosmjs/proto-signing";
import {
  EthNativeSigner,
  deriveUnifiedAccount,
  getNetwork,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { createPublicClient, http, type Address, type PublicClient } from "viem";
import { loadSecrets, secretsPath } from "./secrets.ts";

/** QoreChain testnet (`qorechain-diana`). The kit refuses any other network. */
export interface Network {
  chainId: string;
  evmChainId: number;
  rest: string;
  rpc: string;
  evmRpc: string;
}

export function network(): Network {
  const name = process.env.QORE_NETWORK?.trim() || "testnet";
  if (name !== "testnet") throw new Error(`this kit runs on the testnet only (QORE_NETWORK=${name})`);
  const n = getNetwork("testnet");
  return {
    chainId: n.chainId,
    evmChainId: 9800,
    rest: process.env.QORE_REST_URL?.trim() || n.endpoints.rest,
    rpc: process.env.QORE_RPC_URL?.trim() || n.endpoints.rpc,
    evmRpc: process.env.QORE_EVM_RPC_URL?.trim() || "https://evm-testnet.qore.host",
  };
}

/**
 * The precompile addresses, lower-cased. The SDK exports them in mixed case
 * (`0x…0A01`), which viem rejects as a bad EIP-55 checksum.
 */
export const PQC_VERIFY = "0x0000000000000000000000000000000000000a01" as Address;
export const PQC_KEY_STATUS = "0x0000000000000000000000000000000000000a02" as Address;

/** The fest token fUSD (6 decimals): ERC-20 contract and bank denomination. */
export const FUSD = "0x97143B771D34ddb9130b807b135Ae675A5a963CA" as Address;
export const FUSD_DENOM = "erc20:0x97143B771D34ddb9130b807b135Ae675A5a963CA";

/** Derive the unified account (secp256k1 + ML-DSA-87) from a named secrets file. */
export async function loadAccount(name = "drill"): Promise<UnifiedAccount> {
  const secrets = loadSecrets(secretsPath(name));
  const mnemonic = secrets.QORE_MNEMONIC;
  if (!mnemonic) throw new Error(`QORE_MNEMONIC missing in ${secretsPath(name)}`);
  return deriveUnifiedAccount(mnemonic, 0);
}

export function publicClient(): PublicClient {
  return createPublicClient({ transport: http(network().evmRpc) }) as PublicClient;
}

export async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${network().rest}${path}`);
  if (!res.ok) throw new Error(`GET ${path}: HTTP ${res.status} ${await res.text()}`);
  return (await res.json()) as T;
}

/** Account number and sequence over REST (the eth_secp256k1 account shape). */
export async function accountSequence(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
  const res = await fetch(`${network().rest}/cosmos/auth/v1beta1/accounts/${address}`);
  if (res.status === 404) return { accountNumber: 0n, sequence: 0n };
  if (!res.ok) throw new Error(`account lookup failed: HTTP ${res.status}`);
  const body = (await res.json()) as { account?: Record<string, unknown> };
  const acc = (body.account?.base_account ?? body.account ?? {}) as Record<string, string>;
  return { accountNumber: BigInt(acc.account_number ?? "0"), sequence: BigInt(acc.sequence ?? "0") };
}

/** Native balances of an address, as { denom: amount }. */
export async function balances(address: string): Promise<Record<string, bigint>> {
  const body = await getJson<{ balances: { denom: string; amount: string }[] }>(
    `/cosmos/bank/v1beta1/balances/${address}?pagination.limit=100`,
  );
  return Object.fromEntries(body.balances.map((b) => [b.denom, BigInt(b.amount)]));
}

/** Hybrid transactions are large (a 4,627-byte ML-DSA-87 signature), so the gas limit is generous. */
export const NATIVE_FEE = { amount: [{ denom: "uqor", amount: "150000" }], gas: "1000000" };

export interface BroadcastResult {
  transactionHash: string;
  code: number;
  rawLog?: string;
  height?: number;
}

/**
 * Sign and broadcast native-lane messages. `mode` is "hybrid" for everything
 * except the ML-DSA-87 key registration, which is the one message the chain
 * accepts signed classically. Throws on a non-zero result code.
 */
export async function broadcast(
  acc: UnifiedAccount,
  messages: EncodeObject[],
  mode: "hybrid" | "classical" = "hybrid",
  fee = NATIVE_FEE,
  registry?: Registry,
): Promise<BroadcastResult> {
  const net = network();
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: net.rest, ...(registry ? { registry } : {}) });
  const transport = await StargateClient.connect(net.rpc);
  try {
    const res = await signer.signAndBroadcast(transport, {
      chainId: net.chainId,
      accountNumber,
      sequence,
      fee,
      messages,
    });
    if (res.code !== 0) {
      throw new Error(`transaction ${res.transactionHash} failed with code ${res.code}: ${res.rawLog ?? ""}`);
    }
    return res;
  } finally {
    transport.disconnect();
  }
}

/** Format a uqor amount as QOR. */
export function qor(uqor: bigint): string {
  const whole = uqor / 1_000_000n;
  const frac = (uqor % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac} QOR` : `${whole} QOR`;
}
