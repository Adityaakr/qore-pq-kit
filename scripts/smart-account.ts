/**
 * smart-account.ts - let an agent act for an owner's account, held to limits
 * the chain enforces: link the agent's secp256k1 key to the owner's account
 * with a spending rule, have the agent sign `MsgExecuteEVM` calls, and relay
 * them.
 *
 * Settled by spike S2 on qorechain-diana (docs/spikes.md):
 * - the agent key is linked by its 20-byte address (the MetaMask-style link)
 *   and signs EIP-191 `personal_sign` over the chain's v2 EVM auth digest;
 * - the call runs as the OWNER's 0x address, and needs no EVM window on the
 *   owner account;
 * - the owner's first enabled spending rule bounds the key: a call above
 *   `perTxLimit`, or with calldata to a target/selector not in
 *   `allowedEvmCalls`, comes back `success = false` inside a code-0
 *   transaction and CONSUMES the key's nonce; treat that as final;
 * - a replayed message is refused at delivery (code != 0), and the relayer
 *   still pays its fee.
 *
 * Who holds what (design section 6): the owner signs the link and the rules
 * (hybrid, ML-DSA-87), so the agent cannot raise its own limits; the agent
 * holds only its classical key; the relayer only pays gas.
 *
 * Node only (it uses the full SDK and the kit's broadcaster).
 */
import type { EncodeObject } from "@cosmjs/proto-signing";
import {
  buildMetaMaskExecuteEvm,
  decodeAuthenticatorExecutions,
  fetchAuthNonce,
  linkAuthenticatorMsgs,
  resolveEvmAuthDigestVersion,
  revokeAuthenticatorMsg,
  signAuthenticatorLinkEip191,
  verifyAuthenticatorLinkProof,
  type AuthenticatorExecutionResult,
  type AuthenticatorLinkProof,
  type EvmAuthDigestVersion,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { getAddress, hexToBytes, isAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { broadcast } from "./qore.ts";

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/** One allowed EVM call: a contract, and optionally one function selector of it. */
export interface EvmCall {
  target: Address;
  /** 4-byte selector, e.g. `0x2b926184`; omit to allow any function of `target`. */
  selector?: Hex;
}

/** `0x<target>` or `0x<target>/0x<selector>`, lower-case, as the chain stores it. */
export function evmCallEntry(c: EvmCall): string {
  if (!isAddress(c.target)) throw new Error(`bad target ${c.target}`);
  const t = c.target.toLowerCase();
  if (c.selector === undefined) return t;
  if (!/^0x[0-9a-fA-F]{8}$/.test(c.selector)) throw new Error(`bad selector ${c.selector}`);
  return `${t}/${c.selector.toLowerCase()}`;
}

/** What the agent may do, in base units (uqor for native QOR; the token's own units for ERC-20s). */
export interface AgentRule {
  id: string;
  /** Largest outflow per execution of any denom without a `denomLimits` entry. Must be > 0, or give denomLimits for every denom. */
  perTxLimit: bigint;
  /** Daily outflow cap of any denom without a `denomLimits` entry (UTC day). */
  dailyLimit: bigint;
  /** The only denoms the key may move (`uqor`, `erc20/0x<token>`); empty = any. */
  allowedDenoms?: string[];
  /** Per-denom limits, e.g. fUSD: `{ denom: "erc20/0x9714…63CA", perTxLimit, dailyLimit }`. */
  denomLimits?: { denom: string; perTxLimit: bigint; dailyLimit: bigint }[];
  /** Contracts/functions the key may call with calldata. */
  allowedEvmCalls: EvmCall[];
}

// ---------------------------------------------------------------------------
// Linking (owner-signed)
// ---------------------------------------------------------------------------

/** The agent's proof that it holds its key, bound to the chain and the owner's account. Made by the agent. */
export function agentLinkProof(args: { chainId: string; owner: string; agentPrivateKey: Hex }): AuthenticatorLinkProof {
  return signAuthenticatorLinkEip191({ chainId: args.chainId, account: args.owner, privateKey: args.agentPrivateKey });
}

/**
 * The owner's messages that link the agent key with its rule, for ONE
 * transaction the owner signs (hybrid). They REPLACE every spending rule on the
 * owner's account; pass `otherRules` to keep any others (the chain applies the
 * first enabled rule, which is `rule`).
 */
export function linkAgentMsgs(args: {
  chainId: string;
  owner: string;
  proof: AuthenticatorLinkProof;
  rule: AgentRule;
  /** Unix seconds after which the chain stops accepting the key. */
  expiryUnix: bigint;
  label?: string;
  otherRules?: AgentRule[];
}): EncodeObject[] {
  if (!verifyAuthenticatorLinkProof({ chainId: args.chainId, account: args.owner, scheme: args.proof.scheme, pubkey: args.proof.pubkey, possessionProof: args.proof.possessionProof })) {
    throw new Error("the agent's link proof does not verify for this chain and owner");
  }
  const toInput = (r: AgentRule) => ({
    id: r.id,
    enabled: true,
    perTxLimit: r.perTxLimit,
    dailyLimit: r.dailyLimit,
    allowedDenoms: r.allowedDenoms ?? [],
    allowedEvmCalls: r.allowedEvmCalls.map(evmCallEntry),
    denomLimits: (r.denomLimits ?? []).map((d) => ({ denom: d.denom, perTxLimit: d.perTxLimit.toString(), dailyLimit: d.dailyLimit.toString() })),
  });
  return linkAuthenticatorMsgs({
    owner: args.owner,
    chainId: args.chainId,
    scheme: args.proof.scheme,
    pubkey: args.proof.pubkey,
    possessionProof: args.proof.possessionProof,
    permissions: ["evm"],
    expiryUnix: args.expiryUnix,
    ...(args.label ? { label: args.label } : {}),
    spendingRules: [args.rule, ...(args.otherRules ?? [])].map(toInput),
  });
}

/** The owner's message that disables the agent key at once. */
export function revokeAgentMsg(owner: string, agentAddress: Address): EncodeObject {
  return revokeAuthenticatorMsg({ owner, scheme: "secp256k1", pubkey: hexToBytes(getAddress(agentAddress)) });
}

// ---------------------------------------------------------------------------
// Calling (agent-signed, relayer-broadcast)
// ---------------------------------------------------------------------------

/** The key's next sequence (its own counter, not the account's EVM nonce). */
export async function agentNonce(rest: string, owner: string, agentAddress: Address): Promise<{ nonce: bigint; linked: boolean }> {
  return fetchAuthNonce({ rest, address: owner, pubkey: hexToBytes(getAddress(agentAddress)) });
}

/** An EIP-1193-shaped signer over a raw private key, for the SDK's MetaMask builders. */
function localProvider(privateKey: Hex) {
  const a = privateKeyToAccount(privateKey);
  return {
    address: a.address,
    async request({ method, params }: { method: string; params: unknown[] }): Promise<string> {
      if (method !== "personal_sign") throw new Error(`unsupported method ${method}`);
      if (String(params[1]).toLowerCase() !== a.address.toLowerCase()) throw new Error("personal_sign for another address");
      return a.signMessage({ message: { raw: params[0] as Hex } });
    },
  };
}

export interface AgentCallArgs {
  rest: string;
  chainId: string;
  owner: string;
  relayer: string;
  agentPrivateKey: Hex;
  to: Address;
  data?: Hex;
  /** Native value in wei. Default 0. */
  value?: bigint;
  gasLimit: number | bigint;
  /** Default: read from the chain. */
  nonce?: bigint;
  /** Default: asked from the node (never guessed: the chain accepts exactly one form). */
  digestVersion?: EvmAuthDigestVersion;
}

/** Sign one `MsgExecuteEVM` as the agent. The relayer broadcasts it. */
export async function buildAgentCall(a: AgentCallArgs): Promise<EncodeObject> {
  const p = localProvider(a.agentPrivateKey);
  const nonce = a.nonce ?? (await agentNonce(a.rest, a.owner, p.address)).nonce;
  return buildMetaMaskExecuteEvm({
    provider: p,
    address: p.address,
    relayer: a.relayer,
    chainId: a.chainId,
    account: a.owner,
    to: a.to,
    value: (a.value ?? 0n).toString(),
    ...(a.data ? { data: hexToBytes(a.data) } : {}),
    gasLimit: a.gasLimit,
    nonce,
    digestVersion: a.digestVersion ?? (await resolveEvmAuthDigestVersion({ rest: a.rest })),
  });
}

export interface RelayOutcome {
  txHash: string;
  /** False when the chain refused the transaction outright (e.g. a replay); the relayer still paid. */
  delivered: boolean;
  /** One per message, when delivered. `success = false` is final: the nonce is spent. */
  results: AuthenticatorExecutionResult[];
  error?: string;
}

/**
 * Broadcast agent calls from the relayer (hybrid-signed, it pays the fee) and
 * decode each execution. Never reads a code-0 transaction as success: check
 * `results[i].success`.
 */
export async function relay(relayer: UnifiedAccount, msgs: EncodeObject[]): Promise<RelayOutcome> {
  try {
    const res = (await broadcast(relayer, msgs)) as unknown as Parameters<typeof decodeAuthenticatorExecutions>[0] & { transactionHash: string };
    return { txHash: res.transactionHash, delivered: true, results: decodeAuthenticatorExecutions(res, msgs) };
  } catch (e) {
    const message = (e as Error).message;
    const hash = /transaction ([0-9A-F]{64})/.exec(message)?.[1] ?? "";
    return { txHash: hash, delivered: false, results: [], error: message };
  }
}
