import { describe, expect, it } from "vitest";
import { evmAuthSignBytesV2 } from "@qorechain/sdk";
import { bytesToHex, hashMessage, recoverAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { agentLinkProof, buildAgentCall, evmCallEntry, linkAgentMsgs, revokeAgentMsg, type AgentRule } from "../scripts/smart-account.ts";

const CHAIN = "qorechain-diana";
const OWNER = "qor1tjh4rhpleesty97hx5y5c5ufmpphs7g54sq0qv";
const OTHER_OWNER = "qor1dt98ep2ev99ujz8swmc2yt6awr79027fwfscj6";
const AGENT_KEY = `0x${"11".repeat(32)}` as Hex;
const AGENT = privateKeyToAccount(AGENT_KEY).address;
const TARGET = "0x33055a97ebf2ac0dc5653b932f18c0767d9bcbd2" as Address;
const FUSD = "0x97143B771D34ddb9130b807b135Ae675A5a963CA";

const rule: AgentRule = {
  id: "agent",
  perTxLimit: 1000n,
  dailyLimit: 5000n,
  denomLimits: [{ denom: `erc20/${FUSD}`, perTxLimit: 50_000_000n, dailyLimit: 200_000_000n }],
  allowedEvmCalls: [{ target: TARGET, selector: "0x2b926184" }],
};

describe("rules", () => {
  it("formats allowed EVM calls as the chain stores them", () => {
    expect(evmCallEntry({ target: "0x33055a97EbF2AC0dc5653B932F18C0767d9BcbD2", selector: "0x2B926184" })).toBe(`${TARGET}/0x2b926184`);
    expect(evmCallEntry({ target: TARGET })).toBe(TARGET);
    expect(() => evmCallEntry({ target: "0x1234" as Address })).toThrow();
    expect(() => evmCallEntry({ target: TARGET, selector: "0x12" as Hex })).toThrow();
  });
});

describe("linking", () => {
  const proof = agentLinkProof({ chainId: CHAIN, owner: OWNER, agentPrivateKey: AGENT_KEY });

  it("links by the agent's 20-byte address and builds [rules, register] for one owner-signed tx", () => {
    expect(bytesToHex(proof.pubkey)).toBe(AGENT.toLowerCase());
    const msgs = linkAgentMsgs({ chainId: CHAIN, owner: OWNER, proof, rule, expiryUnix: 1_900_000_000n });
    expect(msgs.map((m) => m.typeUrl)).toEqual([
      "/qorechain.abstractaccount.v1.MsgUpdateSpendingRules",
      "/qorechain.abstractaccount.v1.MsgRegisterAuthenticator",
    ]);
    const rules = JSON.parse(JSON.stringify(msgs[0]!.value, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    expect(JSON.stringify(rules)).toContain(`${TARGET}/0x2b926184`);
    expect(JSON.stringify(rules)).toContain(`erc20/${FUSD}`);
  });

  it("refuses a proof made for another owner", () => {
    const other = agentLinkProof({ chainId: CHAIN, owner: OTHER_OWNER, agentPrivateKey: AGENT_KEY });
    expect(() => linkAgentMsgs({ chainId: CHAIN, owner: OWNER, proof: other, rule, expiryUnix: 1_900_000_000n })).toThrow(/does not verify/);
  });

  it("refuses a proof made for another chain", () => {
    const other = agentLinkProof({ chainId: "qorechain-x", owner: OWNER, agentPrivateKey: AGENT_KEY });
    expect(() => linkAgentMsgs({ chainId: CHAIN, owner: OWNER, proof: other, rule, expiryUnix: 1_900_000_000n })).toThrow(/does not verify/);
  });

  it("revokes by address", () => {
    const m = revokeAgentMsg(OWNER, AGENT);
    expect(m.typeUrl).toBe("/qorechain.abstractaccount.v1.MsgRevokeAuthenticator");
  });
});

describe("agent calls", () => {
  it("signs EIP-191 over the chain's v2 digest, recoverable to the agent's address", async () => {
    const data = "0x2b9261840000000000000000000000000000000000000000000000000000000000000007" as Hex;
    const m = await buildAgentCall({ rest: "unused", chainId: CHAIN, owner: OWNER, relayer: OTHER_OWNER, agentPrivateKey: AGENT_KEY, to: TARGET, data, gasLimit: 200_000, nonce: 3n, digestVersion: "v2" });
    const v = m.value as { account: string; relayer: string; pubkey: Uint8Array; signature: Uint8Array; nonce: bigint | string; gasLimit: bigint | string };
    expect(m.typeUrl).toBe("/qorechain.abstractaccount.v1.MsgExecuteEVM");
    expect(v.account).toBe(OWNER);
    expect(String(v.nonce)).toBe("3");
    expect(String(v.gasLimit)).toBe("200000");
    const digest = evmAuthSignBytesV2({ chainId: CHAIN, account: OWNER, pubkey: v.pubkey, to: TARGET, value: "0", data: Buffer.from(data.slice(2), "hex"), nonce: 3n, gasLimit: 200_000n });
    const signer = await recoverAddress({ hash: hashMessage({ raw: digest }), signature: bytesToHex(v.signature) });
    expect(signer).toBe(AGENT);
  });

  it("binds the gas limit and nonce: a different one gives a different signature", async () => {
    const base = { rest: "unused", chainId: CHAIN, owner: OWNER, relayer: OTHER_OWNER, agentPrivateKey: AGENT_KEY, to: TARGET, gasLimit: 200_000, nonce: 0n, digestVersion: "v2" as const };
    const a = (await buildAgentCall(base)).value as { signature: Uint8Array };
    const b = (await buildAgentCall({ ...base, gasLimit: 300_000 })).value as { signature: Uint8Array };
    const c = (await buildAgentCall({ ...base, nonce: 1n })).value as { signature: Uint8Array };
    expect(bytesToHex(a.signature)).not.toBe(bytesToHex(b.signature));
    expect(bytesToHex(a.signature)).not.toBe(bytesToHex(c.signature));
  });
});
