import { describe, expect, it } from "vitest";
import { generateSealKeys, recipientOf, isQoreSealError } from "@qorechain/qoreseal";
import { bytesToHex, encodeFunctionResult, type PublicClient } from "viem";
import {
  InstructionRefused,
  instructionBytes,
  isoSeconds,
  openInstruction,
  qorToEvm,
  randomNonce,
  receiveInstruction,
  sealInstruction,
  signInstruction,
  verifyInstruction,
  verifyInstructionWithChain,
  type InstructionFields,
} from "../scripts/messaging.ts";
import { SEAL_CHAIN_ID, testMember } from "./fixtures.ts";

const owner = testMember(11);
const agent = testMember(12);
const stranger = testMember(13);
const NOW = new Date("2026-11-20T12:00:00Z");
const PURPOSE = "peal-bidder/mandate/v1";

function fields(over: Partial<InstructionFields> = {}): InstructionFields {
  return {
    chainId: SEAL_CHAIN_ID,
    from: owner.qor,
    to: agent.qor,
    purpose: PURPOSE,
    nonce: "n-1",
    issuedAt: "2026-11-20T11:00:00Z",
    expiresAt: "2026-11-21T11:00:00Z",
    body: JSON.stringify({ budget: "1000000", maxTick: 40, note: "bid on auction 0xabc" }),
    ...over,
  };
}

const expectFor = { chainId: SEAL_CHAIN_ID, to: agent.qor, purpose: PURPOSE, now: NOW };
const sign = (f = fields()) => signInstruction({ fields: f, classicalKey: owner.classical, pqKey: owner.pq });

function refused(f: () => unknown, re: RegExp) {
  expect(f).toThrow(InstructionRefused);
  expect(f).toThrow(re);
}

const KEY_STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }],
  },
] as const;
const chainWith = (keys: Record<string, Uint8Array>): PublicClient =>
  ({
    call: async ({ data }: { data: string }) => {
      const who = `0x${data.slice(-40)}`.toLowerCase();
      const pk = keys[who];
      return {
        data: encodeFunctionResult({ abi: KEY_STATUS_ABI, functionName: "pqcKeyStatus", result: pk ? [true, 1, bytesToHex(pk), true] : [false, 0, "0x", false] }),
      };
    },
  }) as unknown as PublicClient;

describe("instruction encoding", () => {
  it("is one fixed text, and every field changes it", () => {
    const base = new TextDecoder().decode(instructionBytes(fields()));
    expect(base.startsWith("qore-pq-kit instruction v1\n[")).toBe(true);
    for (const k of ["chainId", "from", "to", "purpose", "nonce", "body"] as const) {
      expect(new TextDecoder().decode(instructionBytes(fields({ [k]: "x" })))).not.toBe(base);
    }
  });

  it("refuses badly formed times", () => {
    expect(() => instructionBytes(fields({ expiresAt: "tomorrow" }))).toThrow();
    expect(() => instructionBytes(fields({ issuedAt: "2026-11-20T11:00:00.000Z" }))).toThrow();
  });

  it("helpers", () => {
    expect(isoSeconds(new Date("2026-11-20T11:00:00.123Z"))).toBe("2026-11-20T11:00:00Z");
    expect(randomNonce()).toMatch(/^[0-9a-f]{32}$/);
    expect(qorToEvm(owner.qor).toLowerCase()).toBe(owner.evm.toLowerCase());
  });
});

describe("sign and verify", () => {
  it("accepts a genuine instruction", () => {
    const f = verifyInstruction(sign(), owner.pq.publicKey, expectFor);
    expect(JSON.parse(f.body).maxTick).toBe(40);
  });

  it("refuses an altered field", () => {
    const s = sign();
    refused(() => verifyInstruction({ ...s, fields: { ...s.fields, body: s.fields.body.replace("40", "99") } }, owner.pq.publicKey, expectFor), /bad signature/);
  });

  it("refuses a forgery by another account claiming to be the owner", () => {
    // QoreSign will not sign as an account the key does not control, so the forger
    // signs as itself and then relabels the sender.
    const own = signInstruction({ fields: fields({ from: stranger.qor }), classicalKey: stranger.classical, pqKey: stranger.pq });
    const forged = { ...own, fields: { ...own.fields, from: owner.qor } };
    refused(() => verifyInstruction(forged, owner.pq.publicKey, expectFor), /bad signature/);
  });

  it("refuses when the ML-DSA half is by another key (classical key stolen)", () => {
    const halfStolen = signInstruction({ fields: fields(), classicalKey: owner.classical, pqKey: stranger.pq });
    refused(() => verifyInstruction(halfStolen, owner.pq.publicKey, expectFor), /bad signature/);
  });

  it("refuses a classical-only signature", () => {
    const s = sign();
    const { pq: _pq, ...classicalOnly } = s.signature;
    refused(() => verifyInstruction({ ...s, signature: { ...classicalOnly, signatureType: "secp256k1" } }, owner.pq.publicKey, expectFor), /bad signature/);
  });

  it("refuses an expired, future-dated or too-long-lived instruction", () => {
    refused(() => verifyInstruction(sign(), owner.pq.publicKey, { ...expectFor, now: new Date("2026-11-21T11:00:00Z") }), /expired/);
    refused(() => verifyInstruction(sign(fields({ issuedAt: "2026-11-20T13:00:00Z" })), owner.pq.publicKey, expectFor), /future/);
    refused(() => verifyInstruction(sign(fields({ expiresAt: "2026-12-20T11:00:00Z" })), owner.pq.publicKey, expectFor), /lifetime/);
  });

  it("refuses another chain, recipient, purpose or sender", () => {
    refused(() => verifyInstruction(sign(fields({ chainId: "qorechain-mainnet" })), owner.pq.publicKey, expectFor), /chain/);
    refused(() => verifyInstruction(sign(fields({ to: stranger.qor })), owner.pq.publicKey, expectFor), /addressed/);
    refused(() => verifyInstruction(sign(fields({ purpose: "other/v1" })), owner.pq.publicKey, expectFor), /purpose/);
    refused(() => verifyInstruction(sign(), owner.pq.publicKey, { ...expectFor, from: stranger.qor }), /from/);
  });

  it("refuses a replayed nonce", () => {
    const used = new Set<string>();
    const e = { ...expectFor, seen: (from: string, nonce: string) => used.has(`${from}/${nonce}`) };
    const f = verifyInstruction(sign(), owner.pq.publicKey, e);
    used.add(`${f.from}/${f.nonce}`);
    refused(() => verifyInstruction(sign(), owner.pq.publicKey, e), /already used/);
  });
});

describe("sealed instructions", () => {
  const agentRecipient = recipientOf(agent.seal);

  it("round trip: seal, open with the agent's keys, verify against the key on chain", async () => {
    const env = sealInstruction(sign(), agentRecipient);
    const client = chainWith({ [owner.evm.toLowerCase()]: owner.pq.publicKey });
    const f = await receiveInstruction({ envelope: env, keys: agent.seal, client, expect: expectFor });
    expect(f.nonce).toBe("n-1");
  });

  it("someone else cannot open it", () => {
    const env = sealInstruction(sign(), agentRecipient);
    try {
      openInstruction({ envelope: env, keys: generateSealKeys(), chainId: SEAL_CHAIN_ID, to: agent.qor, purpose: PURPOSE });
      throw new Error("opened");
    } catch (e) {
      expect(isQoreSealError(e, "NOT_A_RECIPIENT")).toBe(true);
    }
  });

  it("an envelope filed under another purpose or chain does not open", () => {
    const env = sealInstruction(sign(), agentRecipient);
    expect(() => openInstruction({ envelope: env, keys: agent.seal, chainId: SEAL_CHAIN_ID, to: agent.qor, purpose: "other/v1" })).toThrow();
    expect(() => openInstruction({ envelope: env, keys: agent.seal, chainId: "qorechain-x", to: agent.qor, purpose: PURPOSE })).toThrow();
  });

  it("refuses when the chain holds another key for the sender, or none", async () => {
    const s = sign();
    await expect(verifyInstructionWithChain(s, chainWith({ [owner.evm.toLowerCase()]: stranger.pq.publicKey }), expectFor)).rejects.toThrow(/bad signature/);
    await expect(verifyInstructionWithChain(s, chainWith({}), expectFor)).rejects.toThrow(/sender key/);
  });

  it("refuses cheaply before reading the chain", async () => {
    let calls = 0;
    const client = { call: async () => (calls++, { data: "0x" }) } as unknown as PublicClient;
    await expect(verifyInstructionWithChain(sign(fields({ to: stranger.qor })), client, expectFor)).rejects.toThrow(/addressed/);
    expect(calls).toBe(0);
  });
});
