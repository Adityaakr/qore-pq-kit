import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { pqcVerify, generatePqcKeypair } from "@qorechain/sdk";
import { hexToBytes, type Address, type Hex } from "viem";
import { actionId } from "../scripts/pqauth.ts";
import { anyAction, anyMessage, orderShares, quorumAction, quorumMessage, signQuorumShare } from "../scripts/pqauthset.ts";
import { PQAUTHSET_VECTORS_PATH, pqAuthSetVectorsText } from "../scripts/vectors.ts";

const V = JSON.parse(readFileSync(join(import.meta.dirname, "..", "vectors", "pqauthset.json"), "utf8"));

describe("PqAuthSet messages", () => {
  it("vectors/pqauthset.json is what `npm run vectors` writes", () => {
    expect(readFileSync(PQAUTHSET_VECTORS_PATH, "utf8")).toBe(pqAuthSetVectorsText());
  });

  it("match vectors/pqauthset.json (checked by Foundry too)", () => {
    const a = actionId(V.actionName);
    expect(a).toBe(V.action);
    expect(quorumAction(a)).toBe(V.quorumAction);
    expect(anyAction(a)).toBe(V.anyAction);
    const f = { chainId: BigInt(V.chainId), verifier: V.verifier as Address, action: a, nonce: BigInt(V.nonce), deadline: BigInt(V.deadline), argsHash: V.argsHash as Hex };
    expect(quorumMessage(f, V.member)).toBe(V.quorumMessage);
    expect(anyMessage(f, V.member)).toBe(V.anyMessage);
    expect(hexToBytes(V.quorumMessage).length).toBe(256);
  });

  it("signs shares that verify, and orders them ascending", () => {
    const k1 = generatePqcKeypair();
    const k2 = generatePqcKeypair();
    const f = { chainId: 9800n, verifier: V.verifier as Address, action: actionId("X.y"), nonce: 0n, deadline: 1n << 40n, argsHash: V.argsHash as Hex };
    const hi = "0xffffffffffffffffffffffffffffffffffffffff" as Address;
    const lo = "0x0000000000000000000000000000000000000001" as Address;
    const s1 = signQuorumShare(k1, hi, f);
    const s2 = signQuorumShare(k2, lo, f);
    expect(pqcVerify(k1.publicKey, hexToBytes(quorumMessage(f, hi)), hexToBytes(s1.signature))).toBe(true);
    const o = orderShares([s1, s2]);
    expect(o.signers).toEqual([lo, hi]);
    expect(o.signatures).toEqual([s2.signature, s1.signature]);
    expect(() => orderShares([s1, s1])).toThrow(/duplicate/);
  });
});
