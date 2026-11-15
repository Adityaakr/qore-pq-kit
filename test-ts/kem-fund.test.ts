import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { verifyRecipientCard } from "@qorechain/qoreseal";
import { deriveUnifiedAccount } from "@qorechain/sdk";
import { checkFund, fundMsg, FUND_FLOOR_UQOR, FUND_MAX_UQOR, parseQor } from "../scripts/fund.ts";
import { recipientCard, registerKemMsg, sealKeysOf } from "../scripts/kem.ts";
import { cardHash, kemKeySha3 } from "../scripts/threshold.ts";

// The BIP-39 test-vector mnemonic: public, for tests only.
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("fund guards", () => {
  it("parses QOR amounts exactly", () => {
    expect(parseQor("1")).toBe(1_000_000n);
    expect(parseQor("1.5")).toBe(1_500_000n);
    expect(parseQor("0.000001")).toBe(1n);
    for (const bad of ["", "-1", "1.0000001", "1e3", "abc", "1,5"]) expect(() => parseQor(bad)).toThrow();
  });

  it("refuses zero, above the cap, or below the sender's floor", () => {
    expect(() => checkFund(100_000_000n, 0n)).toThrow(/positive/);
    expect(() => checkFund(1_000_000_000n, FUND_MAX_UQOR + 1n)).toThrow(/cap/);
    expect(() => checkFund(2_000_000n, 1_000_000n)).toThrow(/floor/); // 2 - 1 - 0.15 fee < 1
    expect(() => checkFund(2_150_000n, 1_000_000n)).not.toThrow(); // leaves exactly the floor
    expect(() => checkFund(10_000_000n, 9_000_000n, 0n)).not.toThrow();
    expect(FUND_FLOOR_UQOR).toBe(1_000_000n);
  });

  it("builds a plain bank send", () => {
    const m = fundMsg("qor1a", "qor1b", 5n);
    expect(m.typeUrl).toBe("/cosmos.bank.v1beta1.MsgSend");
    expect(m.value).toEqual({ fromAddress: "qor1a", toAddress: "qor1b", amount: [{ denom: "uqor", amount: "5" }] });
  });
});

describe("KEM key and recipient card", () => {
  it("derives seal keys from the mnemonic, per index", async () => {
    const acc = await deriveUnifiedAccount(MNEMONIC, 0);
    const k0 = sealKeysOf(acc);
    expect(kemKeySha3(sealKeysOf(acc, 0).mlkemPublicKey)).toBe(kemKeySha3(k0.mlkemPublicKey));
    expect(kemKeySha3(sealKeysOf(acc, 1).mlkemPublicKey)).not.toBe(kemKeySha3(k0.mlkemPublicKey));
    expect(k0.mlkemPublicKey.length).toBe(1568);
  });

  it("builds MsgRegisterKEMKey and refuses a key of the wrong size", async () => {
    const acc = await deriveUnifiedAccount(MNEMONIC, 0);
    const m = registerKemMsg(acc.cosmos, sealKeysOf(acc).mlkemPublicKey);
    expect(m.typeUrl).toBe("/qorechain.pqc.v1.MsgRegisterKEMKey");
    expect(() => registerKemMsg(acc.cosmos, new Uint8Array(32))).toThrow(/1568/);
  });

  it("signs a card that verifies against the account's ML-DSA and ML-KEM keys, with matching hashes", async () => {
    const acc = await deriveUnifiedAccount(MNEMONIC, 0);
    const keys = sealKeysOf(acc);
    const c = recipientCard(acc, { issuedAt: "2026-11-16T00:00:00Z" });
    expect(c.card.address).toBe(acc.cosmos);
    expect(c.card.chainId).toBe("qorechain-diana");
    expect(c.cardHash).toBe(cardHash(c.card));
    expect(c.mlkemKeySha3).toBe(kemKeySha3(keys.mlkemPublicKey));
    const r = verifyRecipientCard({ card: c.card, chainId: "qorechain-diana", pqPublicKey: acc.pqc.publicKey, mlkemPublicKey: keys.mlkemPublicKey });
    expect(Buffer.from(r.x25519PublicKey!)).toEqual(Buffer.from(keys.x25519PublicKey));
  });
});

describe("secrets directory", () => {
  const dir = mkdtempSync(join(tmpdir(), "qore-pq-kit-secrets-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("QORE_SECRETS_DIR picks the directory; the default stays ~/.qore-drill", async () => {
    vi.resetModules();
    vi.stubEnv("QORE_SECRETS_DIR", dir);
    const withEnv = await import("../scripts/secrets.ts");
    expect(withEnv.secretsPath("member-1")).toBe(join(dir, "member-1.env"));
    vi.unstubAllEnvs();
    vi.resetModules();
    vi.stubEnv("QORE_SECRETS_DIR", "");
    const without = await import("../scripts/secrets.ts");
    expect(without.DEFAULT_SECRETS_DIR.endsWith(".qore-drill")).toBe(true);
    vi.unstubAllEnvs();
  });
});
