/**
 * Risk R4: QoreSeal 0.1.0 pins QoreSign 0.1.0 exactly, while QoreSign 0.2.0 is
 * current. A recipient card is a QoreSign message signature, so a card signed
 * by an app on one version must verify on the other. These tests sign and
 * verify across both versions, in both directions.
 */
import { describe, expect, it } from "vitest";
import { assembleRecipientCard, recipientCardFields, recipientCardSignBytes, signRecipientCard, verifyRecipientCard } from "@qorechain/qoreseal";
import * as qs020 from "@qorechain/qoresign";
import * as qs010 from "qoresign-0.1.0";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { SEAL_CHAIN_ID, testMember } from "./fixtures.ts";

const require = createRequire(import.meta.url);

describe("QoreSign 0.1.0 and 0.2.0 interoperate on recipient cards", () => {
  const m = testMember(7);
  const fields = recipientCardFields({ chainId: SEAL_CHAIN_ID, address: m.qor, keys: m.seal, issuedAt: "2026-11-16T00:00:00Z" });
  const bytes = recipientCardSignBytes(fields);

  it("the installed versions are the ones under test", () => {
    const v020 = JSON.parse(readFileSync(require.resolve("@qorechain/qoresign/package.json"), "utf8")).version;
    const v010 = JSON.parse(readFileSync(require.resolve("qoresign-0.1.0/package.json"), "utf8")).version;
    const sealPkg = require.resolve("@qorechain/qoreseal/package.json");
    const inner = JSON.parse(
      readFileSync(sealPkg.replace(/package\.json$/, "node_modules/@qorechain/qoresign/package.json"), "utf8"),
    ).version;
    expect([v020, v010, inner]).toEqual(["0.2.0", "0.1.0", "0.1.0"]);
  });

  it("both versions build the same message sign bytes", () => {
    expect(Buffer.from(qs010.messagePqSignBytes(SEAL_CHAIN_ID, bytes))).toEqual(
      Buffer.from(qs020.messagePqSignBytes(SEAL_CHAIN_ID, bytes)),
    );
  });

  it("a card signed by QoreSeal (QoreSign 0.1.0 inside) verifies with QoreSign 0.2.0", () => {
    const card = signRecipientCard({
      chainId: SEAL_CHAIN_ID,
      address: m.qor,
      keys: m.seal,
      classicalKey: m.classical,
      pqKey: m.pq,
      issuedAt: fields.issuedAt,
    });
    expect(() =>
      qs020.verifyMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: bytes, signature: card.signature, pqPublicKey: m.pq.publicKey, requirePq: true }),
    ).not.toThrow();
  });

  it("a card signed with QoreSign 0.2.0 verifies in QoreSeal (QoreSign 0.1.0 inside)", () => {
    const sig = qs020.signMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: bytes, classicalKey: m.classical, pqKey: m.pq });
    const card = assembleRecipientCard(fields, sig);
    const r = verifyRecipientCard({ card, chainId: SEAL_CHAIN_ID, pqPublicKey: m.pq.publicKey, mlkemPublicKey: m.seal.mlkemPublicKey });
    expect(Buffer.from(r.x25519PublicKey!)).toEqual(Buffer.from(m.seal.x25519PublicKey));
  });

  it("a message signed with QoreSign 0.1.0 verifies with 0.2.0, and the reverse", () => {
    const s1 = qs010.signMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: "hello", classicalKey: m.classical, pqKey: m.pq });
    expect(() => qs020.verifyMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: "hello", signature: s1, pqPublicKey: m.pq.publicKey, requirePq: true })).not.toThrow();
    const s2 = qs020.signMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: "hello", classicalKey: m.classical, pqKey: m.pq });
    expect(() => qs010.verifyMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: "hello", signature: s2, pqPublicKey: m.pq.publicKey, requirePq: true })).not.toThrow();
  });

  it("a card signed by the wrong ML-DSA key fails on both versions", () => {
    const wrong = testMember(8);
    const sig = qs020.signMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: bytes, classicalKey: m.classical, pqKey: wrong.pq });
    const card = assembleRecipientCard(fields, sig);
    expect(() => verifyRecipientCard({ card, chainId: SEAL_CHAIN_ID, pqPublicKey: m.pq.publicKey, mlkemPublicKey: m.seal.mlkemPublicKey })).toThrow();
    expect(() => qs020.verifyMessage({ chainId: SEAL_CHAIN_ID, signer: m.qor, data: bytes, signature: sig, pqPublicKey: m.pq.publicKey, requirePq: true })).toThrow();
  });
});
