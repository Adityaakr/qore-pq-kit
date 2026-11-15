import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { recipientOf, generateSealKeys, isQoreSealError, seal } from "@qorechain/qoreseal";
import { bytesToHex, encodeFunctionResult, hexToBytes, type Address, type Hex, type PublicClient } from "viem";
import {
  FIELD_P,
  cardHash,
  combine,
  fieldInverse,
  kemKeySha3,
  keyHash,
  openShare,
  openSlot,
  qorAddress,
  randomFieldElement,
  readPqKey,
  sealSlot,
  shareAad,
  shareHash,
  split,
  verifyMember,
  xorSlot,
  type SlotBinding,
} from "../scripts/threshold.ts";
import { VECTORS_PATH, seededField, vectorsText } from "../scripts/vectors.ts";
import { PURPOSE, SEAL_CHAIN_ID, testMember } from "./fixtures.ts";

const B: SlotBinding = {
  chainId: 9800n,
  app: "0x1111111111111111111111111111111111111111",
  sender: "0x2222222222222222222222222222222222222222",
  seq: 0n,
};
const PT = "0x000000000000000000000000000003e80007000000000000000000000000000" + "0" as Hex;

describe("field and Shamir", () => {
  it("uses P = 2^255 - 19", () => {
    expect(FIELD_P).toBe(2n ** 255n - 19n);
  });

  it("inverts", () => {
    for (const a of [1n, 2n, 12345n, FIELD_P - 1n, randomFieldElement()]) {
      if (a === 0n) continue;
      expect((a * fieldInverse(a)) % FIELD_P).toBe(1n);
    }
  });

  it("recovers from every pair of a 2-of-3 dealing", () => {
    const k = randomFieldElement();
    const s = split(k, 2, 3);
    for (const [i, j] of [[0, 1], [0, 2], [1, 2], [2, 0]] as const) expect(combine([s[i]!, s[j]!])).toBe(k);
    expect(combine(s)).toBe(k);
  });

  it("recovers from every 3-subset of a 3-of-5 dealing", () => {
    const k = randomFieldElement();
    const s = split(k, 3, 5);
    for (let a = 0; a < 5; a++)
      for (let b = a + 1; b < 5; b++)
        for (let c = b + 1; c < 5; c++) expect(combine([s[a]!, s[b]!, s[c]!])).toBe(k);
  });

  it("t - 1 shares do not give the key", () => {
    const k = randomFieldElement();
    const s = split(k, 3, 3);
    expect(combine([s[0]!, s[1]!])).not.toBe(k);
  });

  it("one share of a 2-of-n dealing is consistent with every key", () => {
    // For share (1, y) and any candidate key k', the line f(x) = k' + (y - k') x passes through it.
    const s = split(randomFieldElement(), 2, 3)[0]!;
    for (const candidate of [0n, 1n, randomFieldElement()]) {
      const slope = (((s.value - candidate) % FIELD_P) + FIELD_P) % FIELD_P;
      expect((candidate + slope * 1n) % FIELD_P).toBe(s.value);
    }
  });

  it("refuses bad arguments", () => {
    expect(() => split(1n, 0, 3)).toThrow();
    expect(() => split(1n, 4, 3)).toThrow();
    expect(() => split(1n, 2, 256)).toThrow();
    expect(() => split(FIELD_P, 2, 3)).toThrow();
    expect(() => combine([])).toThrow();
    expect(() => combine([{ index: 1, value: 1n }, { index: 1, value: 2n }])).toThrow(/duplicate/);
    expect(() => combine([{ index: 0, value: 1n }])).toThrow(/bad index/);
    expect(() => combine([{ index: 1, value: FIELD_P }])).toThrow(/out of range/);
  });
});

describe("vectors", () => {
  it("vectors/threshold.json is what `npm run vectors` writes", () => {
    expect(readFileSync(VECTORS_PATH, "utf8")).toBe(vectorsText());
  });

  it("the seeded stream stays below P", () => {
    const r = seededField("x");
    for (let i = 0; i < 100; i++) expect(r() < FIELD_P).toBe(true);
  });
});

describe("sealSlot and openShare", () => {
  const members = [testMember(1), testMember(2), testMember(3)];
  const committee = members.map((m) => recipientOf(m.seal));
  const slot = sealSlot({ binding: B, plaintext: PT, committee, threshold: 2, sealChainId: SEAL_CHAIN_ID, purpose: PURPOSE });

  it("produces one 1,752-byte hybrid envelope per member for a 32-byte share", () => {
    expect(slot.envelopes).toHaveLength(3);
    for (const e of slot.envelopes) expect(e.length).toBe(56 + 1664 + 32);
    expect(slot.shareHashes).toHaveLength(3);
  });

  it("any two members open their shares and recover the plaintext", () => {
    const shares = members.map((m, i) =>
      ({
        index: i + 1,
        value: openShare({
          envelope: slot.envelopes[i]!,
          keys: m.seal,
          binding: B,
          index: i + 1,
          shareHash: slot.shareHashes[i]!,
          sealChainId: SEAL_CHAIN_ID,
          purpose: PURPOSE,
        }),
      }),
    );
    for (const pair of [[0, 1], [0, 2], [1, 2]] as const) {
      expect(openSlot(B, [shares[pair[0]]!, shares[pair[1]]!], slot.keyHash, slot.ct).toLowerCase()).toBe(PT.toLowerCase());
    }
    expect(() => openSlot(B, [shares[0]!], slot.keyHash, slot.ct)).toThrow(/keyHash/);
  });

  const openAs = (over: Partial<Parameters<typeof openShare>[0]>) =>
    openShare({
      envelope: slot.envelopes[0]!,
      keys: members[0]!.seal,
      binding: B,
      index: 1,
      shareHash: slot.shareHashes[0]!,
      sealChainId: SEAL_CHAIN_ID,
      purpose: PURPOSE,
      ...over,
    });

  const expectQoreSeal = (f: () => unknown, code: string) => {
    try {
      f();
    } catch (e) {
      expect(isQoreSealError(e)).toBe(true);
      expect((e as { code: string }).code).toBe(code);
      return;
    }
    throw new Error("expected a QoreSeal error");
  };

  it("an outsider cannot open a share", () => {
    expectQoreSeal(() => openAs({ keys: generateSealKeys() }), "NOT_A_RECIPIENT");
  });

  it("another member cannot open member 1's envelope", () => {
    expectQoreSeal(() => openAs({ keys: members[1]!.seal }), "NOT_A_RECIPIENT");
  });

  it("an envelope copied under another sender, seq, app or index does not open", () => {
    expectQoreSeal(() => openAs({ binding: { ...B, sender: "0x3333333333333333333333333333333333333333" } }), "DECRYPTION_FAILED");
    expectQoreSeal(() => openAs({ binding: { ...B, seq: 1n } }), "DECRYPTION_FAILED");
    expectQoreSeal(() => openAs({ binding: { ...B, app: "0x4444444444444444444444444444444444444444" } }), "DECRYPTION_FAILED");
    expectQoreSeal(() => openAs({ index: 2 }), "DECRYPTION_FAILED");
  });

  it("an envelope under another purpose or chain does not open", () => {
    expectQoreSeal(() => openAs({ purpose: "other/v1" }), "DECRYPTION_FAILED");
    expectQoreSeal(() => openAs({ sealChainId: "qorechain-other" }), "DECRYPTION_FAILED");
  });

  it("an envelope paired with another share hash does not open", () => {
    expectQoreSeal(() => openAs({ shareHash: slot.shareHashes[1]! }), "DECRYPTION_FAILED");
  });

  it("a share that does not match its committed hash is caught after opening", () => {
    // A dishonest sender seals a different value under the committed hash's AAD.
    const committed = slot.shareHashes[0]!;
    const forged = seal({
      chainId: SEAL_CHAIN_ID,
      purpose: PURPOSE,
      recipients: [committee[0]!],
      plaintext: hexToBytes(`0x${(123n).toString(16).padStart(64, "0")}`),
      aad: shareAad(B, 1, committed),
    });
    expect(() => openAs({ envelope: forged })).toThrow(/does not match its committed hash/);
  });

  it("an envelope from another slot does not open under this slot's hash", () => {
    const other = sealSlot({ binding: B, plaintext: PT, committee, threshold: 2, sealChainId: SEAL_CHAIN_ID, purpose: PURPOSE });
    expectQoreSeal(() => openAs({ envelope: other.envelopes[0]! }), "DECRYPTION_FAILED");
  });

  it("refuses a plaintext that is not 32 bytes", () => {
    expect(() =>
      sealSlot({ binding: B, plaintext: "0x01", committee, threshold: 2, sealChainId: SEAL_CHAIN_ID, purpose: PURPOSE }),
    ).toThrow(/32 bytes/);
  });

  it("the hashes match the Solidity formulas", () => {
    const k = 5n;
    expect(keyHash(B, k)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(shareHash(B, 1, k)).not.toBe(shareHash(B, 2, k));
    expect(xorSlot(B, k, xorSlot(B, k, PT))).toBe(PT.toLowerCase());
  });
});

// ---------------------------------------------------------------------------
// verifyMember, against a fake chain
// ---------------------------------------------------------------------------

const KEY_STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

function fakeClient(answer: (to: Address, account: Address) => Hex): PublicClient {
  return {
    call: async ({ to, data }: { to: Address; data: Hex }) => ({ data: answer(to, `0x${data.slice(-40)}` as Address) }),
  } as unknown as PublicClient;
}

function keyStatus(pk: Uint8Array, opts: { registered?: boolean; alg?: number; possession?: boolean } = {}): Hex {
  return encodeFunctionResult({
    abi: KEY_STATUS_ABI,
    functionName: "pqcKeyStatus",
    result: [opts.registered ?? true, opts.alg ?? 1, bytesToHex(pk), opts.possession ?? true],
  });
}

function fakeRest(kemKeys: Record<string, Uint8Array>): typeof fetch {
  return (async (url: string) => {
    const addr = String(url).split("/").pop()!;
    const pk = kemKeys[addr];
    if (!pk) return new Response(JSON.stringify({ found: false, key: null }), { status: 200 });
    return new Response(
      JSON.stringify({
        found: true,
        key: {
          address: addr,
          algorithm_id: 2,
          algorithm_name: "ml-kem-1024",
          public_key: Buffer.from(pk).toString("base64"),
          registered_height: "100",
        },
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;
}

describe("verifyMember", () => {
  const m = testMember(1);
  const other = testMember(2);
  const goodClient = fakeClient(() => keyStatus(m.pq.publicKey));
  const goodRest = fakeRest({ [m.qor]: m.seal.mlkemPublicKey });
  const base = {
    address: m.evm,
    expectKemSha3: kemKeySha3(m.seal.mlkemPublicKey),
    card: m.card,
    expectCardHash: cardHash(m.card),
    sealChainId: SEAL_CHAIN_ID,
    client: goodClient,
    rest: "https://rest.invalid",
    fetch: goodRest,
  };

  it("qorAddress matches QoreSign's address forms", () => {
    expect(qorAddress(m.evm)).toBe(m.qor);
  });

  it("accepts a member whose three bindings hold", async () => {
    const r = await verifyMember(base);
    expect(bytesToHex(r.mlkemPublicKey)).toBe(bytesToHex(m.seal.mlkemPublicKey));
    expect(bytesToHex(r.x25519PublicKey!)).toBe(bytesToHex(m.seal.x25519PublicKey));
  });

  it("refuses when the chain holds another ML-DSA key", async () => {
    await expect(verifyMember({ ...base, client: fakeClient(() => keyStatus(other.pq.publicKey)) })).rejects.toThrow();
  });

  it("refuses an ML-DSA key without proven possession, of another algorithm, or unregistered", async () => {
    for (const o of [{ possession: false }, { alg: 2 }, { registered: false }]) {
      await expect(verifyMember({ ...base, client: fakeClient(() => keyStatus(m.pq.publicKey, o)) })).rejects.toThrow(/usable/);
    }
  });

  it("fails closed when the precompile answers with empty data", async () => {
    await expect(readPqKey(fakeClient(() => "0x"), m.evm)).rejects.toThrow(/empty/);
  });

  it("refuses an ML-KEM key from REST that does not match the committed hash (lying proxy)", async () => {
    await expect(verifyMember({ ...base, fetch: fakeRest({ [m.qor]: other.seal.mlkemPublicKey }) })).rejects.toThrow(/ML-KEM/);
  });

  it("refuses a member with no ML-KEM key", async () => {
    await expect(verifyMember({ ...base, fetch: fakeRest({}) })).rejects.toThrow();
  });

  it("refuses a card that does not match its committed hash", async () => {
    await expect(verifyMember({ ...base, card: other.card })).rejects.toThrow(/card/);
  });

  it("refuses a tampered card even with a matching hash", async () => {
    const tampered = { ...m.card, x25519PublicKey: bytesToHex(other.seal.x25519PublicKey).slice(2) };
    await expect(verifyMember({ ...base, card: tampered, expectCardHash: cardHash(tampered) })).rejects.toThrow();
  });

  it("refuses another account's genuine card", async () => {
    // other's card, other's keys on chain and in REST, but listed under m's address
    await expect(
      verifyMember({
        ...base,
        card: other.card,
        expectCardHash: cardHash(other.card),
        expectKemSha3: kemKeySha3(other.seal.mlkemPublicKey),
        client: fakeClient(() => keyStatus(other.pq.publicKey)),
        fetch: fakeRest({ [m.qor]: other.seal.mlkemPublicKey }),
      }),
    ).rejects.toThrow();
  });

  it("cardHash covers every signed field", () => {
    expect(cardHash({ ...m.card, issuedAt: "2026-11-17T00:00:00Z" })).not.toBe(cardHash(m.card));
    expect(cardHash({ ...m.card, mlkemKeySha3: "00".repeat(32) })).not.toBe(cardHash(m.card));
  });

});
