import { describe, expect, it } from "vitest";
import { createRest, handleRestProxy, isAllowedRoute, toQor, RestError } from "../scripts/rest.ts";

const QOR = "qor1ekyftdz36tndvnmttjexmzpgj48j0mfwk007rp";
const EVM = "0xcd8895b451d2e6d64f6b5cb26d8828954f27ed2e";

type Handler = (url: string, init?: RequestInit) => { status: number; body: unknown };

function fakeFetch(h: Handler, seen: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    seen.push(url);
    const { status, body } = h(url, init);
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

describe("routes and addresses", () => {
  it("converts 0x to qor1 and back-checks qor1", () => {
    expect(toQor(EVM)).toBe(QOR);
    expect(toQor(QOR.toUpperCase())).toBe(QOR);
    expect(() => toQor("cosmos1ekyftdz36tndvnmttjexmzpgj48j0mfw7m4wa8")).toThrow();
  });

  it("allows only the read routes", () => {
    expect(isAllowedRoute(`/qorechain/pqc/v1/kem/${QOR}`)).toBe(true);
    expect(isAllowedRoute(`/qorechain/pqc/v1/account/${EVM}`)).toBe(true);
    expect(isAllowedRoute(`/qorechain/abstractaccount/v1/accounts/${QOR}/spending_rules`)).toBe(true);
    expect(isAllowedRoute("/cosmos/tx/v1beta1/txs")).toBe(false); // broadcast
    expect(isAllowedRoute(`/qorechain/pqc/v1/kem/${QOR}/../../x`)).toBe(false);
    expect(isAllowedRoute(`/qorechain/pqc/v1/kem/${QOR}?x=1`)).toBe(false);
    expect(isAllowedRoute("/cosmos/bank/v1beta1/balances/qor1notanaddress")).toBe(false);
  });
});

describe("client", () => {
  it("reads and decodes a PQC account", async () => {
    const seen: string[] = [];
    const rest = createRest({
      base: "https://proxy.invalid/rest/",
      fetch: fakeFetch(
        () => ({
          status: 200,
          body: { found: true, account: { address: QOR, public_key: "AQID", algorithm_id: 1, key_type: "hybrid", possession_proven: true, created_at_height: "9936548" } },
        }),
        seen,
      ),
    });
    const a = await rest.pqcAccount(EVM);
    expect(seen[0]).toBe(`https://proxy.invalid/rest/qorechain/pqc/v1/account/${QOR}`);
    expect(a).toMatchObject({ found: true, algorithmId: 1, possessionProven: true, createdAtHeight: 9936548n });
    expect([...a.publicKey!]).toEqual([1, 2, 3]);
  });

  it("reports a missing PQC account and KEM key as not found", async () => {
    const rest = createRest({ fetch: fakeFetch(() => ({ status: 200, body: { found: false, account: null, key: null } })) });
    expect(await rest.pqcAccount(QOR)).toEqual({ found: false });
    expect(await rest.kemKey(QOR)).toEqual({ found: false });
  });

  it("refuses to read a KEM key from a network without the registry", async () => {
    const rest = createRest({ fetch: fakeFetch(() => ({ status: 501, body: { code: 12, message: "Not Implemented" } })) });
    await expect(rest.kemKey(QOR)).rejects.toThrow(/KEM key registry/);
  });

  it("parses a window and balances", async () => {
    const rest = createRest({
      fetch: fakeFetch((url) =>
        url.includes("evm_window")
          ? { status: 200, body: { found: true, live: true, expiry_height: "100", max_txs: "3", used_txs: "1", remaining_blocks: "50", remaining_txs: "2", remaining_value: "1000", native_only: false, allowed_targets: ["0xabc"] } }
          : { status: 200, body: { balances: [{ denom: "uqor", amount: "1500000" }] } },
      ),
    });
    expect(await rest.evmWindow(QOR)).toMatchObject({ found: true, live: true, remainingTxs: 2n, allowedTargets: ["0xabc"] });
    expect(await rest.balances(QOR)).toEqual({ uqor: 1500000n });
  });

  it("gives a zero sequence for an unknown account, and undefined for an unknown tx", async () => {
    const rest = createRest({ fetch: fakeFetch(() => ({ status: 404, body: { code: 5, message: "not found" } })) });
    expect(await rest.accountSequence(QOR)).toEqual({ accountNumber: 0n, sequence: 0n });
    expect(await rest.tx("AB".repeat(32))).toBeUndefined();
    expect(await rest.abstractAccount(QOR, "spending_rules")).toBeUndefined();
  });

  it("refuses a non-allowlisted route without sending anything", async () => {
    const seen: string[] = [];
    const rest = createRest({ fetch: fakeFetch(() => ({ status: 200, body: {} }), seen) });
    await expect(rest.get("/cosmos/tx/v1beta1/txs")).rejects.toBeInstanceOf(RestError);
    expect(seen).toHaveLength(0);
  });

  it("turns a non-JSON answer into a RestError", async () => {
    const rest = createRest({ fetch: fakeFetch(() => ({ status: 502, body: "<html>bad gateway</html>" })) });
    await expect(rest.pqcAccount(QOR)).rejects.toThrow(/non-JSON/);
  });
});

describe("proxy", () => {
  const upstream = (seen: string[], inits: (RequestInit | undefined)[] = []) =>
    fakeFetch((url, init) => {
      inits.push(init);
      return { status: 200, body: { found: false, key: null, url } };
    }, seen);

  it("answers preflight with CORS headers", async () => {
    const res = await handleRestProxy(new Request("http://p/rest/x", { method: "OPTIONS" }), { prefix: "/rest" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("forwards an allowed GET with CORS headers, dropping other query parameters and request headers", async () => {
    const seen: string[] = [];
    const inits: (RequestInit | undefined)[] = [];
    const req = new Request(`http://p/rest/qorechain/pqc/v1/kem/${QOR}?pagination.limit=5&evil=1`, { headers: { cookie: "session=secret", authorization: "Bearer x" } });
    const res = await handleRestProxy(req, { prefix: "/rest", upstream: "https://up.invalid", fetch: upstream(seen, inits) });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(seen[0]).toBe(`https://up.invalid/qorechain/pqc/v1/kem/${QOR}?pagination.limit=5`);
    const sent = new Headers(inits[0]!.headers);
    expect(sent.get("cookie")).toBeNull();
    expect(sent.get("authorization")).toBeNull();
  });

  it("refuses POST (no broadcasting) and other routes", async () => {
    const seen: string[] = [];
    const post = await handleRestProxy(new Request("http://p/cosmos/tx/v1beta1/txs", { method: "POST", body: "{}" }), { fetch: upstream(seen) });
    expect(post.status).toBe(405);
    const other = await handleRestProxy(new Request("http://p/cosmos/staking/v1beta1/validators"), { fetch: upstream(seen) });
    expect(other.status).toBe(403);
    const outside = await handleRestProxy(new Request(`http://p/other/qorechain/pqc/v1/kem/${QOR}`), { prefix: "/rest", fetch: upstream(seen) });
    expect(outside.status).toBe(404);
    expect(seen).toHaveLength(0);
  });

  it("reports an unreachable upstream as 502", async () => {
    const res = await handleRestProxy(new Request(`http://p/qorechain/pqc/v1/kem/${QOR}`), {
      fetch: (async () => {
        throw new Error("down");
      }) as unknown as typeof fetch,
    });
    expect(res.status).toBe(502);
  });

  it("a client pointed at the proxy works end to end", async () => {
    const seen: string[] = [];
    const proxyFetch = (async (input: RequestInfo | URL) =>
      handleRestProxy(new Request(String(input)), { prefix: "/rest", upstream: "https://up.invalid", fetch: upstream(seen) })) as typeof fetch;
    const rest = createRest({ base: "http://page.invalid/rest", fetch: proxyFetch });
    expect(await rest.kemKey(EVM)).toEqual({ found: false });
    expect(seen[0]).toBe(`https://up.invalid/qorechain/pqc/v1/kem/${QOR}`);
  });
});

describe.runIf(process.env.QORE_LIVE === "1")("live testnet (QORE_LIVE=1)", () => {
  it("reads QoreChain's own account and an empty KEM key", async () => {
    const rest = createRest();
    const a = await rest.pqcAccount(QOR);
    expect(a.found).toBe(true);
    expect(a.publicKey!.length).toBe(2592);
    expect(a.possessionProven).toBe(true);
    expect((await rest.kemKey(QOR)).found).toBe(false);
    expect((await rest.evmWindow(QOR)).found).toBe(false);
  });
});
