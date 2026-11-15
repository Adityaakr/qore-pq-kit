/**
 * rest.ts - read QoreChain's REST API from a browser or Node, directly or
 * through a proxy, plus the proxy itself.
 *
 * The public REST endpoint sends no CORS headers (spike S4 in docs/spikes.md),
 * so a web page must go through a proxy. A proxy is a party that can lie, so
 * treat everything read here as a claim: check keys against hashes or chain
 * state before relying on them (`threshold.ts` `verifyMember` does that for
 * committee keys, and reads ML-DSA keys from the EVM RPC instead, which does
 * send CORS headers).
 *
 * The client only issues GETs to an allowlist of read routes, and the proxy
 * only forwards those, so a proxy built from this file cannot be used to
 * broadcast transactions or reach other routes.
 *
 * Browser-safe: uses `fetch`, `Request` and `Response` only.
 */
import { base64, bech32 } from "@scure/base";

export const DEFAULT_REST = "https://api-testnet.qore.host";

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

const QOR = "qor1[02-9ac-hj-np-z]{38,58}";
const ADDR = `(?:${QOR}|0x[0-9a-fA-F]{40})`;
const HASH = "[0-9A-Fa-f]{64}";

/** The read routes the client issues and the proxy forwards. Anything else is refused. */
export const REST_ROUTES: readonly RegExp[] = [
  new RegExp(`^/qorechain/pqc/v1/account/${ADDR}$`),
  new RegExp(`^/qorechain/pqc/v1/kem/${ADDR}$`),
  new RegExp(`^/qorechain/pqc/v1/evm_window/${ADDR}$`),
  /^\/qorechain\/pqc\/v1\/params$/,
  new RegExp(`^/qorechain/abstractaccount/v1/accounts/${QOR}(?:/authenticators|/spending_rules)?$`),
  new RegExp(`^/cosmos/auth/v1beta1/accounts/${QOR}$`),
  new RegExp(`^/cosmos/bank/v1beta1/balances/${QOR}$`),
  /^\/cosmos\/bank\/v1beta1\/denoms_metadata$/,
  /^\/cosmos\/evm\/erc20\/v1\/token_pairs$/,
  new RegExp(`^/cosmos/tx/v1beta1/txs/${HASH}$`),
  /^\/cosmos\/base\/tendermint\/v1beta1\/blocks\/latest$/,
];

/** Query parameters the proxy passes on; everything else is dropped. */
const ALLOWED_QUERY = new Set(["pagination.limit", "pagination.key"]);

export function isAllowedRoute(path: string): boolean {
  return REST_ROUTES.some((r) => r.test(path));
}

/** The `qor1` form of a `0x` address (or a `qor1` address, checked and returned lower-case). */
export function toQor(address: string): string {
  if (/^0x[0-9a-fA-F]{40}$/.test(address)) {
    const bytes = new Uint8Array(20);
    for (let i = 0; i < 20; i++) bytes[i] = parseInt(address.slice(2 + 2 * i, 4 + 2 * i), 16);
    return bech32.encode("qor", bech32.toWords(bytes));
  }
  const lower = address.toLowerCase();
  const d = bech32.decode(lower as `${string}1${string}`);
  if (d.prefix !== "qor") throw new Error(`not a qor address: ${address}`);
  return lower;
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

export class RestError extends Error {
  constructor(
    readonly path: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "RestError";
  }
}

export interface RestOptions {
  /** REST base URL: the public endpoint, or a proxy (for example `/rest` on the page's own origin). */
  base?: string;
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout. Default 15 s. */
  timeoutMs?: number;
}

export interface PqcAccount {
  found: boolean;
  address?: string;
  algorithmId?: number;
  keyType?: string;
  publicKey?: Uint8Array;
  possessionProven?: boolean;
  createdAtHeight?: bigint;
}

export interface KemKey {
  found: boolean;
  algorithmId?: number;
  publicKey?: Uint8Array;
  registeredHeight?: bigint;
}

export interface EvmWindow {
  found: boolean;
  live: boolean;
  expiryHeight: bigint;
  maxTxs: bigint;
  usedTxs: bigint;
  remainingBlocks: bigint;
  remainingTxs: bigint;
  remainingValue: string;
  nativeOnly: boolean;
  allowedTargets: string[];
}

const big = (v: unknown): bigint => (typeof v === "string" && /^\d+$/.test(v) ? BigInt(v) : typeof v === "number" ? BigInt(v) : 0n);
const b64 = (v: unknown): Uint8Array | undefined => (typeof v === "string" && v !== "" ? base64.decode(v) : undefined);

export function createRest(opts: RestOptions = {}) {
  const baseUrl = (opts.base ?? DEFAULT_REST).replace(/\/+$/, "");
  const f = opts.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const timeoutMs = opts.timeoutMs ?? 15_000;

  /** GET an allowlisted route; returns the JSON body and the HTTP status. */
  async function get<T = Record<string, unknown>>(path: string, query?: Record<string, string>): Promise<{ status: number; body: T }> {
    if (!isAllowedRoute(path)) throw new RestError(path, 0, `route not allowed: ${path}`);
    const qs = query ? `?${new URLSearchParams(query).toString()}` : "";
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await f(`${baseUrl}${path}${qs}`, { method: "GET", signal: ctrl.signal, headers: { accept: "application/json" } });
    } catch (e) {
      throw new RestError(path, 0, `request to ${path} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      clearTimeout(timer);
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new RestError(path, res.status, `${path} answered HTTP ${res.status} with a non-JSON body`);
    }
    return { status: res.status, body: body as T };
  }

  async function getOk<T>(path: string, query?: Record<string, string>): Promise<T> {
    const { status, body } = await get<T>(path, query);
    if (status >= 400) throw new RestError(path, status, `${path}: HTTP ${status} ${JSON.stringify(body).slice(0, 200)}`);
    return body;
  }

  return {
    base: baseUrl,
    get,

    /** The account's registered post-quantum (ML-DSA-87) key, as REST reports it. */
    async pqcAccount(address: string): Promise<PqcAccount> {
      const body = await getOk<{ found?: boolean; account?: Record<string, unknown> | null }>(`/qorechain/pqc/v1/account/${toQor(address)}`);
      const a = body.account;
      if (body.found !== true || !a) return { found: false };
      return {
        found: true,
        address: typeof a.address === "string" ? a.address : undefined,
        algorithmId: Number(a.algorithm_id),
        keyType: typeof a.key_type === "string" ? a.key_type : undefined,
        publicKey: b64(a.public_key),
        possessionProven: a.possession_proven === true,
        createdAtHeight: big(a.created_at_height),
      };
    },

    /** The account's published KEM (ML-KEM-1024) key. */
    async kemKey(address: string): Promise<KemKey> {
      const { status, body } = await get<{ found?: boolean; key?: Record<string, unknown> | null }>(`/qorechain/pqc/v1/kem/${toQor(address)}`);
      if (status === 501 || (status === 404 && body.found === undefined)) {
        throw new RestError("/qorechain/pqc/v1/kem", status, "this network does not serve the KEM key registry");
      }
      if (status >= 400) throw new RestError("/qorechain/pqc/v1/kem", status, `HTTP ${status}`);
      if (body.found !== true || !body.key) return { found: false };
      return {
        found: true,
        algorithmId: Number(body.key.algorithm_id),
        publicKey: b64(body.key.public_key),
        registeredHeight: big(body.key.registered_height),
      };
    },

    /** The account's EVM window (the scoped permission an account needs to send EVM transactions). */
    async evmWindow(address: string): Promise<EvmWindow> {
      const b = await getOk<Record<string, unknown>>(`/qorechain/pqc/v1/evm_window/${toQor(address)}`);
      return {
        found: b.found === true,
        live: b.live === true,
        expiryHeight: big(b.expiry_height),
        maxTxs: big(b.max_txs),
        usedTxs: big(b.used_txs),
        remainingBlocks: big(b.remaining_blocks),
        remainingTxs: big(b.remaining_txs),
        remainingValue: typeof b.remaining_value === "string" ? b.remaining_value : "",
        nativeOnly: b.native_only === true,
        allowedTargets: Array.isArray(b.allowed_targets) ? b.allowed_targets.map(String) : [],
      };
    },

    /** Bank balances as { denom: amount }. */
    async balances(address: string): Promise<Record<string, bigint>> {
      const b = await getOk<{ balances?: { denom: string; amount: string }[] }>(`/cosmos/bank/v1beta1/balances/${toQor(address)}`, {
        "pagination.limit": "200",
      });
      return Object.fromEntries((b.balances ?? []).map((x) => [x.denom, big(x.amount)]));
    },

    /** Account number and sequence; zero for an account the chain has not seen. */
    async accountSequence(address: string): Promise<{ accountNumber: bigint; sequence: bigint }> {
      const { status, body } = await get<{ account?: Record<string, unknown> }>(`/cosmos/auth/v1beta1/accounts/${toQor(address)}`);
      if (status === 404) return { accountNumber: 0n, sequence: 0n };
      if (status >= 400) throw new RestError("/cosmos/auth/v1beta1/accounts", status, `HTTP ${status}`);
      const acc = ((body.account?.base_account as Record<string, unknown> | undefined) ?? body.account ?? {}) as Record<string, unknown>;
      return { accountNumber: big(acc.account_number), sequence: big(acc.sequence) };
    },

    /** Raw abstract-account views (authenticators, spending rules); undefined when the account has none. */
    async abstractAccount(address: string, part: "" | "authenticators" | "spending_rules" = ""): Promise<Record<string, unknown> | undefined> {
      const { status, body } = await get<Record<string, unknown>>(
        `/qorechain/abstractaccount/v1/accounts/${toQor(address)}${part ? `/${part}` : ""}`,
      );
      if (status === 404 || (body as { code?: number }).code === 5) return undefined;
      if (status >= 400) throw new RestError("/qorechain/abstractaccount/v1/accounts", status, `HTTP ${status}`);
      return body;
    },

    /** A committed transaction by hash, or undefined if the chain does not know it. */
    async tx(hash: string): Promise<Record<string, unknown> | undefined> {
      const h = hash.replace(/^0x/, "").toUpperCase();
      const { status, body } = await get<Record<string, unknown>>(`/cosmos/tx/v1beta1/txs/${h}`);
      if (status === 404 || (status >= 400 && (body as { code?: number }).code === 5)) return undefined;
      if (status >= 400) throw new RestError("/cosmos/tx/v1beta1/txs", status, `HTTP ${status}`);
      return body;
    },
  };
}

export type RestClient = ReturnType<typeof createRest>;

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

export interface ProxyOptions {
  /** Upstream REST endpoint. Default the public testnet. */
  upstream?: string;
  /** Path prefix the proxy is mounted at, stripped before matching (for example `/rest`). */
  prefix?: string;
  /** Value of Access-Control-Allow-Origin. Default `*`: the data is public and the proxy is read-only. */
  allowOrigin?: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

function cors(allowOrigin: string): Record<string, string> {
  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-headers": "accept, content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function json(status: number, body: unknown, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "content-type": "application/json", "cache-control": "no-store" } });
}

/**
 * A read-only REST proxy as a fetch handler (`Request` in, `Response` out), for a
 * Worker, Deno, Bun, or Node through `scripts/rest-proxy.ts`. It answers CORS
 * preflights, forwards only GETs to allowlisted routes, forwards no request
 * headers (so no cookies or credentials reach the upstream), and passes only
 * pagination query parameters.
 */
export async function handleRestProxy(request: Request, opts: ProxyOptions = {}): Promise<Response> {
  const headers = cors(opts.allowOrigin ?? "*");
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (request.method !== "GET") return json(405, { error: "read-only proxy: GET only" }, headers);
  const url = new URL(request.url);
  let path = url.pathname;
  const prefix = (opts.prefix ?? "").replace(/\/+$/, "");
  if (prefix) {
    if (path !== prefix && !path.startsWith(`${prefix}/`)) return json(404, { error: "not found" }, headers);
    path = path.slice(prefix.length) || "/";
  }
  if (!isAllowedRoute(path)) return json(403, { error: `route not allowed: ${path}` }, headers);
  const q = new URLSearchParams();
  for (const [k, v] of url.searchParams) if (ALLOWED_QUERY.has(k)) q.append(k, v);
  const upstream = (opts.upstream ?? DEFAULT_REST).replace(/\/+$/, "");
  const f = opts.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 15_000);
  try {
    const res = await f(`${upstream}${path}${q.size ? `?${q}` : ""}`, { method: "GET", signal: ctrl.signal, headers: { accept: "application/json" } });
    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: { ...headers, "content-type": res.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
    });
  } catch (e) {
    return json(502, { error: `upstream unavailable: ${e instanceof Error ? e.message : String(e)}` }, headers);
  } finally {
    clearTimeout(timer);
  }
}
