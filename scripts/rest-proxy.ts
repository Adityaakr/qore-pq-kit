/**
 * rest-proxy.ts - run the read-only REST proxy (`handleRestProxy` in rest.ts)
 * on localhost, for a web page under development.
 *
 *   npx tsx scripts/rest-proxy.ts [port]      # default 8787, upstream QORE_REST_URL or the public testnet
 *
 * A page then reads `http://127.0.0.1:8787/qorechain/pqc/v1/kem/<address>`.
 * It binds to 127.0.0.1 only.
 */
import { createServer } from "node:http";
import { DEFAULT_REST, handleRestProxy } from "./rest.ts";

const port = Number(process.argv[2] ?? 8787);
const upstream = process.env.QORE_REST_URL?.trim() || DEFAULT_REST;

createServer(async (req, res) => {
  const request = new Request(`http://127.0.0.1:${port}${req.url ?? "/"}`, { method: req.method });
  const response = await handleRestProxy(request, { upstream });
  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => (headers[k] = v));
  res.writeHead(response.status, headers);
  res.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, "127.0.0.1", () => console.log(`read-only REST proxy on http://127.0.0.1:${port} -> ${upstream}`));
