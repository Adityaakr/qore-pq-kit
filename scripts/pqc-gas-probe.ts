/**
 * pqc-gas-probe.ts - spike S6: what `pqcVerify` costs on the live testnet, and
 * how it answers valid, invalid and malformed input. Read-only: one `eth_call`
 * per case with the creation code of test/live/StaticcallGasProbe.sol, so no
 * account, deployment or gas is needed. The key is a throwaway made from a
 * random seed for this run and is never registered or stored.
 *
 *   forge build && npx tsx scripts/pqc-gas-probe.ts
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pqKeyFromSeed, pqSign } from "@qorechain/qoresign";
import {
  bytesToHex,
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  http,
  keccak256,
  toBytes,
  type Address,
  type Hex,
} from "viem";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rpc = process.env.QORE_EVM_RPC_URL?.trim() || "https://evm-testnet.qore.host";
const PQC_VERIFY = "0x0000000000000000000000000000000000000a01" as Address;
const INACTIVE = "0x0000000000000000000000000000000000000a09" as Address;

/** A PqAuth-shaped 256-byte message (eight words), as PqAuth.message builds it. */
function authMessage(len = 256): Uint8Array {
  const words = encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes32" }],
    [keccak256(toBytes("qore-pq-kit.PqAuth.v1")), 9800n, "0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", keccak256(toBytes("Probe.action")), 0n, 2n ** 40n, keccak256(toBytes("args"))],
  );
  const m = toBytes(words);
  if (len === 256) return m;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = m[i % m.length]!;
  return out;
}

async function main(): Promise<void> {
  const artifact = JSON.parse(readFileSync(join(root, "out/StaticcallGasProbe.sol/StaticcallGasProbe.json"), "utf8"));
  const bytecode = artifact.bytecode.object as Hex;
  const client = createPublicClient({ transport: http(rpc) });
  console.log(`rpc ${rpc}, chain id ${await client.getChainId()}, block ${await client.getBlockNumber()}`);

  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const kp = pqKeyFromSeed(seed);
  const other = pqKeyFromSeed(globalThis.crypto.getRandomValues(new Uint8Array(32)));

  const VERIFY_ABI = [
    { type: "function", name: "pqcVerify", stateMutability: "view", inputs: [{ type: "bytes" }, { type: "bytes" }, { type: "bytes" }], outputs: [{ type: "bool" }] },
  ] as const;
  const KEY_STATUS_ABI = [
    { type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] },
  ] as const;

  const probe = async (label: string, target: Address, input: Hex) => {
    const args = encodeAbiParameters([{ type: "address" }, { type: "bytes" }], [target, input]);
    const res = await client.call({ data: `${bytecode}${args.slice(2)}` as Hex, gas: 30_000_000n });
    const [ok, len, word, gas, ret] = decodeAbiParameters(
      [{ type: "bool" }, { type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }],
      res.data!,
    );
    const w = word === 2n ** 256n - 1n ? "-" : word.toString();
    console.log(`${label.padEnd(48)} ok=${ok} returnBytes=${len} word=${w} staticcallGas=${gas}`);
    return ret;
  };
  const run = (label: string, target: Address, pk: Uint8Array, sig: Uint8Array, msg: Uint8Array) =>
    probe(label, target, encodeFunctionData({ abi: VERIFY_ABI, functionName: "pqcVerify", args: [bytesToHex(pk), bytesToHex(sig), bytesToHex(msg)] }));

  for (const len of [32, 256, 1024]) {
    const m = authMessage(len);
    await run(`valid signature, ${len}-byte message`, PQC_VERIFY, kp.publicKey, pqSign(kp.secretKey, m), m);
  }
  const m = authMessage();
  const sig = pqSign(kp.secretKey, m);
  const flipped = new Uint8Array(sig);
  flipped[100]! ^= 1;
  const otherMsg = new Uint8Array(m);
  otherMsg[255]! ^= 1;
  await run("bit-flipped signature", PQC_VERIFY, kp.publicKey, flipped, m);
  await run("other message", PQC_VERIFY, kp.publicKey, sig, otherMsg);
  await run("other key", PQC_VERIFY, other.publicKey, sig, m);
  await run("short key (100 bytes)", PQC_VERIFY, kp.publicKey.slice(0, 100), sig, m);
  await run("short signature (100 bytes)", PQC_VERIFY, kp.publicKey, sig.slice(0, 100), m);
  await run("arguments as (pubkey, message, signature)", PQC_VERIFY, kp.publicKey, m, sig);
  await run("inactive precompile address 0x…0a09", INACTIVE, kp.publicKey, sig, m);

  // pqcKeyStatus for an account that has a key (QoreChain's own rollup creator, public) and one that has none.
  const KNOWN = "0xcd8895b451d2e6d64f6b5cb26d8828954f27ed2e" as Address; // qor1ekyftdz36tndvnmttjexmzpgj48j0mfwk007rp
  for (const [label, who] of [["pqcKeyStatus, account with a key", KNOWN], ["pqcKeyStatus, fresh address (no key)", "0x000000000000000000000000000000000000dEaD"]] as const) {
    const ret = await probe(label, "0x0000000000000000000000000000000000000a02", encodeFunctionData({ abi: KEY_STATUS_ABI, functionName: "pqcKeyStatus", args: [who] }));
    if (ret.length > 2) {
      const [reg, alg, key, pop] = decodeAbiParameters(KEY_STATUS_ABI[0].outputs, ret);
      console.log(`  -> registered=${reg} algorithm=${alg} keyBytes=${(key.length - 2) / 2} fourthWord=${pop}`);
    }
  }

  // Whole-transaction view: what eth_estimateGas says for a direct call (intrinsic + calldata + precompile).
  const data = encodeFunctionData({ abi: VERIFY_ABI, functionName: "pqcVerify", args: [bytesToHex(kp.publicKey), bytesToHex(sig), bytesToHex(m)] });
  try {
    const est = await client.estimateGas({ account: "0x000000000000000000000000000000000000dEaD", to: PQC_VERIFY, data });
    console.log(`eth_estimateGas, direct transaction to pqcVerify (${(data.length - 2) / 2} bytes calldata): ${est}`);
  } catch (e) {
    console.log(`eth_estimateGas refused: ${(e as Error).message.split("\n")[0]}`);
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
