/**
 * threshold-probe.ts - run Shamir.sol and SealedSlot.sol on the live testnet
 * against vectors/threshold.json, without an account, a deployment or gas.
 *
 * The probe contract (test/live/ThresholdProbe.sol) does its work in its
 * constructor and returns the answer, so an `eth_call` with no `to` and its
 * creation code as data executes it on the real chain, with the chain's own
 * modexp precompile, and changes nothing.
 *
 *   forge build && npx tsx scripts/threshold-probe.ts
 *
 * Exits non-zero if any value differs from the vectors.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, decodeAbiParameters, encodeAbiParameters, http, type Hex } from "viem";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rpc = process.env.QORE_EVM_RPC_URL?.trim() || "https://evm-testnet.qore.host";

interface VectorCase {
  name: string;
  chainId: Hex;
  seq: Hex;
  key: Hex;
  ct: Hex;
  plaintext: Hex;
  keyHash: Hex;
  shares: Hex[];
  openingSets: number[][];
}

async function main(): Promise<void> {
  const artifact = JSON.parse(readFileSync(join(root, "out/ThresholdProbe.sol/ThresholdProbe.json"), "utf8"));
  const bytecode = artifact.bytecode.object as Hex;
  const vectors = JSON.parse(readFileSync(join(root, "vectors/threshold.json"), "utf8")) as { cases: VectorCase[] };
  const client = createPublicClient({ transport: http(rpc) });
  const chainId = BigInt(await client.getChainId());
  console.log(`rpc ${rpc}, chain id ${chainId}, block ${await client.getBlockNumber()}`);
  let failures = 0;
  for (const c of vectors.cases.filter((v) => BigInt(v.chainId) === chainId)) {
    const set = c.openingSets[c.openingSets.length - 1]!;
    const args = encodeAbiParameters(
      [{ type: "uint256[]" }, { type: "uint256[]" }, { type: "bytes32" }, { type: "uint256" }],
      [set.map(BigInt), set.map((i) => BigInt(c.shares[i - 1]!)), c.ct, BigInt(c.seq)],
    );
    const res = await client.call({ data: `${bytecode}${args.slice(2)}` as Hex });
    const [cid, key, keyHash, pt, gas] = decodeAbiParameters(
      [{ type: "uint256" }, { type: "uint256" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }],
      res.data!,
    );
    const ok = cid === chainId && key === BigInt(c.key) && keyHash === c.keyHash && pt === c.plaintext;
    if (!ok) failures++;
    console.log(`${ok ? "ok  " : "FAIL"} ${c.name}: shares ${set.join(",")} -> key ${ok ? "matches" : "DIFFERS"}, combineAtZero ${gas} gas`);
  }
  if (failures) {
    console.error(`${failures} case(s) differ from the vectors`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
