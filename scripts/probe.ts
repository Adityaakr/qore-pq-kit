/**
 * probe.ts - live probes of the post-quantum precompiles and of PqAuth.sol.
 *
 * Read-only: every check is an eth_call, nothing is sent and no window is
 * needed. The PqAuth checks run the library's compiled code by sending the
 * creation code of `test/live/PqAuthProbe.sol` in an eth_call, so the real
 * precompiles are exercised by the real library without a deployment.
 *
 * Needs `forge build` in kit/ first (for the probe's bytecode).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pqcSign } from "@qorechain/sdk";
import {
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  toBytes,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { PQC_KEY_STATUS, PQC_VERIFY, loadAccount, publicClient } from "./qore.ts";
import { actionId, authMessage } from "./pqauth.ts";

const here = dirname(fileURLToPath(import.meta.url));

function probeBytecode(): Hex {
  const art = JSON.parse(readFileSync(join(here, "..", "out", "PqAuthProbe.sol", "PqAuthProbe.json"), "utf8"));
  return art.bytecode.object as Hex;
}

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

const VERIFY_ABI = [
  {
    type: "function",
    name: "pqcVerify",
    stateMutability: "view",
    inputs: [
      { name: "pubkey", type: "bytes" },
      { name: "signature", type: "bytes" },
      { name: "message", type: "bytes" },
    ],
    outputs: [{ name: "valid", type: "bool" }],
  },
] as const;

interface Row {
  check: string;
  expected: string;
  got: string;
  pass: boolean;
}

export async function probe(name = "drill"): Promise<boolean> {
  const client = publicClient();
  const acc = await loadAccount(name);
  const account = acc.evm as Address;
  const rows: Row[] = [];
  const add = (check: string, expected: string, got: string) => rows.push({ check, expected, got, pass: expected === got });

  // 1. pqcKeyStatus directly.
  const [registered, alg, pubkey, proven] = await client.readContract({
    address: PQC_KEY_STATUS,
    abi: KEY_STATUS_ABI,
    functionName: "pqcKeyStatus",
    args: [account],
  });
  add("pqcKeyStatus(drill).registered", "true", String(registered));
  add("pqcKeyStatus(drill).algorithmId", "1", String(alg));
  add("pqcKeyStatus(drill).possessionProven", "true", String(proven));
  add("pqcKeyStatus(drill).pubkey == local key", "true", String(pubkey.toLowerCase() === toHex(acc.pqc.publicKey)));

  const fresh = "0x000000000000000000000000000000000000dEaD" as Address;
  const rawEmpty = await client.call({
    to: PQC_KEY_STATUS,
    data: encodeFunctionData({ abi: KEY_STATUS_ABI, functionName: "pqcKeyStatus", args: [fresh] }),
  });
  add("pqcKeyStatus(no key) return length", "160", String(((rawEmpty.data?.length ?? 2) - 2) / 2));

  // 2. pqcVerify directly over a PqAuth message.
  const block = await client.getBlock();
  const fields = {
    chainId: 9800n,
    verifier: "0x00000000000000000000000000000000000000aa" as Address,
    signer: account,
    action: actionId("probe"),
    nonce: 0n,
    deadline: block.timestamp + 3600n,
    argsHash: keccak256(toBytes("probe args")),
  };
  const message = authMessage(fields);
  const sig = toHex(pqcSign(acc.pqc.secretKey, toBytes(message)));
  const verify = (pk: Hex, s: Hex, m: Hex) =>
    client.readContract({ address: PQC_VERIFY, abi: VERIFY_ABI, functionName: "pqcVerify", args: [pk, s, m] });
  add("pqcVerify(valid)", "true", String(await verify(pubkey, sig, message)));
  const tampered = (sig.slice(0, 100) + (sig[100] === "0" ? "1" : "0") + sig.slice(101)) as Hex;
  add("pqcVerify(one signature nibble changed)", "false", String(await verify(pubkey, tampered, message)));
  const otherMessage = authMessage({ ...fields, nonce: 1n });
  add("pqcVerify(different nonce in message)", "false", String(await verify(pubkey, sig, otherMessage)));
  const gas = await client.estimateGas({
    account: fresh,
    to: PQC_VERIFY,
    data: encodeFunctionData({ abi: VERIFY_ABI, functionName: "pqcVerify", args: [pubkey, sig, message] }),
  });
  rows.push({ check: "pqcVerify estimateGas (whole tx, incl. calldata)", expected: "-", got: String(gas), pass: true });

  // 3. An inactive precompile answers success with empty data.
  const inactive = await client.call({ to: "0x0000000000000000000000000000000000000b01", data: "0x12345678" });
  add("inactive precompile 0x…0B01 return data", "empty", inactive.data && inactive.data !== "0x" ? inactive.data : "empty");

  // 4. PqAuth.sol itself, through the probe's creation code.
  const bytecode = probeBytecode();
  const runProbe = async (who: Address, s: Hex, m: Hex) => {
    const args = encodeAbiParameters([{ type: "address" }, { type: "bytes" }, { type: "bytes" }], [who, s, m]);
    try {
      const res = await client.call({ data: (bytecode + args.slice(2)) as Hex });
      const [keyHash, keyLen, valid, chainId] = decodeAbiParameters(
        [{ type: "bytes32" }, { type: "uint256" }, { type: "bool" }, { type: "uint256" }],
        res.data as Hex,
      );
      return { ok: true as const, keyHash, keyLen, valid, chainId };
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err);
      return { ok: false as const, error: text.split("\n")[0] };
    }
  };
  const good = await runProbe(account, sig, message);
  add("PqAuth.keyOf + verify (valid)", "valid=true", good.ok ? `valid=${good.valid}` : `revert: ${good.error}`);
  if (good.ok) {
    add("PqAuth.keyOf length", "2592", String(good.keyLen));
    add("PqAuth.keyOf hash == local key hash", "true", String(good.keyHash === keccak256(acc.pqc.publicKey)));
    add("block.chainid seen by PqAuth", "9800", String(good.chainId));
  }
  const bad = await runProbe(account, tampered, message);
  add("PqAuth.verify (tampered)", "valid=false", bad.ok ? `valid=${bad.valid}` : `revert: ${bad.error}`);
  const noKey = await runProbe(fresh, sig, message);
  add("PqAuth.keyOf (account without key)", "revert", noKey.ok ? "returned" : "revert");

  for (const r of rows) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.check}: expected ${r.expected}, got ${r.got}`);
  const allPass = rows.every((r) => r.pass);
  console.log(allPass ? "all live probes passed" : "SOME LIVE PROBES FAILED");
  return allPass;
}
