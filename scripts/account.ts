/**
 * account.ts - create a fresh account and report its state.
 *
 * `newAccount` makes a new BIP-39 mnemonic. The classical secp256k1 key comes
 * from it on the Ethereum path m/44'/60'/0'/0/0; the ML-DSA-87 key comes from
 * shake256("qorechain:pqc:v1|" ‖ qor1-address ‖ "|" ‖ mnemonic) inside the SDK,
 * so it cannot be computed from the classical private key. Handing the raw
 * classical key to someone (the Q-Day Drill does exactly that) gives them no
 * way to produce the post-quantum half of a signature.
 */
import { deriveUnifiedAccount, fetchPqcStatus, generateMnemonic, isRegisteredPqcKey } from "@qorechain/sdk";
import { fetchEvmWindow } from "@qorechain/sdk";
import { writeSecrets, secretsPath } from "./secrets.ts";
import { balances, loadAccount, network, publicClient, qor } from "./qore.ts";

export async function newAccount(name = "drill"): Promise<void> {
  const path = secretsPath(name);
  const mnemonic = generateMnemonic(256);
  const acc = await deriveUnifiedAccount(mnemonic, 0);
  writeSecrets(
    path,
    {
      QORE_MNEMONIC: mnemonic,
      PRIVATE_KEY: acc.privateKey,
      EVM_ADDRESS: acc.evm,
      QOR_ADDRESS: acc.cosmos,
    },
    [
      `QoreChain testnet account "${name}", created ${new Date().toISOString()}.`,
      "QORE_MNEMONIC restores both keys. PRIVATE_KEY is the classical secp256k1 key only;",
      "the ML-DSA-87 key cannot be derived from it. Never commit this file.",
    ].join("\n"),
  );
  console.log(`created ${path} (mode 0600)`);
  console.log(`evm address: ${acc.evm}`);
  console.log(`qor address: ${acc.cosmos}`);
}

export async function status(name = "drill"): Promise<void> {
  const net = network();
  const acc = await loadAccount(name);
  console.log(`account:  ${acc.evm}  (${acc.cosmos})`);
  const bal = await balances(acc.cosmos);
  const entries = Object.entries(bal);
  console.log(
    `native:   ${entries.length === 0 ? "empty" : entries.map(([d, a]) => (d === "uqor" ? qor(a) : `${a} ${d}`)).join(", ")}`,
  );
  const evmBalance = await publicClient().getBalance({ address: acc.evm as `0x${string}` });
  console.log(`evm:      ${evmBalance} wei`);
  const pqc = await fetchPqcStatus({ rest: net.rest, address: acc.cosmos });
  const mine = pqc.registered ? isRegisteredPqcKey(pqc, acc.pqc.publicKey) : false;
  console.log(`PQC key:  ${pqc.registered ? (mine === false ? "registered, but NOT this key" : "registered, this key") : "not registered"}`);
  const w = await fetchEvmWindow({ rest: net.rest, address: acc.cosmos });
  if (!w.found) {
    console.log("window:   none");
  } else {
    console.log(
      `window:   ${w.live ? "LIVE" : "not usable"}; ${w.remainingBlocks} blocks, ${w.remainingTxs} txs, ${w.remainingValue} uqor left` +
        `${w.nativeOnly ? ", native transfers only" : ""}${w.allowedTargets?.length ? `, targets ${w.allowedTargets.join(" ")}` : ", any target"}`,
    );
  }
}
