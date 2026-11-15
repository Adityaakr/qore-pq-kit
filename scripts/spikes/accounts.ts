/**
 * spikes/accounts.ts - throwaway testnet accounts for the spikes.
 *
 * Each account is a fresh BIP-39 mnemonic in ~/.qore-pq-kit/spikes/<name>.env
 * (directory 0700, file 0600), never inside the repository. This prints
 * addresses only, never a mnemonic or key. These are NOT the drill accounts and
 * must never be used for the drill.
 *
 *   npx tsx scripts/spikes/accounts.ts new <name>...
 *   npx tsx scripts/spikes/accounts.ts show <name>...
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { deriveUnifiedAccount, generateMnemonic, type UnifiedAccount } from "@qorechain/sdk";

export const SPIKE_SECRETS_DIR = process.env.QORE_PQ_KIT_SECRETS?.trim() || join(homedir(), ".qore-pq-kit", "spikes");

function pathOf(name: string): string {
  if (!/^[a-z0-9-]{1,32}$/.test(name)) throw new Error(`bad account name ${name}`);
  return join(SPIKE_SECRETS_DIR, `${name}.env`);
}

export function createSpikeAccount(name: string): Promise<UnifiedAccount> {
  const path = pathOf(name);
  if (existsSync(path)) throw new Error(`refusing to overwrite ${path}`);
  mkdirSync(SPIKE_SECRETS_DIR, { recursive: true, mode: 0o700 });
  chmodSync(SPIKE_SECRETS_DIR, 0o700);
  const mnemonic = generateMnemonic(256);
  writeFileSync(
    path,
    `# qore-pq-kit spike account "${name}", created ${new Date().toISOString()}. Testnet only. Never commit.\nQORE_MNEMONIC="${mnemonic}"\n`,
    { mode: 0o600, flag: "wx" },
  );
  chmodSync(path, 0o600);
  return deriveUnifiedAccount(mnemonic, 0);
}

export function loadSpikeAccount(name: string): Promise<UnifiedAccount> {
  const path = pathOf(name);
  if (!existsSync(path)) throw new Error(`no spike account ${name} (create it: npx tsx scripts/spikes/accounts.ts new ${name})`);
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`${path} has mode ${mode.toString(8)}; run chmod 600 on it`);
  const m = /QORE_MNEMONIC="([^"]+)"/.exec(readFileSync(path, "utf8"));
  if (!m) throw new Error(`QORE_MNEMONIC missing in ${path}`);
  return deriveUnifiedAccount(m[1]!, 0);
}

async function main(): Promise<void> {
  const [cmd, ...names] = process.argv.slice(2);
  if ((cmd !== "new" && cmd !== "show") || names.length === 0) {
    throw new Error("usage: accounts.ts new|show <name>...");
  }
  for (const name of names) {
    const acc = cmd === "new" ? await createSpikeAccount(name) : await loadSpikeAccount(name);
    console.log(`${name.padEnd(12)} ${acc.evm}  ${acc.cosmos}`);
  }
}

if (process.argv[1]?.endsWith("accounts.ts")) {
  main().catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
