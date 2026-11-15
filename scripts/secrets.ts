/**
 * secrets.ts - load and create the account secrets file.
 *
 * The secrets live OUTSIDE the repository, in a file of KEY=value lines with
 * 0600 permissions (default: ~/.qore-drill/<name>.env). Nothing in this kit
 * prints a mnemonic or a private key; scripts print addresses only.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_SECRETS_DIR = join(homedir(), ".qore-drill");

/** Path of a named secrets file, or QORE_SECRETS_FILE when it is set. */
export function secretsPath(name = "drill"): string {
  const override = process.env.QORE_SECRETS_FILE?.trim();
  if (override && name === "drill") return override;
  return join(DEFAULT_SECRETS_DIR, `${name}.env`);
}

/** Parse KEY=value lines (no shell expansion; quotes around the value are removed). */
export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[line.slice(0, eq).trim()] = value;
  }
  return out;
}

/** Read a secrets file, refusing one that other users can read. */
export function loadSecrets(path: string): Record<string, string> {
  if (!existsSync(path)) {
    throw new Error(`secrets file not found: ${path} (create one with: npm run pq -- new-account)`);
  }
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(`secrets file ${path} has mode ${mode.toString(8)}; run chmod 600 on it`);
  }
  return parseEnvFile(readFileSync(path, "utf8"));
}

/** Write a new secrets file with 0600 permissions in a 0700 directory. Never overwrites. */
export function writeSecrets(path: string, entries: Record<string, string>, header: string): void {
  if (existsSync(path)) throw new Error(`refusing to overwrite existing secrets file ${path}`);
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const body =
    header
      .split("\n")
      .map((l) => `# ${l}`)
      .join("\n") +
    "\n" +
    Object.entries(entries)
      .map(([k, v]) => `${k}="${v}"`)
      .join("\n") +
    "\n";
  writeFileSync(path, body, { mode: 0o600, flag: "wx" });
  chmodSync(path, 0o600);
}
