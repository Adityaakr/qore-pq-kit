/**
 * cli.ts - the kit's command line: `npm run pq -- <command> [args]`.
 */
import { newAccount, status } from "./account.ts";
import { register } from "./register.ts";
import { probe } from "./probe.ts";
import { rehearse } from "./rehearse.ts";
import { convertTo, swapQorFor } from "./fest.ts";
import { FUSD_DENOM } from "./qore.ts";
import { closeWindow, openWindow } from "./window.ts";

const commands: Record<string, (...args: string[]) => Promise<void>> = {
  "new-account": (name?: string) => newAccount(name),
  status: (name?: string) => status(name),
  register: (name?: string) => register(name),
  // rehearse <account> [vault] [token]
  rehearse: async (name?: string, vault?: string, token?: string) => {
    if (!(await rehearse(name, vault, token))) process.exitCode = 1;
  },
  probe: async (name?: string) => {
    if (!(await probe(name))) process.exitCode = 1;
  },
  // open-window <name> <blocks> <maxTxs> <gasPerTx> [target,target,...]
  "open-window": async (name = "drill", blocks = "300", maxTxs = "3", gas = "3000000", targets = "") => {
    await openWindow(name, {
      blocks: Number(blocks),
      maxTxs: Number(maxTxs),
      gasPerTx: BigInt(gas),
      targets: targets ? targets.split(",") : [],
    });
  },
  // swap-fusd <account> <uqorIn> <minOutBaseUnits>   (testnet AMM pool 2: fUSD/QOR)
  "swap-fusd": async (name = "drill", uqor = "0", minOut = "0") => {
    await swapQorFor(name, "2", BigInt(uqor), FUSD_DENOM, BigInt(minOut));
  },
  // convert-fusd <account> <receiver0x> [amount]   (bank fUSD -> ERC-20 held by receiver)
  "convert-fusd": async (name = "drill", to = "", amount?: string) => {
    await convertTo(name, to, FUSD_DENOM, amount ? BigInt(amount) : undefined);
  },
  "close-window": async (name = "drill") => {
    await closeWindow(name);
  },
};

const [cmd = "status", ...args] = process.argv.slice(2);
const run = commands[cmd];
if (!run) {
  console.error(`Unknown command "${cmd}". Commands: ${Object.keys(commands).join(", ")}`);
  process.exit(1);
}
run(...args).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
