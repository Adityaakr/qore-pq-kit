/**
 * fund.ts - split test QOR from one account (a "bank" that received the
 * faucet) to the service accounts an app needs: committee members, agents,
 * relayers. A hybrid-signed native `MsgSend`, nothing else.
 *
 * Guards: the amount is capped, and the sender must keep a floor for its own
 * fees, so a typo cannot empty an account.
 */
import type { EncodeObject } from "@cosmjs/proto-signing";
import { broadcast, balances, loadAccount, NATIVE_FEE, qor } from "./qore.ts";
import { toQor } from "./rest.ts";

/** Largest single transfer `fund` makes, in uqor (50 QOR). */
export const FUND_MAX_UQOR = 50_000_000n;
/** What the sender keeps by default, in uqor (1 QOR). */
export const FUND_FLOOR_UQOR = 1_000_000n;

/** Parse "1.5" (QOR) into uqor, exactly. */
export function parseQor(text: string): bigint {
  const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(text.trim());
  if (!m) throw new Error(`not a QOR amount: ${text} (up to 6 decimals)`);
  return BigInt(m[1]!) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0") || "0");
}

export function fundMsg(from: string, to: string, uqor: bigint): EncodeObject {
  return {
    typeUrl: "/cosmos.bank.v1beta1.MsgSend",
    value: { fromAddress: from, toAddress: to, amount: [{ denom: "uqor", amount: uqor.toString() }] },
  };
}

/** Throws unless the transfer is positive, at most the cap, and leaves the sender its floor after the fee. */
export function checkFund(balanceUqor: bigint, amountUqor: bigint, floorUqor = FUND_FLOOR_UQOR, feeUqor = BigInt(NATIVE_FEE.amount[0]!.amount)): void {
  if (amountUqor <= 0n) throw new Error("amount must be positive");
  if (amountUqor > FUND_MAX_UQOR) throw new Error(`amount ${qor(amountUqor)} is above the ${qor(FUND_MAX_UQOR)} cap`);
  const left = balanceUqor - amountUqor - feeUqor;
  if (left < floorUqor) throw new Error(`would leave ${qor(left < 0n ? 0n : left)}, below the ${qor(floorUqor)} floor (balance ${qor(balanceUqor)})`);
}

/** Send `amount` QOR from the named account to an address (`qor1…` or `0x…`) or another named account. */
export async function fund(fromName: string, to: string, amount: string, floor = FUND_FLOOR_UQOR): Promise<string> {
  const from = await loadAccount(fromName);
  const toAddr = /^(qor1|0x)/i.test(to) ? toQor(to) : (await loadAccount(to)).cosmos;
  if (toAddr === from.cosmos) throw new Error("sender and recipient are the same account");
  const uqor = parseQor(amount);
  checkFund((await balances(from.cosmos)).uqor ?? 0n, uqor, floor);
  const res = await broadcast(from, [fundMsg(from.cosmos, toAddr, uqor)]);
  console.log(`sent ${qor(uqor)} from ${from.cosmos} to ${toAddr}: tx ${res.transactionHash}`);
  return res.transactionHash;
}
