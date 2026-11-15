/**
 * fest.ts - the builder-fest test tokens (fUSD, fETH, fBTC) on the testnet.
 *
 * The faucet pays them as BANK coins (`erc20:0x…` denominations). A contract
 * sees them only after `MsgConvertCoin` turns the bank coin into the ERC-20
 * form, and the receiver of that conversion can be any 0x address, including
 * a contract. Converting straight into a vault means the plain account never
 * holds the ERC-20 and never has to approve anyone: there is no allowance for
 * a stolen classical key to spend.
 *
 * The SDK has no builder for MsgConvertCoin, so it is encoded here by hand
 * (cosmos.evm.erc20.v1.MsgConvertCoin: coin = 1, receiver = 2, sender = 3).
 */
import { Registry, type EncodeObject, type GeneratedType } from "@cosmjs/proto-signing";
import { BinaryReader, BinaryWriter } from "cosmjs-types/binary";
import { Coin } from "cosmjs-types/cosmos/base/v1beta1/coin";
import { msg as sdkMsg, qorechainRegistryTypes } from "@qorechain/sdk";
import { balances, broadcast, loadAccount, FUSD_DENOM, NATIVE_FEE } from "./qore.ts";

export const MSG_CONVERT_COIN_TYPE_URL = "/cosmos.evm.erc20.v1.MsgConvertCoin";

interface MsgConvertCoin {
  coin?: Coin;
  receiver: string;
  sender: string;
}

const MsgConvertCoinCodec: GeneratedType = {
  encode(m: MsgConvertCoin, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (m.coin) Coin.encode(m.coin, writer.uint32(10).fork()).ldelim();
    if (m.receiver) writer.uint32(18).string(m.receiver);
    if (m.sender) writer.uint32(26).string(m.sender);
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgConvertCoin {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    const end = length === undefined ? reader.len : reader.pos + length;
    const m: MsgConvertCoin = { receiver: "", sender: "" };
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          m.coin = Coin.decode(reader, reader.uint32());
          break;
        case 2:
          m.receiver = reader.string();
          break;
        case 3:
          m.sender = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
      }
    }
    return m;
  },
  fromPartial(o: Partial<MsgConvertCoin>): MsgConvertCoin {
    return { coin: o.coin ? Coin.fromPartial(o.coin) : undefined, receiver: o.receiver ?? "", sender: o.sender ?? "" };
  },
} as unknown as GeneratedType;

/** The SDK's registry plus MsgConvertCoin. */
export function festRegistry(): Registry {
  const r = new Registry(qorechainRegistryTypes as Iterable<[string, GeneratedType]>);
  r.register(MSG_CONVERT_COIN_TYPE_URL, MsgConvertCoinCodec);
  return r;
}

export function convertCoinMsg(sender: string, denom: string, amount: bigint, receiver0x: string): EncodeObject {
  return {
    typeUrl: MSG_CONVERT_COIN_TYPE_URL,
    value: { coin: { denom, amount: amount.toString() }, receiver: receiver0x, sender },
  };
}

/** Convert `amount` (default: all) of a fest bank coin into its ERC-20 form held by `receiver0x`. */
export async function convertTo(name: string, receiver0x: string, denom = FUSD_DENOM, amount?: bigint): Promise<string> {
  const acc = await loadAccount(name);
  const have = (await balances(acc.cosmos))[denom] ?? 0n;
  const amt = amount ?? have;
  if (amt === 0n || amt > have) throw new Error(`${acc.cosmos} holds ${have} ${denom}; cannot convert ${amt}`);
  const res = await broadcast(acc, [convertCoinMsg(acc.cosmos, denom, amt, receiver0x)], "hybrid", NATIVE_FEE, festRegistry());
  console.log(`converted ${amt} ${denom} to ERC-20 at ${receiver0x}: tx ${res.transactionHash}`);
  return res.transactionHash;
}

/** Swap native QOR for a fest token on the testnet AMM (constant-product pool). */
export async function swapQorFor(name: string, poolId: string, uqorIn: bigint, denomOut: string, minOut: bigint): Promise<string> {
  const acc = await loadAccount(name);
  const m = sdkMsg.amm.swapExactIn({
    sender: acc.cosmos,
    poolId,
    tokenIn: { denom: "uqor", amount: uqorIn.toString() },
    denomOut,
    minOut: minOut.toString(),
  });
  const res = await broadcast(acc, [m]);
  console.log(`swapped ${uqorIn} uqor in pool ${poolId}: tx ${res.transactionHash}`);
  return res.transactionHash;
}
