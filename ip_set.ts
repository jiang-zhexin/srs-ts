import { decodeVarint32 } from "@std/encoding";
import { Address, AddressPrefix } from "./netip.ts";
import { encodeUint64, writeByte, writeVarint } from "./utils.ts";

export function readIPSet(
  buf: Uint8Array,
  offset: number = 0,
): [AddressPrefix[], number] {
  const version = buf[offset++];
  if (version !== 1) throw new Error(`unknown version: ${version}`);

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const length = view.getBigUint64(offset);
  offset += 8;

  const mySet: AddressPrefix[] = [];

  for (let i = BigInt(0); i < length; i++) {
    const [fromLen, of] = decodeVarint32(buf, offset);
    offset = of;
    const fromBytes = buf.slice(offset, offset + fromLen);
    offset += fromLen;

    const [toLen, ot] = decodeVarint32(buf, offset);
    offset = ot;
    const toBytes = buf.slice(offset, offset + toLen);
    offset += toLen;

    const from = fromLen === 4
      ? Address.fromIPv4Bytes(fromBytes)
      : Address.fromIPv6Bytes(fromBytes);

    const prefix = getCommonBitPrefixLength(fromBytes, toBytes);
    const cidr = AddressPrefix.from(from, prefix);

    mySet.push(cidr);
  }
  return [mySet, offset];
}

export async function writeIPSet(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: AddressPrefix[],
): Promise<void> {
  await writeByte(w, 1);

  const [buf] = encodeUint64(BigInt(value.length));
  await w.write(buf);

  for (const prefix of value) {
    const { from, to } = prefix.getRanges();
    const fromBytes = Address.parseAddress(from).marshalBinary();
    const toBytes = Address.parseAddress(to).marshalBinary();

    await writeVarint(w, fromBytes.length);
    await w.write(fromBytes);

    await writeVarint(w, toBytes.length);
    await w.write(toBytes);
  }
}

function getCommonBitPrefixLength(buf1: Uint8Array, buf2: Uint8Array): number {
  const minLength = Math.min(buf1.length, buf2.length);
  for (let i = 0; i < minLength; i++) {
    if (buf1[i] === buf2[i]) continue;

    const diff = buf1[i] ^ buf2[i];
    const commonBitsInByte = Math.clz32(diff) - 24;

    return i * 8 + commonBitsInByte;
  }
  return minLength * 8;
}
