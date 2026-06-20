import { decodeVarint32 } from "@std/encoding";
import { Address, AddressPrefix } from "./netip.ts";
import { writeVarint } from "./utils.ts";

export function readPrefix(
  buf: Uint8Array,
  offset: number = 0,
): [AddressPrefix, number] {
  const [addrLen, o] = decodeVarint32(buf, offset);
  offset = o;
  const addrSlice = buf.slice(offset, offset + addrLen);
  offset += addrLen;

  const prefix = buf[offset++];

  const ip = addrLen == 4
    ? Address.fromIPv4Bytes(addrSlice)
    : Address.fromIPv6Bytes(addrSlice);

  const cidr = AddressPrefix.from(ip, prefix);

  return [cidr, offset];
}

export async function writePrefix(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: AddressPrefix,
): Promise<void> {
  const bytes = value.marshalBinary();
  await writeVarint(w, bytes.length - 1);
  await w.write(bytes);
}
