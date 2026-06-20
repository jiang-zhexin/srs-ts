import { decodeVarint32, encodeVarint } from "@std/encoding";
import type { Bytes } from "./types.ts";

const decoder = new TextDecoder("utf-8");
const encoder = new TextEncoder();

export function encodeUint64(
  num: bigint,
  buf?: Bytes,
  offset: number = 0,
): [Bytes, number] {
  if (buf === undefined) buf = new Uint8Array(8);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  view.setBigUint64(offset, num);
  offset += 8;
  return [buf, offset];
}

export async function writeByte(
  w: WritableStreamDefaultWriter<BufferSource>,
  byte: number,
): Promise<void> {
  await w.write(new Uint8Array([byte]));
}

export async function writeVarint(
  w: WritableStreamDefaultWriter<BufferSource>,
  num: number,
): Promise<void> {
  const [buf] = encodeVarint(num);
  await w.write(buf);
}

export function readStringArray(
  buf: Uint8Array,
  offset: number = 0,
): [string[], number] {
  const [length, o] = decodeVarint32(buf, offset);
  offset = o;
  const result: string[] = [];
  for (let i = 0; i < length; i++) {
    const [l, o] = decodeVarint32(buf, offset);
    offset = o;
    result.push(decoder.decode(buf.subarray(offset, offset + l)));
    offset += l;
  }
  return [result, offset];
}

export async function writeStringArray(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: string[],
): Promise<void> {
  await writeVarint(w, value.length);

  for (const v of value) {
    const stringBuf = encoder.encode(v);
    const [lenBuf] = encodeVarint(stringBuf.length);
    await w.write(lenBuf);
    await w.write(stringBuf);
  }
}

export function readUint8Array(
  buf: Uint8Array,
  offset: number = 0,
): [Uint8Array, number] {
  const [length, o] = decodeVarint32(buf, offset);
  offset = o;
  const result = new Uint8Array(length);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < length; i++) {
    result[i] = view.getUint8(offset);
    offset += 1;
  }
  return [result, offset];
}

export async function writeUint8Array(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: number[] | Uint8Array,
) {
  await writeVarint(w, value.length);

  const buf = new Uint8Array(value.length);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;
  for (const v of value) {
    view.setUint8(offset, v);
    offset += 1;
  }
  await w.write(buf);
}

export function readUint16Array(
  buf: Uint8Array,
  offset: number = 0,
): [Uint16Array, number] {
  const [length, o] = decodeVarint32(buf, offset);
  offset = o;
  const result = new Uint16Array(length);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < length; i++) {
    result[i] = view.getUint16(offset);
    offset += 2;
  }
  return [result, offset];
}

export async function writeUint16Array(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: number[] | Uint16Array,
): Promise<void> {
  await writeVarint(w, value.length);

  const buf = new Uint8Array(value.length * 2);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;
  for (const v of value) {
    view.setUint16(offset, v);
    offset += 2;
  }
  await w.write(buf);
}

export function readUint64Array(
  buf: Uint8Array,
  offset: number = 0,
): [BigUint64Array, number] {
  const [length, o] = decodeVarint32(buf, offset);
  offset = o;
  const result = new BigUint64Array(length);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < length; i++) {
    result[i] = view.getBigUint64(offset);
    offset += 8;
  }
  return [result, offset];
}

export async function writeUint64Array(
  w: WritableStreamDefaultWriter<BufferSource>,
  value: BigUint64Array,
): Promise<void> {
  await writeVarint(w, value.length);

  const buf = new Uint8Array(value.length * 8);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = 0;
  for (const v of value) {
    view.setBigUint64(offset, v);
    offset += 8;
  }
  await w.write(buf);
}

enum InterfaceType {
  wifi = 0,
  cellular,
  ethernet,
  other,
}

export function interfaceTypeToString(i: number): keyof typeof InterfaceType {
  const v = InterfaceType[i] as keyof typeof InterfaceType;
  if (v === undefined) throw new Error(`unknown interface type: ${i}`);
  return v;
}

export function stringToInterfaceType(str: string): InterfaceType {
  const v = InterfaceType[str as keyof typeof InterfaceType];
  if (v === undefined) throw new Error(`unknown interface type: ${str}`);
  return v;
}

export enum DNSType {
  A = 1,
  NS = 2,
  MD = 3,
  MF = 4,
  CNAME = 5,
  SOA = 6,
  MB = 7,
  MG = 8,
  MR = 9,
  NULL = 10,
  WKS = 11,
  PTR = 12,
  HINFO = 13,
  MINFO = 14,
  MX = 15,
  TXT = 16,
  RP = 17,
  AFSDB = 18,
  X25 = 19,
  ISDN = 20,
  RT = 21,
  "NSAP-PTR" = 23,
  SIG = 24,
  KEY = 25,
  PX = 26,
  GPOS = 27,
  AAAA = 28,
  LOC = 29,
  NXT = 30,
  EID = 31,
  NIMLOC = 32,
  SRV = 33,
  ATMA = 34,
  NAPTR = 35,
  KX = 36,
  CERT = 37,
  A6 = 38,
  DNAME = 39,
  SINK = 40,
  OPT = 41,
  APL = 42,
  DS = 43,
  SSHFP = 44,
  IPSECKEY = 45,
  RRSIG = 46,
  NSEC = 47,
  DNSKEY = 48,
  DHCID = 49,
  NSEC3 = 50,
  NSEC3PARAM = 51,
  TLSA = 52,
  SMIMEA = 53,
  HIP = 55,
  NINFO = 56,
  RKEY = 57,
  TALINK = 58,
  CDS = 59,
  CDNSKEY = 60,
  OPENPGPKEY = 61,
  CSYNC = 62,
  ZONEMD = 63,
  SVCB = 64,
  HTTPS = 65,
  SPF = 99,
  UINFO = 100,
  UID = 101,
  GID = 102,
  UNSPEC = 103,
  NID = 104,
  L32 = 105,
  L64 = 106,
  LP = 107,
  EUI48 = 108,
  EUI64 = 109,
  NXNAME = 128,
  AMTRELAY = 256,
  CAA = 257,
  AVC = 258,
  RESINFO = 261,
  TA = 32768,
  DLV = 32769,

  MAILB = 253,
  MAILA = 254,
  ANY = 255,
  None = 0,
  Reserved = 65535,
}

export function dnsTypeToString(type: DNSType | number): string {
  const name = DNSType[type];
  return name !== undefined ? name : `${type}`;
}

export function stringToDnsType(typeStr: string): DNSType {
  const v = DNSType[typeStr as keyof typeof DNSType];
  if (v === undefined) throw new Error(`unknown DNS query type: ${typeStr}`);
  return v;
}
