/**
 * @module
 * Native typeScript implementation of encode and decode srs file.
 *
 * @example
 * ```ts
 * import { readSrs, writeSrs } from "@zhexin/srs";
 *
 * const file = await Deno.open("geosite-cn.srs");
 * const ruleSet = await readSrs(file.readable);
 *
 * const output = writeSrs(ruleSet);
 * await Deno.writeFile("output.srs", output);
 * ```
 */

import { equals } from "@std/bytes";
import { decodeVarint32, encodeVarint } from "@std/encoding";
import { ByteSliceStream, concatReadableStreams, toBytes } from "@std/streams";
import { domainMatcherDump, NewMatcher } from "./domain.ts";
import { readPrefix, writePrefix } from "./ip_cidr.ts";
import { readIPSet, writeIPSet } from "./ip_set.ts";
import { AddressPrefix } from "./netip.ts";
import { readSuccinctSet, writeSuccinctSet } from "./succinct.ts";
import type {
  Bytes,
  DefaultRule,
  LogicalRule,
  Network,
  Rule,
  RuleSet,
  Version,
} from "./types.ts";
import {
  interfaceTypeToString,
  readStringArray,
  readUint16Array,
  readUint8Array,
  stringToDnsType,
  stringToInterfaceType,
  writeByte,
  writeStringArray,
  writeUint16Array,
  writeUint8Array,
  writeVarint,
} from "./utils.ts";

const MagicBytes = new Uint8Array([0x53, 0x52, 0x53]);

enum RuleItemType {
  QueryType = 0,
  Network,
  Domain,
  DomainKeyword,
  DomainRegex,
  SourceIPCIDR,
  IPCIDR,
  SourcePort,
  SourcePortRange,
  Port,
  PortRange,
  ProcessName,
  ProcessPath,
  PackageName,
  WIFISSID,
  WIFIBSSID,
  AdGuardDomain,
  ProcessPathRegex,
  NetworkType,
  NetworkIsExpensive,
  NetworkIsConstrained,
  NetworkInterfaceAddress,
  DefaultInterfaceAddress,
  PackageNameRegex,
  Final = 0xFF,
}

export type {
  DefaultRule,
  LogicalRule,
  Rule,
  RuleSet,
  Version,
} from "./types.ts";

/**
 * decode srs
 *
 * @example
 * ```ts
 * const ruleSet = await readSrs(file.readable);
 * ```
 */
export async function readSrs(
  readableStream: ReadableStream<Bytes>,
): Promise<RuleSet> {
  const [r1, r2] = readableStream.tee();
  const header = await toBytes(r1.pipeThrough(new ByteSliceStream(0, 4)));

  const magicBytes = header.slice(0, 3);
  if (!equals(magicBytes, MagicBytes)) {
    throw new Error("invalid sing-box rule-set file");
  }

  const version = header[3];
  if (
    version !== 1 &&
    version !== 2 &&
    version !== 3 &&
    version !== 4 &&
    version !== 5
  ) throw new Error(`unsupported version: ${version}`);

  const compressStream = r2
    .pipeThrough(new ByteSliceStream(4) as TransformStream<Bytes, Bytes>)
    .pipeThrough(new DecompressionStream("deflate"));

  const buf = await toBytes(compressStream);

  let [length, offset] = decodeVarint32(buf);

  const ruleSet: RuleSet = { version: version, rules: [] };
  for (let i = 0; i < length; i++) {
    const [r, o] = readRule(buf, offset);
    offset = o;
    ruleSet.rules.push(r);
  }
  return ruleSet;
}

/**
 * encode srs
 *
 * @example
 * ```ts
 * const stream = writeSrs(ruleSet);
 * ```
 */
export function writeSrs(
  ruleSet: RuleSet,
): ReadableStream<Bytes> {
  const stream = new TransformStream<Bytes, Bytes>();
  const compressionStream = new CompressionStream("deflate");

  (async () => {
    const headWriter = stream.writable.getWriter();
    await headWriter.write(MagicBytes);
    await headWriter.write(new Uint8Array([ruleSet.version]));
    await headWriter.close();

    const writer = compressionStream.writable.getWriter();

    await writeVarint(writer, ruleSet.rules.length);
    for (const rule of ruleSet.rules) {
      await writeRule(writer, rule, ruleSet.version);
    }

    await writer.close();
  })();

  return concatReadableStreams(stream.readable, compressionStream.readable);
}

function readRule(
  buf: Uint8Array,
  offset: number = 0,
): [Rule, number] {
  const ruleType = buf[offset++];
  switch (ruleType) {
    case 0:
      return readDefaultRule(buf, offset);
    case 1:
      return readLogicalRule(buf, offset);
    default:
      throw new Error(`unknown rule type: ${ruleType}`);
  }
}

async function writeRule(
  w: WritableStreamDefaultWriter<BufferSource>,
  rule: Rule,
  version: Version,
): Promise<void> {
  switch (rule.type) {
    case undefined:
    case "default":
      return await writeDefaultRule(w, rule, version);

    case "logical":
      return await writeLogicalRule(w, rule, version);
  }
}

function readDefaultRule(
  buf: Uint8Array,
  offset: number = 0,
): [DefaultRule, number] {
  const rule: DefaultRule = {};
  let lastItemType: RuleItemType = RuleItemType.Final;
  while (true) {
    const itemType = buf[offset++];
    switch (itemType) {
      case RuleItemType.QueryType: {
        const [r, o] = readUint16Array(buf, offset);
        offset = o;
        rule.query_type = [...r];
        break;
      }
      case RuleItemType.Network: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.network = r as Network[];
        break;
      }
      case RuleItemType.Domain: {
        const [r, o] = readSuccinctSet(buf, offset);
        offset = o;
        const [domain, prefix] = domainMatcherDump(r);
        if (domain.length > 0) rule.domain = domain;
        if (prefix.length > 0) rule.domain_suffix = prefix;
        break;
      }
      case RuleItemType.DomainKeyword: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.domain_keyword = r;
        break;
      }
      case RuleItemType.DomainRegex: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.domain_regex = r;
        break;
      }
      case RuleItemType.SourceIPCIDR: {
        const [r, o] = readIPSet(buf, offset);
        offset = o;
        rule.source_ip_cidr = r.map((p) => p.toString());
        break;
      }
      case RuleItemType.IPCIDR: {
        const [r, o] = readIPSet(buf, offset);
        offset = o;
        rule.ip_cidr = r.map((p) => p.toString());
        break;
      }
      case RuleItemType.SourcePort: {
        const [r, o] = readUint16Array(buf, offset);
        offset = o;
        rule.source_port = [...r];
        break;
      }
      case RuleItemType.SourcePortRange: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.source_port_range = r;
        break;
      }
      case RuleItemType.Port: {
        const [r, o] = readUint16Array(buf, offset);
        offset = o;
        rule.port = [...r];
        break;
      }
      case RuleItemType.PortRange: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.port_range = r;
        break;
      }
      case RuleItemType.ProcessName: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.process_name = r;
        break;
      }
      case RuleItemType.ProcessPath: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.process_path = r;
        break;
      }
      case RuleItemType.ProcessPathRegex: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.process_path_regex = r;
        break;
      }
      case RuleItemType.PackageName: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.package_name = r;
        break;
      }
      case RuleItemType.PackageNameRegex: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.package_name_regex = r;
        break;
      }
      case RuleItemType.WIFISSID: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.wifi_ssid = r;
        break;
      }
      case RuleItemType.WIFIBSSID: {
        const [r, o] = readStringArray(buf, offset);
        offset = o;
        rule.wifi_bssid = r;
        break;
      }
      case RuleItemType.AdGuardDomain: {
        const [_, o] = readSuccinctSet(buf, offset);
        offset = o;
        console.warn("AdGuardDomain is unsupported!");
        break;
      }
      case RuleItemType.NetworkType: {
        const [r, o] = readUint8Array(buf, offset);
        offset = o;
        rule.network_type = [...r].map(interfaceTypeToString);
        break;
      }
      case RuleItemType.NetworkIsExpensive: {
        rule.network_is_expensive = true;
        break;
      }
      case RuleItemType.NetworkIsConstrained: {
        rule.network_is_constrained = true;
        break;
      }
      case RuleItemType.NetworkInterfaceAddress: {
        rule.network_interface_address = {};
        const [size, o] = decodeVarint32(buf, offset);
        offset = o;
        for (let i = 0; i < size; i++) {
          const key = buf[offset++];
          const [prefixCount, o] = decodeVarint32(buf, offset);
          offset = o;

          const value: string[] = [];
          for (let j = 0; j < prefixCount; j++) {
            const [prefix, o] = readPrefix(buf, offset);
            offset = o;
            value.push(prefix.toString());
          }
          rule.network_interface_address[interfaceTypeToString(key)] = value;
        }
        break;
      }
      case RuleItemType.DefaultInterfaceAddress: {
        const [prefixCount, o] = decodeVarint32(buf, offset);
        offset = o;

        rule.default_interface_address = [];
        for (let j = 0; j < prefixCount; j++) {
          const [prefix, o] = readPrefix(buf, offset);
          offset = o;
          rule.default_interface_address.push(prefix.toString());
        }
        break;
      }
      case RuleItemType.Final: {
        const invert = buf[offset++] !== 0;
        if (invert) rule.invert = invert;
        return [rule, offset];
      }
      default:
        throw new Error(
          `unknown rule item type: ${itemType}, last type: ${lastItemType}`,
        );
    }
    lastItemType = itemType;
  }
}

async function writeDefaultRule(
  w: WritableStreamDefaultWriter<BufferSource>,
  rule: DefaultRule,
  version: Version,
): Promise<void> {
  await writeByte(w, 0);
  if (rule.query_type && rule.query_type.length > 0) {
    await writeByte(w, RuleItemType.QueryType);
    await writeUint16Array(
      w,
      rule.query_type.map((qt) =>
        (typeof qt === "string") ? stringToDnsType(qt) : qt
      ),
    );
  }
  if (rule.network && rule.network.length > 0) {
    await writeByte(w, RuleItemType.Network);
    await writeStringArray(w, rule.network);
  }
  if (
    rule.domain && rule.domain.length > 0 ||
    rule.domain_suffix && rule.domain_suffix.length > 0
  ) {
    await writeByte(w, RuleItemType.Domain);
    const ss = NewMatcher(rule.domain, rule.domain_suffix, version === 1);
    await writeSuccinctSet(w, ss);
  }
  if (rule.domain_keyword && rule.domain_keyword.length > 0) {
    await writeByte(w, RuleItemType.DomainKeyword);
    await writeStringArray(w, rule.domain_keyword);
  }
  if (rule.domain_regex && rule.domain_regex.length > 0) {
    await writeByte(w, RuleItemType.DomainRegex);
    await writeStringArray(w, rule.domain_regex);
  }
  if (rule.source_ip_cidr && rule.source_ip_cidr.length > 0) {
    await writeByte(w, RuleItemType.SourceIPCIDR);
    await writeIPSet(w, rule.source_ip_cidr.map(AddressPrefix.parsePrefix));
  }
  if (rule.ip_cidr && rule.ip_cidr.length > 0) {
    await writeByte(w, RuleItemType.IPCIDR);
    await writeIPSet(w, rule.ip_cidr.map(AddressPrefix.parsePrefix));
  }
  if (rule.source_port && rule.source_port.length > 0) {
    await writeByte(w, RuleItemType.SourcePort);
    await writeUint16Array(w, rule.source_port);
  }
  if (rule.source_port_range && rule.source_port_range.length > 0) {
    await writeByte(w, RuleItemType.SourcePortRange);
    await writeStringArray(w, rule.source_port_range);
  }
  if (rule.port && rule.port.length > 0) {
    await writeByte(w, RuleItemType.Port);
    await writeUint16Array(w, rule.port);
  }
  if (rule.port_range && rule.port_range.length > 0) {
    await writeByte(w, RuleItemType.PortRange);
    await writeStringArray(w, rule.port_range);
  }
  if (rule.process_name && rule.process_name.length > 0) {
    await writeByte(w, RuleItemType.ProcessName);
    await writeStringArray(w, rule.process_name);
  }
  if (rule.process_path && rule.process_path.length > 0) {
    await writeByte(w, RuleItemType.ProcessPath);
    await writeStringArray(w, rule.process_path);
  }
  if (rule.process_path_regex && rule.process_path_regex.length > 0) {
    await writeByte(w, RuleItemType.ProcessPathRegex);
    await writeStringArray(w, rule.process_path_regex);
  }
  if (rule.package_name && rule.package_name.length > 0) {
    await writeByte(w, RuleItemType.PackageName);
    await writeStringArray(w, rule.package_name);
  }
  if (rule.package_name_regex && rule.package_name_regex.length > 0) {
    if (version < 5) {
      throw new Error(
        "`package_name_regex` rule item is only supported in version 5 or later",
      );
    }

    await writeByte(w, RuleItemType.PackageNameRegex);
    await writeStringArray(w, rule.package_name_regex);
  }
  if (rule.network_type && rule.network_type.length > 0) {
    if (version < 3) {
      throw new Error(
        "`network_type` rule item is only supported in version 3 or later",
      );
    }
    await writeByte(w, RuleItemType.NetworkType);
    await writeUint8Array(w, rule.network_type.map(stringToInterfaceType));
  }
  if (rule.network_is_expensive) {
    if (version < 3) {
      throw new Error(
        "`network_is_expensive` rule item is only supported in version 3 or later",
      );
    }
    await writeByte(w, RuleItemType.NetworkIsExpensive);
  }
  if (rule.network_is_constrained) {
    if (version < 3) {
      throw new Error(
        "`network_is_constrained` rule item is only supported in version 3 or later",
      );
    }
    await writeByte(w, RuleItemType.NetworkIsConstrained);
  }
  if (
    rule.network_interface_address &&
    Object.keys(rule.network_interface_address).length > 0
  ) {
    if (version < 4) {
      throw new Error(
        "`network_interface_address` rule item is only supported in version 4 or later",
      );
    }
    await writeByte(w, RuleItemType.NetworkInterfaceAddress);

    const keys = Object.keys(rule.network_interface_address);
    await writeVarint(w, keys.length);

    for (const [k, entry] of Object.entries(rule.network_interface_address)) {
      await writeByte(w, stringToInterfaceType(k));
      await writeVarint(w, entry.length);
      for (const e of entry) {
        await writePrefix(w, AddressPrefix.parsePrefix(e));
      }
    }
  }
  if (
    rule.default_interface_address && rule.default_interface_address.length > 0
  ) {
    if (version < 4) {
      throw new Error(
        "`default_interface_address` rule item is only supported in version 4 or later",
      );
    }
    await writeByte(w, RuleItemType.DefaultInterfaceAddress);

    await writeVarint(w, rule.default_interface_address.length);
    for (const e of rule.default_interface_address) {
      await writePrefix(w, AddressPrefix.parsePrefix(e));
    }
  }
  if (rule.wifi_ssid && rule.wifi_ssid.length > 0) {
    await writeByte(w, RuleItemType.WIFISSID);
    await writeStringArray(w, rule.wifi_ssid);
  }
  if (rule.wifi_bssid && rule.wifi_bssid.length > 0) {
    await writeByte(w, RuleItemType.WIFIBSSID);
    await writeStringArray(w, rule.wifi_bssid);
  }
  await writeByte(w, RuleItemType.Final);
  await writeByte(w, rule.invert ? 1 : 0);
}

function readLogicalRule(
  buf: Uint8Array,
  offset: number = 0,
): [LogicalRule, number] {
  const rule: LogicalRule = {
    type: "logical",
    mode: "and",
    rules: [],
  };
  const mode = buf[offset++];
  switch (mode) {
    case 0:
      rule.mode = "and";
      break;
    case 1:
      rule.mode = "or";
      break;
    default:
      throw new Error(`unknown logical mode: ${mode}`);
  }
  const [length, o] = decodeVarint32(buf, offset);
  offset = o;
  for (let i = 0; i < length; i++) {
    const [r, o] = readRule(buf, offset);
    offset = o;
    rule.rules.push(r);
  }
  const invert = buf[offset++] !== 0;
  if (invert) rule.invert = invert;
  return [rule, offset];
}

async function writeLogicalRule(
  w: WritableStreamDefaultWriter<BufferSource>,
  rule: LogicalRule,
  version: Version,
): Promise<void> {
  await writeByte(w, 1);
  switch (rule.mode) {
    case "and":
      await writeByte(w, 0);
      break;
    case "or":
      await writeByte(w, 1);
  }
  const [buf] = encodeVarint(rule.rules.length);
  await w.write(buf);

  for (const r of rule.rules) {
    await writeRule(w, r, version);
  }
  await writeByte(w, rule.invert ? 1 : 0);
}
