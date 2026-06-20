/**
 * from https://github.com/SagerNet/sing/blob/dev/common/domain/set.go
 */

import type { succinctSet } from "./types.ts";
import {
  readUint64Array,
  readUint8Array,
  writeByte,
  writeUint64Array,
  writeUint8Array,
} from "./utils.ts";

const decoder = new TextDecoder("utf-8");
const encoder = new TextEncoder();

const select8Lookup: Uint8Array = (() => {
  const array = new Uint8Array(256 * 8);

  for (let i = 0; i < 256; i++) {
    let w = i;
    for (let j = 0; j < 8; j++) {
      const x = w === 0 ? 8 : 31 - Math.clz32(w & -w);
      w = (w & (w - 1)) & 0xff;
      array[i * 8 + j] = x;
    }
  }
  return array;
})();

const mask: BigUint64Array = (() => {
  const array = new BigUint64Array(65);
  for (let i = 0; i < 65; i++) {
    array[i] = (1n << BigInt(i)) - 1n;
  }
  return array;
})();

const rMaskUpto: BigUint64Array = (() => {
  const array = new BigUint64Array(64);
  const ALL_ONES_64 = 0xffffffffffffffffn;

  for (let i = 0; i < 64; i++) {
    const maskUpto = (1n << BigInt(i + 1)) - 1n;

    array[i] = maskUpto ^ ALL_ONES_64;
  }
  return array;
})();

export function newSuccinctSet(keys: string[]): succinctSet {
  let labelBitmap = new BigUint64Array();
  let leaves = new BigUint64Array();
  const labels: number[] = [];
  let lIdx = 0;
  const byteKeys = keys.map((k) => encoder.encode(k));
  const queue = [{ s: 0, e: byteKeys.length, col: 0 }];

  for (let i = 0; i < queue.length; i++) {
    const elt = queue[i];
    if (elt.col === byteKeys[elt.s].length) {
      elt.s++;
      leaves = setBit(leaves, i, 1);
    }
    for (let j = elt.s; j < elt.e;) {
      const frm = j;
      while (j < elt.e && byteKeys[j][elt.col] === byteKeys[frm][elt.col]) j++;
      queue.push({ s: frm, e: j, col: elt.col + 1 });
      labels.push(byteKeys[frm][elt.col]);
      labelBitmap = setBit(labelBitmap, lIdx, 0);
      lIdx++;
    }
    labelBitmap = setBit(labelBitmap, lIdx, 1);
    lIdx++;
  }

  const selects = indexSelect32R64(labelBitmap);
  const ranks = indexRank64(labelBitmap, true);

  return {
    leaves,
    labelBitmap,
    labels: new Uint8Array(labels),
    selects,
    ranks,
  };
}

export function succinctSetToKeys(ss: succinctSet): string[] {
  const result: string[] = [];
  const currentKey: number[] = [];

  const traverse = (nodeId: number, bmIdx: number): void => {
    if (getBit(ss.leaves, nodeId) !== BigInt(0)) {
      result.push(decoder.decode(new Uint8Array(currentKey)));
    }

    for (;; bmIdx++) {
      if (getBit(ss.labelBitmap, bmIdx) !== BigInt(0)) return;

      const nextLabel = ss.labels[bmIdx - nodeId];
      currentKey.push(nextLabel);

      const nextNodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx + 1);
      const nextBmIdx = selectIthOne(
        ss.labelBitmap,
        ss.ranks,
        ss.selects,
        nextNodeId - 1,
      ) + 1;
      traverse(nextNodeId, nextBmIdx);
      currentKey.pop();
    }
  };

  traverse(0, 0);
  return result;
}

export function readSuccinctSet(
  buf: Uint8Array,
  offset: number = 0,
): [succinctSet, number] {
  buf[offset++];
  const [leaves, offsetLeaves] = readUint64Array(buf, offset);
  offset = offsetLeaves;

  const [labelBitmap, offsetLabelBitmap] = readUint64Array(buf, offset);
  offset = offsetLabelBitmap;

  const [labels, offsetLabels] = readUint8Array(buf, offset);
  offset = offsetLabels;

  const selects = indexSelect32R64(labelBitmap);
  const ranks = indexRank64(labelBitmap, true);

  return [{ leaves, labelBitmap, labels, selects, ranks }, offset];
}

export async function writeSuccinctSet(
  w: WritableStreamDefaultWriter<BufferSource>,
  ss: succinctSet,
) {
  await writeByte(w, 0);
  await writeUint64Array(w, ss.leaves);
  await writeUint64Array(w, ss.labelBitmap);
  await writeUint8Array(w, ss.labels);
}

function setBit(
  bm: BigUint64Array<ArrayBuffer>,
  i: number,
  v: number,
) {
  const arrayIndex = i >> 6;
  if (arrayIndex >= bm.length) {
    const newBm = new BigUint64Array(arrayIndex + 1);
    newBm.set(bm);
    bm = newBm;
  }

  const mask = 1n << BigInt(i & 63);
  if (v) {
    bm[arrayIndex] |= mask;
  } else {
    bm[arrayIndex] &= ~mask;
  }
  return bm;
}

function getBit(bm: BigUint64Array, i: number): bigint {
  return bm[i >> 6] & (1n << BigInt(i & 63));
}

function countZeros(bm: BigUint64Array, ranks: Int32Array, i: number): number {
  const [a, _] = rank64(bm, ranks, i);
  return i - a;
}

function selectIthOne(
  bm: BigUint64Array,
  ranks: Int32Array,
  selects: Int32Array,
  i: number,
): number {
  const [a, _] = select32R64(bm, selects, ranks, i);
  return a;
}

function rank64(
  words: BigUint64Array,
  rindex: Int32Array,
  i: number,
): [number, number] {
  const wordI = i >> 6;
  const j = i & 63;
  const n = rindex[wordI];
  const w = words[wordI];
  const c1 = n + OnesCount64(w & mask[j]);
  return [c1, Number(w >> BigInt(j)) & 1];
}

function select32R64(
  words: BigUint64Array,
  selectIndex: Int32Array,
  rankIndex: Int32Array,
  i: number,
): [number, number] {
  let a = 0;
  const l = words.length;

  let wordI = selectIndex[i >> 5] >> 6;

  while (rankIndex[wordI + 1] <= i) {
    wordI++;
  }

  let w = words[wordI];
  let ww = w;
  const base = wordI << 6;
  let findIth = i - rankIndex[wordI];
  let offset = 0;

  let ones = onesCount32(Number(ww & 0xffffffffn));
  if (ones <= findIth) {
    findIth -= ones;
    offset |= 32;
    ww >>= 32n;
  }

  ones = onesCount32(Number(ww & 0xffffn));
  if (ones <= findIth) {
    findIth -= ones;
    offset |= 16;
    ww >>= 16n;
  }

  const wwNum = Number(ww & 0xffffn);
  ones = onesCount32(wwNum & 0xff);

  if (ones <= findIth) {
    a = select8Lookup[((wwNum >> 5) & 0x7f8) | (findIth - ones)] + offset + 8;
  } else {
    a = select8Lookup[((wwNum & 0xff) << 3) | findIth] + offset;
  }

  a += base;
  w &= rMaskUpto[a & 63];

  if (w !== 0n) {
    return [a, base + trailingZeros64(w)];
  }

  wordI++;
  for (; wordI < l; wordI++) {
    w = words[wordI];
    if (w !== 0n) {
      return [a, (wordI << 6) + trailingZeros64(w)];
    }
  }

  return [a, l << 6];
}

function indexSelect32R64(words: BigUint64Array): Int32Array {
  const l = words.length << 6;
  const sidx: number[] = [];

  let ith = -1;
  for (let i = 0; i < l; i++) {
    if (getBit(words, i) !== BigInt(0)) {
      ith++;
      if ((ith & 31) === 0) {
        sidx.push(i);
      }
    }
  }

  return new Int32Array(sidx);
}

function indexRank64(words: BigUint64Array, trailing: boolean): Int32Array {
  const idx = new Int32Array(trailing ? words.length + 1 : words.length);

  let n = 0;
  for (let i = 0; i < words.length; i++) {
    idx[i] = n;
    n += OnesCount64(words[i]);
  }

  if (trailing) idx[words.length] = n;

  return idx;
}

function trailingZeros64(x: bigint): number {
  if (x === 0n) return 64;

  const low = Number(x & 0xffffffffn);
  if (low !== 0) {
    return 31 - Math.clz32(low & -low);
  }

  const high = Number((x >> 32n) & 0xffffffffn);
  return 32 + (31 - Math.clz32(high & -high));
}

function onesCount32(x: number): number {
  x = x - ((x >>> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
  return Math.imul((x + (x >>> 4)) & 0x0f0f0f0f, 0x01010101) >>> 24;
}

function OnesCount64(n: bigint): number {
  const low = Number(n & 0xffffffffn);
  const high = Number((n >> 32n) & 0xffffffffn);
  return onesCount32(low) + onesCount32(high);
}
