import { newSuccinctSet, succinctSetToKeys } from "./succinct.ts";
import type { succinctSet } from "./types.ts";

const prefixLabel = "\r";
const rootLabel = "\n";

export function NewMatcher(
  domain: string[] = [],
  domainSuffix: string[] = [],
  generateLegacy: boolean,
): succinctSet {
  const domainList: string[] = [];
  const seen = new Set<string>();

  for (const d of domainSuffix) {
    if (seen.has(d)) continue;
    seen.add(d);

    if (d.startsWith(".")) {
      domainList.push(reverseDomain(prefixLabel + d));
    } else if (generateLegacy) {
      domainList.push(reverseDomain(d));
      const suffixDomain = "." + d;
      if (!seen.has(suffixDomain)) {
        seen.add(suffixDomain);
        domainList.push(reverseDomain(prefixLabel + suffixDomain));
      }
    } else {
      domainList.push(reverseDomain(rootLabel + d));
    }
  }

  for (const d of domain) {
    if (seen.has(d)) continue;
    seen.add(d);

    domainList.push(reverseDomain(d));
  }

  domainList.sort();

  return newSuccinctSet(domainList);
}

export function domainMatcherDump(ss: succinctSet): [string[], string[]] {
  const domainSet = new Set<string>();
  const prefixSet = new Set<string>();
  const prefixList: string[] = [];

  for (const key of succinctSetToKeys(ss).map(reverseDomain)) {
    switch (key[0]) {
      case prefixLabel: {
        prefixSet.add(key.slice(1));
        break;
      }
      case rootLabel: {
        prefixList.push(key.slice(1));
        break;
      }
      default: {
        domainSet.add(key);
      }
    }
  }

  for (const rawPrefix of prefixSet) {
    if (rawPrefix[0] === ".") {
      const rootDomain = rawPrefix.slice(1);
      if (domainSet.has(rootDomain)) {
        domainSet.delete(rootDomain);
        prefixList.push(rootDomain);
        continue;
      }
    }
    prefixList.push(rawPrefix);
  }

  return [[...domainSet].sort(), prefixList.sort()];
}

function reverseDomain(domain: string): string {
  return [...domain].reverse().join("");
}
