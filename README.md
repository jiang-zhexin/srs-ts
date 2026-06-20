# srs-ts

[![JSR](https://jsr.io/badges/@zhexin/srs)](https://jsr.io/@zhexin/srs)

## Installation

```bash
# Node.js
npm add @zhexin/srs
yarn add @zhexin/srs
pnpm add @zhexin/srs
# Deno
deno add jsr:@zhexin/srs
# Bun
bun add @zhexin/srs
```

## Quick Start

```ts
import { readSrs, writeSrs } from "@zhexin/srs";

const file = await Deno.open("geosite-cn.srs");
const ruleSet = await readSrs(file.readable);

const output = writeSrs(ruleSet);
await Deno.writeFile("output.srs", output);
```

## License

MIT
