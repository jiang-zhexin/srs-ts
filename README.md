# srs-ts

[![JSR](https://jsr.io/badges/@zhexin/srs)](https://jsr.io/@zhexin/srs)

## Installation

## from jsr

```bash
# Node.js
npx jsr add @zhexin/srs
yarn add jsr:@zhexin/srs
pnpm add jsr:@zhexin/srs
# Deno
deno add jsr:@zhexin/srs
# Bun
bunx jsr add @zhexin/srs
```

## from npm

write `@jsr:registry=https://npm.jsr.io` into `.npmrc`, then

```bash
npm add @zhexin/srs
yarn add @zhexin/srs
pnpm add @zhexin/srs

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
