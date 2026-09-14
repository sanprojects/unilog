// One-line entrypoint.
//   Node:  NODE_OPTIONS="--import unilog/auto" node app.js
//   Bun:   bunfig.toml -> preload = ["unilog/auto"]  (bun ignores NODE_OPTIONS=--import)
//   Or, for partial coverage only: import 'unilog/auto' as your first import.
//
// An .mjs file so --import's ESM-first loader always accepts it; internally
// it just requires the CJS core (no build step, no bundler — this ships as
// the exact source that runs).
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
require('./capture.cjs').install();
