// Makes index.js from the server's guard.js, so the package and {URL}/guard.js are always the
// same code. Run `node build.mjs` after changing src/guard.js (a server test checks they match).
import { readFileSync, writeFileSync } from "node:fs";

export const DEFAULT_URL = "https://agenttrust-production-381e.up.railway.app";

const guard = readFileSync(new URL("../../src/guard.js", import.meta.url), "utf8");
writeFileSync(new URL("./index.js", import.meta.url), guard.replaceAll("{URL}", DEFAULT_URL));
