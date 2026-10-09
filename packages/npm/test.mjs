// Runs without a network: a fake seller and a fake Keptvow stand in for both sides.
// Set KEPTVOW_TEST_URL to also check a running Keptvow server for real.
import assert from "node:assert/strict";
import { check, withKeptvow, KeptvowStop } from "./index.js";

const SCAM = "0x" + "c3".repeat(20);
const SIGNED = "0x" + "5e".repeat(20);
const GOOD = "0x" + "a1".repeat(20);
const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const seen = [];
const outcomeKeys = [];

async function fake(url, init = {}) {
  const u = new URL(url);
  seen.push(u.pathname + u.search);
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
  if (u.pathname === "/v1/check") {
    const payTo = u.searchParams.get("pay_to");
    const signed = payTo === SIGNED ? { message: "m", signature: "0x", signer: "0x", valid_until_ms: Date.now() + 60_000 } : undefined;
    return json(200, { pay_to: payTo, verdict: payTo === SCAM ? "stop" : "ok", advice: "test", amount_usd: Number(u.searchParams.get("amount_usd")), signed });
  }
  if (u.pathname === "/v1/outcomes") {
    outcomeKeys.push((init.headers || {})["X-Api-Key"]);
    return json(202, { status: "queued", body: JSON.parse(init.body) });
  }
  if (u.hostname === "scam.example") return json(402, { accepts: [{ payTo: SCAM, maxAmountRequired: "2000000", asset: USDC }] });
  if (u.hostname === "good.example") {
    if (init.paid) return json(200, { data: 1 }, { "payment-response": btoa(JSON.stringify({ success: true, transaction: "0x" + "ab".repeat(32) })) });
    return json(402, { accepts: [{ payTo: GOOD, maxAmountRequired: "10000", asset: USDC }] });
  }
  return json(404, {});
}
const base = "https://keptvow.test";

// One wallet, asked directly.
const r = await check(GOOD, { amountUsd: 5, baseUrl: base, fetch: fake });
assert.equal(r.verdict, "ok");
assert.ok(seen.at(-1).includes("amount_usd=5"));

// A seller with a bad record is stopped before any money moves.
const guarded = withKeptvow(fake, { baseUrl: base });
await assert.rejects(guarded("https://scam.example/x"), (e) => e instanceof KeptvowStop && e.check.pay_to === SCAM);
assert.ok(seen.some((s) => s.includes(`pay_to=${SCAM}`) && s.includes("amount_usd=2")), "the price is checked in dollars");

// A good seller passes through untouched, and the paid result is reported in the background.
const res = await guarded("https://good.example/x");
assert.equal(res.status, 402, "the 402 goes back to the x402 wrapper to pay");
const paid = await guarded("https://good.example/x", { paid: true });
assert.equal(paid.status, 200);
await new Promise((ok) => setTimeout(ok, 10));
assert.ok(seen.includes("/v1/outcomes"), "the delivery is reported");

// A fresh signed answer is reused instead of asking again; cache: false always asks.
const asked = () => seen.filter((s) => s.includes(`pay_to=${SIGNED}`)).length;
await check(SIGNED, { baseUrl: base, fetch: fake });
await check(SIGNED, { baseUrl: base, fetch: fake });
assert.equal(asked(), 1, "the second check reused the signed answer");
await check(SIGNED, { baseUrl: base, fetch: fake, cache: false });
assert.equal(asked(), 2);

// With a key, the delivery report carries it, so that seller's checks come back free.
await withKeptvow(fake, { baseUrl: base, apiKey: "k_test" })("https://good.example/x", { paid: true });
await new Promise((ok) => setTimeout(ok, 10));
assert.equal(outcomeKeys.at(-1), "k_test");

// Keptvow unreachable: pays on by default, blocks when failOpen is false.
const down = () => Promise.reject(new Error("offline"));
const mixed = (u, i) => (String(u).startsWith(base) ? down() : fake(u, i));
assert.equal((await withKeptvow(mixed, { baseUrl: base })("https://scam.example/x")).status, 402);
await assert.rejects(withKeptvow(mixed, { baseUrl: base, failOpen: false })("https://scam.example/x"));

if (process.env.KEPTVOW_TEST_URL) {
  const live = await check("0x" + "12".repeat(20), { baseUrl: process.env.KEPTVOW_TEST_URL });
  assert.ok(["ok", "careful", "stop"].includes(live.verdict));
  console.log("live server answered:", live.verdict);
}
console.log("keptvow npm package: all checks passed");
