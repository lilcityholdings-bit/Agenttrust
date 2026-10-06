// Keptvow guard — checks who you are about to pay before an x402 payment goes out.
//
//   npm install keptvow          (or save this file from https://keptvow.com/guard.js)
//
//   import { withKeptvow } from "keptvow";
//   import { wrapFetchWithPayment } from "x402-fetch";
//
//   const pay = wrapFetchWithPayment(withKeptvow(fetch), account);
//   await pay("https://seller.example/api");   // throws KeptvowStop instead of paying a bad actor
//
// When a seller answers 402 Payment Required, every wallet it asks to be paid at is checked at
// https://keptvow.com/v1/check. A wallet with a bad record stops the payment before any money moves.
//
// After a paid request it also tells Keptvow, in the background, whether the result arrived —
// quoting the payment's transaction from the PAYMENT-RESPONSE header, so only real buyers are
// counted. That is what lets honest sellers earn "ok" and lets everyone avoid the ones that
// take the money and deliver nothing. Free, no key needed.
//
// Or ask about one wallet yourself:
//
//   import { check } from "keptvow";
//   const { verdict, advice } = await check("0xSELLER", { amountUsd: 5 });   // "ok" | "careful" | "stop"
//
// Options: { allowCareful: true }  false also blocks wallets with no track record
//          { failOpen: true }      false blocks when Keptvow can't be reached
//          { onCheck: fn }         called with each check result, e.g. for logging
//          { reportOutcomes: true } false turns off the delivery reports
//          { apiKey, baseUrl }

const KEPTVOW = "https://keptvow.com";

// USDC (6 decimals) on Base, Base Sepolia and Ethereum, so amounts can be judged in dollars.
const USDC = new Set([
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
]);

export class KeptvowStop extends Error {
  constructor(check) {
    super(`Keptvow: not paying ${check.pay_to}: ${check.advice}`);
    this.name = "KeptvowStop";
    this.check = check;
  }
}

/** The payment options a 402 response offers, from its body or its PAYMENT-REQUIRED header. */
function paymentOptions(res, body) {
  if (body && Array.isArray(body.accepts)) return body.accepts;
  const header = res.headers.get("payment-required");
  if (header) {
    try {
      const j = JSON.parse(atob(header));
      if (Array.isArray(j.accepts)) return j.accepts;
    } catch {}
  }
  return [];
}

/**
 * Asks Keptvow about one wallet before paying it. Resolves to
 * { verdict: "ok" | "careful" | "stop", advice, evidence, matches, wallet_page }.
 */
export async function check(payTo, { amountUsd, apiKey, baseUrl, fetch: fetchImpl = globalThis.fetch } = {}) {
  const base = (baseUrl || KEPTVOW).replace(/\/$/, "");
  const q = new URLSearchParams({ pay_to: payTo });
  if (amountUsd != null) q.set("amount_usd", String(amountUsd));
  const r = await fetchImpl.call(globalThis, `${base}/v1/check?${q}`, { headers: apiKey ? { "X-Api-Key": apiKey } : {} });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || `Keptvow answered ${r.status}`);
  return j;
}

export function withKeptvow(fetchImpl = globalThis.fetch, options = {}) {
  const base = (options.baseUrl || KEPTVOW).replace(/\/$/, "");
  const allowCareful = options.allowCareful !== false;
  const failOpen = options.failOpen !== false;
  const onCheck = typeof options.onCheck === "function" ? options.onCheck : () => {};
  const reportOutcomes = options.reportOutcomes !== false;
  const call = (input, init) => fetchImpl.call(globalThis, input, init);
  const keyOf = (input) => String(input && input.url ? input.url : input);
  const payToByUrl = new Map();

  // After a paid request: the settlement receipt names the transaction; report whether the
  // result arrived. Never awaited and never throws, so it can't slow or break the payment.
  function report(input, res) {
    if (!reportOutcomes) return;
    const header = res.headers.get("payment-response") || res.headers.get("x-payment-response");
    if (!header) return;
    let receipt;
    try {
      receipt = JSON.parse(atob(header));
    } catch {
      return;
    }
    const tx = receipt && (receipt.transaction || receipt.txHash);
    if (!tx || receipt.success === false) return;
    const body = { tx, status: res.status };
    const payTo = payToByUrl.get(keyOf(input));
    if (payTo) body.pay_to = payTo;
    Promise.resolve()
      .then(() =>
        call(`${base}/v1/outcomes`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      )
      .catch(() => {});
  }

  return async function guardedFetch(input, init) {
    const res = await call(input, init);
    if (res.status !== 402) {
      report(input, res);
      return res;
    }
    let body = null;
    try {
      body = await res.clone().json();
    } catch {}
    for (const option of paymentOptions(res, body)) {
      if (!option || typeof option.payTo !== "string") continue;
      const units = option.maxAmountRequired ?? option.amount;
      const amountUsd = units != null && USDC.has(String(option.asset || "").toLowerCase()) ? Number(units) / 1e6 : undefined;
      let result;
      try {
        result = await check(option.payTo, { amountUsd, apiKey: options.apiKey, baseUrl: base, fetch: call });
      } catch (e) {
        if (failOpen) continue;
        throw e;
      }
      onCheck(result);
      if (result.verdict === "stop" || (!allowCareful && result.verdict === "careful")) {
        throw new KeptvowStop(result);
      }
      payToByUrl.set(keyOf(input), option.payTo);
    }
    return res;
  };
}

export default withKeptvow;
