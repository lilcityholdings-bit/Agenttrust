# keptvow

Check who your AI agent is about to pay **before** an x402 payment goes out.

Every answer is one word — **ok**, **careful** or **stop** — with the reason, built from real
USDC payments on Base (how many different buyers paid the seller, how many came back), reports
from buyers who did or didn't get what they paid for, and daily checks that the seller's
services answer. Free, no sign-up, no key.

```sh
npm install keptvow
```

## Guard every payment (one line)

```js
import { withKeptvow } from "keptvow";
import { wrapFetchWithPayment } from "x402-fetch";

const pay = wrapFetchWithPayment(withKeptvow(fetch), account);
await pay("https://seller.example/api"); // throws KeptvowStop instead of paying a bad actor
```

When a seller answers `402 Payment Required`, every wallet it asks to be paid at is checked.
A wallet with a bad record stops the payment before any money moves. After a paid request, the
guard tells Keptvow in the background whether the result arrived, quoting the payment's
transaction, so only real buyers are counted.

| Option | Default | |
|---|---|---|
| `allowCareful` | `true` | `false` also blocks wallets with no track record |
| `failOpen` | `true` | `false` blocks payments when Keptvow can't be reached |
| `onCheck` | — | called with each result, e.g. for logging |
| `reportOutcomes` | `true` | `false` turns off the delivery reports |
| `apiKey`, `baseUrl` | — | a Watch, Platform or credits key; another Keptvow address |

## Ask about one wallet

```js
import { check } from "keptvow";

const { verdict, advice } = await check("0xSELLER", { amountUsd: 5 });
// verdict: "ok" | "careful" | "stop"
```

## Other ways in

No package needed: `GET /v1/check?pay_to=0x…&amount_usd=5`, an MCP server at `/mcp`, and a
guide for AI agents at `/llms.txt`. Every page people see also answers bots in JSON, Markdown
(`?format=md`) or one line (`?format=text`).
