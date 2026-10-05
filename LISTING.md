# Listing text for directories

Paste-ready copy for each place Keptvow is listed. Nothing here is published until the owner
does it. Replace `{URL}` with the live address (keptvow.com once it is bought).

## One line (the official MCP Registry takes this from `server.json` and rejects more than 100 characters)

Check a seller's wallet before your agent pays it: ok, careful or stop. Free, no key.

## Short description (directories that allow about 200 characters)

Check a seller's wallet before your agent pays it. Returns ok, careful or stop from real USDC
payment history and delivery reports. Free, no key.

## Long description (Smithery, Glama, PulseMCP, mcp.so, GitHub)

**Keptvow tells your agent who is safe to pay.**

When a seller answers `402 Payment Required`, send the wallet it asks to be paid at to
`check_payment`. You get back **ok**, **careful** or **stop**, one sentence of advice, and the
evidence behind it:

- **Payment history, read from Base**: how many different buyers paid the wallet, how many came
  back, and how many of them are established (they have paid other sellers for weeks), which is
  expensive to fake.
- **Delivery reports**: buyers who paid and got nothing flag the seller. Only buyers whose
  payment is on-chain count, once per payment.
- **Live checks**: every listed paid service is visited daily to see that it answers and asks to
  be paid at the wallet it lists.
- **Ratings for every bot in the ERC-8004 registry** (about 98,000), kept honest: public reviews
  alone never lift a bot above "fair", because they cost almost nothing to fake.

After you pay, call `report_delivery` with the payment's transaction to say whether the result
arrived. That is what lets honest sellers earn **ok** and exposes the ones that take the money
and deliver nothing.

Free, no sign-up, no API key (300 checks an hour per address). Prepaid credit and plans for
heavy use. Paying never buys a better score.

**Tools**: `check_payment` (before paying), `report_delivery` (after paying), `wallet_history`,
`check_trust`, `search_bots`, plus `register` and deal tools for bots that want to build their own
record.

**Connect**: MCP (streamable HTTP) at `{URL}/mcp` · `npm install keptvow` · `pip install keptvow`
· REST `GET {URL}/v1/check?pay_to=0x…&amount_usd=5` · OpenAPI `{URL}/openapi.json` · A2A agent
card `{URL}/.well-known/agent.json` · guide for AI agents `{URL}/llms.txt`.

## Tags / categories

payments, x402, trust, reputation, security, ai-agents, usdc, base, erc-8004, fraud-prevention

## Example prompts (for directories that ask)

- "Is 0x… safe to pay for this API call?"
- "Check the seller before you pay and tell me if it says stop."
- "Report that the payment 0x… delivered."
- "Look up this bot's trust rating."

## Notes for each place

- **Official MCP Registry**: run the "Publish to MCP Registry" workflow (Actions tab). Bump
  `version` in `server.json` first.
- **Smithery, Glama, PulseMCP, mcp.so**: most crawl the official registry; claim the page when it
  appears and paste the long description.
- **x402 service list / A2A directories**: use the short description and the agent card address.
- **Wording**: say "ok, careful or stop" every time, and never say "guarantee" or "verified safe".
  Keptvow reports evidence; it does not promise a seller is honest.
