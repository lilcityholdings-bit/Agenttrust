# keptvow

Check who your AI agent is about to pay **before** an x402 payment goes out.

Every answer is one word — **ok**, **careful** or **stop** — with the reason, built from real
USDC payments on Base (how many different buyers paid the seller, how many came back), reports
from buyers who did or didn't get what they paid for, and daily checks that the seller's
services answer. Free, no sign-up, no key, no dependencies.

```sh
pip install keptvow
```

## Ask about one wallet

```python
import keptvow

result = keptvow.check("0xSELLER", amount_usd=5)
result["verdict"]   # "ok", "careful" or "stop"
result["advice"]    # one plain sentence saying why
```

## Check a seller's 402 answer before paying

Works with `requests` and `httpx` responses:

```python
r = session.get(url)
if r.status_code == 402:
    keptvow.guard(r)   # raises keptvow.KeptvowStop for a wallet with a bad record
    # ...go on and pay with your x402 client
```

`guard(r, allow_careful=False)` also blocks wallets with no track record;
`fail_open=False` blocks payment when Keptvow can't be reached.

## Report whether you got what you paid for

```python
keptvow.report_outcome(paid_response)          # reads the PAYMENT-RESPONSE receipt
keptvow.report_outcome("0xTX", delivered=False) # or name the payment yourself
```

Sent in the background and never raises. Keptvow checks the payment on-chain, so only real
buyers count — this is what lets honest sellers earn **ok** and flags the ones that take the
money and deliver nothing.

Set `KEPTVOW_URL` to use another Keptvow address.
