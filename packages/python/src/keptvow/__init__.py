"""Check who your AI agent is about to pay before an x402 payment goes out.

    import keptvow

    result = keptvow.check("0xSELLER", amount_usd=5)
    result["verdict"]   # "ok", "careful" or "stop"
    result["advice"]    # one plain sentence saying why

With requests or httpx, check a seller's 402 answer before paying it, and report afterwards
whether the result arrived:

    r = session.get(url)
    if r.status_code == 402:
        keptvow.guard(r)          # raises keptvow.KeptvowStop for a wallet with a bad record
    ...
    keptvow.report_outcome(paid_response)   # in the background; never raises

Every answer is signed by Keptvow (result["signed"], checkable at
https://keptvow.com/.well-known/keptvow-signer.json) and says how long it stays fresh, so checking
the same seller again within five minutes reuses the answer. With a key, the same seller is billed
at most once a day, and delivery reports sent with that key make its checks free.

Free, no sign-up, no key. No dependencies. Set KEPTVOW_URL to use another Keptvow address.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Optional

__all__ = ["check", "guard", "report_outcome", "payment_options", "KeptvowStop", "DEFAULT_URL"]
__version__ = "0.1.0"

DEFAULT_URL = "https://keptvow.com"

# USDC (6 decimals) on Base, Base Sepolia and Ethereum, so prices can be judged in dollars.
_USDC = {
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
}


class KeptvowStop(Exception):
    """Raised instead of paying a wallet Keptvow says to stop at. `.check` holds the full answer."""

    def __init__(self, check: dict):
        super().__init__(f"Keptvow: not paying {check.get('pay_to')}: {check.get('advice')}")
        self.check = check


def _base(base_url: Optional[str]) -> str:
    return (base_url or os.environ.get("KEPTVOW_URL") or DEFAULT_URL).rstrip("/")


def _request(method: str, url: str, body: Optional[dict], headers: dict, timeout: float) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


# Answers still fresh, by base, wallet and amount: reused until their signed "Valid until".
_fresh: dict = {}
_fresh_lock = threading.Lock()
_CACHE_MAX = 1000


def check(
    pay_to: str,
    amount_usd: Optional[float] = None,
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    cache: bool = True,
    timeout: float = 5.0,
) -> dict:
    """Asks Keptvow about one wallet before paying it.

    Returns {"verdict": "ok" | "careful" | "stop", "advice": ..., "evidence": ..., "signed": ...}.
    A fresh answer for the same wallet and amount is reused unless cache=False.
    Raises RuntimeError when Keptvow refuses the question (e.g. not a wallet address).
    """
    base = _base(base_url)
    key = (base, pay_to.strip().lower(), amount_usd)
    if cache:
        with _fresh_lock:
            hit = _fresh.get(key)
        if hit and hit[0] > time.time() * 1000:
            return hit[1]
    q = {"pay_to": pay_to}
    if amount_usd is not None:
        q["amount_usd"] = str(amount_usd)
    headers = {"X-Api-Key": api_key} if api_key else {}
    status, j = _request("GET", f"{base}/v1/check?{urllib.parse.urlencode(q)}", None, headers, timeout)
    if status >= 400:
        raise RuntimeError(j.get("error") or f"Keptvow answered {status}")
    until = (j.get("signed") or {}).get("valid_until_ms") if isinstance(j, dict) else None
    if cache and isinstance(until, (int, float)) and until > time.time() * 1000:
        with _fresh_lock:
            if len(_fresh) >= _CACHE_MAX:
                _fresh.pop(next(iter(_fresh)))
            _fresh[key] = (until, j)
    return j


def _header(response: Any, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None) or {}
    try:
        return headers.get(name) or headers.get(name.lower()) or headers.get(name.upper())
    except AttributeError:
        return None


def payment_options(response: Any) -> list[dict]:
    """The payment options a 402 answer offers, from its JSON body or PAYMENT-REQUIRED header."""
    try:
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("accepts"), list):
            return [a for a in body["accepts"] if isinstance(a, dict)]
    except Exception:
        pass
    header = _header(response, "payment-required")
    if header:
        try:
            j = json.loads(base64.b64decode(header))
            if isinstance(j.get("accepts"), list):
                return [a for a in j["accepts"] if isinstance(a, dict)]
        except Exception:
            pass
    return []


def guard(
    response: Any,
    *,
    allow_careful: bool = True,
    fail_open: bool = True,
    on_check: Optional[Callable[[dict], None]] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    cache: bool = True,
    timeout: float = 5.0,
) -> list[dict]:
    """Checks every wallet a 402 Payment Required answer asks to be paid at.

    Works with requests and httpx responses (anything with .json() and .headers). Raises
    KeptvowStop for a wallet with a bad record — or, with allow_careful=False, one with no track
    record. If Keptvow can't be reached, payment goes ahead unless fail_open=False.
    Returns the check results.
    """
    results = []
    for option in payment_options(response):
        pay_to = option.get("payTo")
        if not isinstance(pay_to, str):
            continue
        units = option.get("maxAmountRequired", option.get("amount"))
        amount = None
        if units is not None and str(option.get("asset", "")).lower() in _USDC:
            try:
                amount = float(units) / 1e6
            except (TypeError, ValueError):
                amount = None
        try:
            result = check(pay_to, amount, api_key=api_key, base_url=base_url, cache=cache, timeout=timeout)
        except Exception:
            if fail_open:
                continue
            raise
        if on_check:
            on_check(result)
        results.append(result)
        if result.get("verdict") == "stop" or (not allow_careful and result.get("verdict") == "careful"):
            raise KeptvowStop(result)
    return results


def report_outcome(
    response_or_tx: Any,
    *,
    delivered: Optional[bool] = None,
    pay_to: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    background: bool = True,
    timeout: float = 5.0,
) -> bool:
    """Tells Keptvow whether a paid request delivered.

    Pass the paid response (its PAYMENT-RESPONSE receipt names the transaction, and its status
    says whether it delivered), or a transaction hash with delivered=True/False. Keptvow checks
    the payment on-chain, so only real buyers count. With api_key, that seller's checks on the
    key come back free. Never raises; returns False when there was nothing to report.
    """
    body: dict = {}
    if isinstance(response_or_tx, str):
        body["tx"] = response_or_tx
    else:
        header = _header(response_or_tx, "payment-response") or _header(response_or_tx, "x-payment-response")
        if not header:
            return False
        try:
            receipt = json.loads(base64.b64decode(header))
        except Exception:
            return False
        if receipt.get("success") is False:
            return False
        tx = receipt.get("transaction") or receipt.get("txHash")
        if not tx:
            return False
        body["tx"] = tx
        status = getattr(response_or_tx, "status_code", None) or getattr(response_or_tx, "status", None)
        if isinstance(status, int):
            body["status"] = status
    if delivered is not None:
        body["delivered"] = delivered
    elif "status" not in body:
        return False
    if pay_to:
        body["pay_to"] = pay_to
    url = f"{_base(base_url)}/v1/outcomes"

    def send() -> None:
        try:
            _request("POST", url, body, {"X-Api-Key": api_key} if api_key else {}, timeout)
        except Exception:
            pass

    if background:
        threading.Thread(target=send, daemon=True).start()
    else:
        send()
    return True
