"""Runs without a network: Keptvow's answers are faked. Set KEPTVOW_TEST_URL to also ask a
running Keptvow server for real."""

import base64
import json
import os
import time
import unittest

import keptvow

SCAM = "0x" + "c3" * 20
GOOD = "0x" + "a1" * 20
SIGNED = "0x" + "5e" * 20
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class Test(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.report_headers = []
        keptvow._fresh.clear()
        self.real = keptvow._request

        def fake(method, url, body, headers, timeout):
            self.calls.append((method, url, body))
            if "/v1/check" in url:
                q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
                if q["pay_to"] == "down":
                    raise OSError("offline")
                signed = {"valid_until_ms": (time.time() + 60) * 1000} if q["pay_to"] == SIGNED else None
                return 200, {"pay_to": q["pay_to"], "verdict": "stop" if q["pay_to"] == SCAM else "ok", "advice": "test", "signed": signed}
            self.report_headers.append(headers)
            return 202, {"status": "queued"}

        keptvow._request = fake

    def tearDown(self):
        keptvow._request = self.real

    def test_check_asks_about_one_wallet(self):
        r = keptvow.check(GOOD, 5, base_url="https://k.test")
        self.assertEqual(r["verdict"], "ok")
        self.assertIn("amount_usd=5", self.calls[-1][1])

    def test_guard_stops_a_bad_seller_and_passes_a_good_one(self):
        bad = FakeResponse(402, {"accepts": [{"payTo": SCAM, "maxAmountRequired": "2000000", "asset": USDC}]})
        with self.assertRaises(keptvow.KeptvowStop) as e:
            keptvow.guard(bad)
        self.assertEqual(e.exception.check["pay_to"], SCAM)
        self.assertIn("amount_usd=2.0", self.calls[-1][1])
        # The payment request can also come in the PAYMENT-REQUIRED header.
        header = base64.b64encode(json.dumps({"accepts": [{"payTo": GOOD}]}).encode()).decode()
        self.assertEqual(keptvow.guard(FakeResponse(402, headers={"PAYMENT-REQUIRED": header}))[0]["verdict"], "ok")

    def test_unreachable_keptvow_pays_on_unless_told_not_to(self):
        r = FakeResponse(402, {"accepts": [{"payTo": "down"}]})
        self.assertEqual(keptvow.guard(r), [])
        with self.assertRaises(OSError):
            keptvow.guard(r, fail_open=False)

    def test_outcomes_come_from_the_payment_receipt(self):
        receipt = base64.b64encode(json.dumps({"success": True, "transaction": "0x" + "ab" * 32}).encode()).decode()
        self.assertTrue(keptvow.report_outcome(FakeResponse(200, {}, {"PAYMENT-RESPONSE": receipt}), background=False))
        self.assertEqual(self.calls[-1][2], {"tx": "0x" + "ab" * 32, "status": 200})
        self.assertFalse(keptvow.report_outcome(FakeResponse(200, {}, {})), "no receipt, nothing to report")
        self.assertTrue(keptvow.report_outcome("0x" + "cd" * 32, delivered=False, background=False))
        self.assertEqual(self.calls[-1][2], {"tx": "0x" + "cd" * 32, "delivered": False})

    def test_a_fresh_signed_answer_is_reused(self):
        keptvow.check(SIGNED)
        keptvow.check(SIGNED.upper().replace("0X", "0x"))
        self.assertEqual(sum(1 for c in self.calls if SIGNED in c[1].lower()), 1)
        keptvow.check(SIGNED, cache=False)
        self.assertEqual(sum(1 for c in self.calls if SIGNED in c[1].lower()), 2)
        keptvow.check(GOOD)
        keptvow.check(GOOD)
        self.assertEqual(sum(1 for c in self.calls if GOOD in c[1]), 2, "unsigned answers are never reused")

    def test_a_report_sent_with_a_key_carries_it(self):
        keptvow.report_outcome("0x" + "ab" * 32, delivered=True, api_key="k_test", background=False)
        self.assertEqual(self.report_headers[-1].get("X-Api-Key"), "k_test")


@unittest.skipUnless(os.environ.get("KEPTVOW_TEST_URL"), "set KEPTVOW_TEST_URL to test against a server")
class Live(unittest.TestCase):
    def test_a_real_server_answers(self):
        r = keptvow.check("0x" + "12" * 20, base_url=os.environ["KEPTVOW_TEST_URL"])
        self.assertIn(r["verdict"], ("ok", "careful", "stop"))
        with self.assertRaises(RuntimeError):
            keptvow.check("not-a-wallet", base_url=os.environ["KEPTVOW_TEST_URL"])


if __name__ == "__main__":
    unittest.main()
