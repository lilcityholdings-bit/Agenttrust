"""Checks the payment history reader against a fake Base node that behaves the way the public nodes
did in production: HTTP 413 for requests with too many wallets, a range error for wide queries, and
a burst of 403s. It starts the real server on this node, waits for the history to be read, then
compares every wallet's counted payments with the node's ground truth: nothing missed, nothing
counted twice, nothing outside each wallet's range counted.

    cargo build --release && python3 tools/check_history_reader.py

Exits non-zero with the mismatches if anything is off. Needs no network.
"""
import json, os, random, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

HEAD = 52_300_000
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
MAX_WALLETS = int(os.environ.get("FAKE_MAX_WALLETS", "8"))  # more than this in one query: HTTP 413
MAX_SPAN = 500            # wider than this: refused, as Base's public node does (measured)
MAX_LOGS = 150            # an answer with more logs than this: HTTP 413, like a busy wallet on a public node
UNTIL = HEAD - 1000       # the reader is told to cover up to here
FROM = HEAD - 40_000      # ...and from here (the resume point)
random.seed(7)
WALLET_COUNT = int(os.environ.get("WALLETS", "40"))
wallets = ["0x%040x" % (0xabc000 + i) for i in range(WALLET_COUNT)]
buyers = ["0x%040x" % (0xb0b000 + i) for i in range(30)]
transfers = []   # (buyer, seller, block, units)
for w in wallets:
    for _ in range(random.randint(0, 12)):
        # a spread of blocks: before FROM and after UNTIL must NOT be counted
        transfers.append((random.choice(buyers), w, random.randint(HEAD - 60_000, HEAD), 10_000 * random.randint(1, 9)))
HOT, SUPER_HOT = wallets[0], wallets[1]
# HOT: a payment every block for 3,000 blocks: answers fit only when asked in slices of about 125 blocks
for blk in range(FROM + 5000, FROM + 8000):
    transfers.append((random.choice(buyers), HOT, blk, 10_000))
# SUPER_HOT: five payments a block for 400 blocks: too busy to read even in the narrowest slice
for blk in range(FROM + 12000, FROM + 12400):
    for _ in range(5):
        transfers.append((random.choice(buyers), SUPER_HOT, blk, 10_000))
def expected():
    out = {}
    for b, w, blk, u in transfers:
        if FROM <= blk <= UNTIL:
            c = out.setdefault(w, [0, 0]); c[0] += 1; c[1] += u
    return out
stats = {"queries": 0, "413": 0, "403": 0, "range": 0, "ok": 0, "max_wallets_ok": 0}
burst = {"left": 3}
lock = threading.Lock()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body=b"{}"):
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/stats": return self._send(200, json.dumps({**stats, "expected": expected()}).encode())
        self._send(404)
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m, p = req["method"], req["params"]
        rid = req.get("id", 1)
        def ok(r): self._send(200, json.dumps({"jsonrpc": "2.0", "id": rid, "result": r}).encode())
        if m == "eth_blockNumber": return ok(hex(HEAD + 5))
        if m != "eth_getLogs": return ok(None)
        f = p[0]; lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
        if len(f["topics"]) < 3 or not isinstance(f["topics"][2], list):
            return ok([])   # the registry reader's queries: nothing to see here
        tops = f["topics"][2]
        with lock:
            stats["queries"] += 1
            if len(tops) > MAX_WALLETS: stats["413"] += 1; return self._send(413, b"too large")
            if stats["queries"] > 40 and burst["left"] > 0 and stats["queries"] % 7 == 0:
                burst["left"] -= 1; stats["403"] += 1; return self._send(403, b"forbidden")
            if hi - lo + 1 > MAX_SPAN:
                stats["range"] += 1
                return self._send(413, b"range too large")
            stats["ok"] += 1; stats["max_wallets_ok"] = max(stats["max_wallets_ok"], len(tops))
        want = set(tops); logs = []
        for b, w, blk, u in transfers:
            t = "0x" + "0" * 24 + w[2:]
            if lo <= blk <= hi and t in want:
                logs.append({"blockNumber": hex(blk), "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                             "topics": [TRANSFER, "0x" + "0" * 24 + b[2:], t], "data": "0x" + "%064x" % u})
        if len(logs) > MAX_LOGS:
            with lock:
                stats["ok"] -= 1; stats["too_many_logs"] = stats.get("too_many_logs", 0) + 1
            return self._send(413, b"response too large")
        ok(logs)

def main():
    import os, subprocess, tempfile, urllib.request
    d = tempfile.mkdtemp(prefix="keptvow-history-")
    # the ledger file the reader starts from: 40 wallets queued, none read yet
    with open(d + "/payments.jsonl", "w") as o:
        o.write(json.dumps({"kind": "header", "version": 1, "cursor": HEAD, "head": HEAD, "catalog_at_ms": int(time.time() * 1000) + 86400000 * 365,
                            "backfill": [[w, UNTIL, FROM] for w in wallets]}) + "\n")
        for w in wallets:
            o.write(json.dumps({"kind": "seller", "wallet": w, "payments": 0, "volume": "0", "first_block": 0, "last_block": 0,
                                "backfilled_from": 0, "payers": [], "reports": []}) + "\n")
    node = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=node.serve_forever, daemon=True).start()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ, "STATE_FILE": d + "/state.json", "PORT": "8097", "ADMIN_SECRET": "local-only-test-secret-123456",
           "BASE_RPC_URL": f"http://127.0.0.1:{node.server_address[1]}", "CATALOG_URLS": "https://127.0.0.1:1/x",
           "HISTORY_BATCH": os.environ.get("HISTORY_BATCH", "10"), "HISTORY_READERS": os.environ.get("HISTORY_READERS", "4")}
    server = subprocess.Popen([root + "/target/release/agenttrust"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    calls = [0]
    def get(path):
        # a different caller address each time, so checking thousands of wallets doesn't hit the
        # free tier's hourly limit (300 lookups per address)
        calls[0] += 1
        ip = "10.%d.%d.%d" % (calls[0] >> 16 & 255, calls[0] >> 8 & 255, calls[0] & 255)
        req = urllib.request.Request("http://127.0.0.1:8097" + path, headers={"X-Real-IP": ip})
        return json.load(urllib.request.urlopen(req, timeout=5))
    try:
        for _ in range(120):
            time.sleep(1)
            try:
                c = get("/health")["checks"]
            except Exception:
                continue
            if c["wallets_history_read"] == len(wallets) and c["wallets_history_waiting"] == 0:
                break
        else:
            sys.exit("history was not read in two minutes")
        exp = expected(); bad = 0; got_total = 0
        for w in wallets:
            ev = get(f"/v1/wallets/{w}")["evidence"]
            p = ev["payments"]
            got = (p["received"], round(p["volume_usd"] * 1_000_000)); want = tuple(exp.get(w, [0, 0]))
            got_total += got[0]
            if w == SUPER_HOT:
                # too busy to read in full: flagged, and what was read is a floor, never an overcount
                if not ev["history_incomplete"] or got[0] > want[0]:
                    bad += 1; print("SUPER_HOT not flagged incomplete, or overcounted:", got, want, ev["history_incomplete"])
            elif ev["history_incomplete"] or got != want:
                bad += 1; print("MISMATCH", w, "got", got, "expected", want, "incomplete:", ev["history_incomplete"])
        print(f"{len(wallets)} wallets, {got_total} payments counted of {sum(v[0] for v in exp.values())} expected "
              f"(the unreadable wallet is a floor), {stats['413']} too-large, {stats.get('too_many_logs', 0)} too-busy and "
              f"{stats['403']} blocked requests survived, {stats['queries']} queries in all")
        if bad or stats["413"] == 0 or stats["403"] == 0 or stats.get("too_many_logs", 0) == 0:
            sys.exit("FAILED: " + ("mismatches above" if bad else "the fake node never exercised the failure paths"))
        print("ok")
    finally:
        server.terminate()


if __name__ == "__main__":
    main()
