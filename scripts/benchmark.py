"""Benchmark: measure (no invented numbers) the phases of a /check flow.

Run:  python scripts/benchmark.py [--n 20]
"""

import argparse
import base64
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastapi.testclient import TestClient

from zksafeguard.protocol import server as srv
from zksafeguard.protocol.client import SafetyClient


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20)
    args = ap.parse_args()

    client = TestClient(srv.app)
    setup = client.get("/setup").json()
    sc = SafetyClient(
        base64.b64decode(setup["context_serial_b64"]),
        setup["policy_digest"], setup["model_digest"],
    )
    dim = srv.policy.cfg["fhe"]["feature_dim"]
    prompts = [f"evaluate request number {i} for benchmarking" for i in range(args.n)]

    t_feat, t_post, t_server = [], [], []
    for p in prompts:
        t0 = time.monotonic()
        req = sc.build_check_request(p, dim)
        t1 = time.monotonic()
        r = client.post("/check", json=req)
        t2 = time.monotonic()
        assert r.status_code == 200, r.text
        t_feat.append(t1 - t0)
        t_post.append(t2 - t1)
        t_server.append(r.json()["latency_ms"])

    def ms(xs):
        return 1000 * statistics.mean(xs)

    print("=== zk-SAFEGUARD BENCHMARK (measured on this machine) ===")
    print(f"n prompts                 : {args.n}")
    print(f"client build+encrypt (ms) : mean {ms(t_feat):.1f}")
    print(f"server /check roundtrip   : mean {ms(t_post):.1f}  median {1000 * statistics.median(t_post):.1f}")
    print(f"server-reported latency   : mean {ms(t_server):.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
