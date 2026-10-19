"""Minimal client example against a locally running server.

Start the API first:  uvicorn zksafeguard.protocol.server:app --port 8000
Then:                 python examples/example_client.py
"""

import base64
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from zksafeguard.protocol.client import SafetyClient


def main() -> int:
    base = "http://127.0.0.1:8000"
    health = httpx.get(f"{base}/health", timeout=30.0).json()
    print("server health:", health)

    setup = httpx.get(f"{base}/setup", timeout=30.0).json()
    client = SafetyClient(
        base64.b64decode(setup["context_serial_b64"]),
        setup["policy_digest"],
        setup["model_digest"],
    )

    import json

    policy = json.loads(
        (Path(__file__).resolve().parents[1] / "configs" / "policy.json").read_text()
    )
    dim = policy["fhe"]["feature_dim"]

    req = client.build_check_request("a perfectly ordinary request", dim)
    resp = httpx.post(f"{base}/check", json=req, timeout=60.0).json()
    print("decision:", resp["verdict"], "risk:", resp["risk_score"])

    verdict = httpx.post(
        f"{base}/verify",
        json={"decision_proof_json": resp["decision_proof_json"]},
        timeout=30.0,
    ).json()
    print("proof verified:", verdict["valid"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
