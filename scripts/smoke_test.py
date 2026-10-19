"""zk-SAFEGUARD smoke test: the four required outcomes + measured latency.

Run:  python scripts/smoke_test.py

The unsafe/reject prompt here is CONSTRUCTED from the (public) model weights:
tokens are chosen whose hashed feature indices align with the strongest
positive weights, so the encrypted linear score reliably exceeds the reject
threshold. This demonstrates the REJECT path deterministically without seeing
any plaintext at the server.
"""

import base64
import hashlib
import logging
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastapi.testclient import TestClient

from zksafeguard.protocol import server as srv
from zksafeguard.protocol.client import SafetyClient

logging.basicConfig(level=logging.WARNING)


def crafted_prompt(scorer, positive=True, n_tokens=10) -> str:
    """Tokens hashing to the strongest (positive|negative) weight indices.

    positive=True  -> encrypted linear score reliably exceeds the reject
                      threshold (demonstrates REJECT deterministically).
    positive=False -> score reliably below it (a *benign* prompt that is
                      guaranteed ALLOW, since random free text would sit too
                      close to the threshold)."""
    w = np.asarray(scorer.weights)
    idx = np.argsort(w)[-n_tokens:] if positive else np.argsort(w)[:n_tokens]
    target = set(int(i) for i in idx)
    words, counter = [], 0
    while len(words) < n_tokens:
        tok = f"tok{counter}"
        counter += 1
        h = int(hashlib.sha256(tok.encode()).hexdigest(), 16) % scorer.feature_dim
        if h in target:
            words.append(tok)
    return " ".join(words)


def main() -> int:
    client = TestClient(srv.app)
    setup = client.get("/setup").json()
    sc = SafetyClient(
        base64.b64decode(setup["context_serial_b64"]),
        setup["policy_digest"],
        setup["model_digest"],
    )
    dim = srv.policy.cfg["fhe"]["feature_dim"]

    print("=== zk-SAFEGUARD SMOKE TEST ===")
    t0 = time.monotonic()

    benign = crafted_prompt(srv.scorer, positive=False)
    req = sc.build_check_request(benign, dim)
    r = client.post("/check", json=req)
    body = r.json()
    ver = client.post("/verify", json={"decision_proof_json": body["decision_proof_json"]}).json()
    print(f"[1] valid input   -> verdict={body['verdict']}  "
          f"proof_verified={ver['valid']}  (risk={body['risk_score']:.4f})")
    assert r.status_code == 200 and ver["valid"] is True
    assert body["verdict"] == "ALLOW"

    req_unsafe = sc.build_check_request(crafted_prompt(srv.scorer, positive=True), dim)
    r2 = client.post("/check", json=req_unsafe)
    body2 = r2.json()
    print(f"[2] unsafe input  -> verdict={body2['verdict']}  (risk={body2['risk_score']:.4f})")
    assert body2["verdict"] == "REJECT"

    import json as _json
    artifact = _json.loads(body["decision_proof_json"])
    artifact["verdict"] = "REJECT" if artifact["verdict"] == "ALLOW" else "ALLOW"
    v = client.post("/verify", json={"decision_proof_json": _json.dumps(artifact)}).json()
    print(f"[3] tampered proof -> verified={v['valid']} (expected False)")
    assert v["valid"] is False

    req_mod = sc.build_check_request("another benign prompt", dim)
    req_mod["model_digest"] = "00" * 32
    r4 = client.post("/check", json=req_mod)
    print(f"[4] modified context -> HTTP {r4.status_code} (expected 400)")
    assert r4.status_code == 400

    r5 = client.post("/check", json=req)
    print(f"[5] replay         -> HTTP {r5.status_code} (expected 409)")
    assert r5.status_code == 409

    for prompt in (benign, "another benign prompt"):
        for word in prompt.split():
            assert word not in " ".join(srv.server.transcript.received)
    print("[6] non-disclosure -> no plaintext prompt tokens in server transcript")

    print(f"[7] measured /check latency: {body['latency_ms']:.1f} ms "
          f"(total smoke wall time {time.monotonic() - t0:.1f}s)")
    print("ALL OUTCOMES OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
