import base64

import pytest
from fastapi.testclient import TestClient

from zksafeguard.protocol import server as srv
from zksafeguard.protocol.client import SafetyClient

PROMPT = "please summarize the quarterly report"
FEATURE_DIM = srv.policy.cfg["fhe"]["feature_dim"]


@pytest.fixture()
def client():
    with TestClient(srv.app) as tc:
        yield tc


def _build(client: TestClient, prompt: str, nonce: str | None = None) -> dict:
    setup = client.get("/setup").json()
    sc = SafetyClient(
        base64.b64decode(setup["context_serial_b64"]),
        setup["policy_digest"],
        setup["model_digest"],
    )
    return sc.build_check_request(prompt, FEATURE_DIM, nonce)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_full_flow_allow_and_proof(client):
    req = _build(client, PROMPT)
    r = client.post("/check", json=req)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in ("ALLOW", "REJECT")
    v = client.post("/verify", json={"decision_proof_json": body["decision_proof_json"]})
    assert v.status_code == 200 and v.json()["valid"] is True


def test_replay_rejected(client):
    req = _build(client, PROMPT, nonce="fixed-nonce-123")
    r1 = client.post("/check", json=req)
    assert r1.status_code == 200
    r2 = client.post("/check", json=req)
    assert r2.status_code == 409


def test_stale_timestamp_rejected(client):
    import time

    req = _build(client, PROMPT)
    req["created_at"] = time.time() - 10_000
    r = client.post("/check", json=req)
    assert r.status_code == 400
    assert "stale" in r.json()["detail"]


def test_future_timestamp_rejected(client):
    import time

    req = _build(client, PROMPT)
    req["created_at"] = time.time() + 10_000
    r = client.post("/check", json=req)
    assert r.status_code == 400
    assert "future" in r.json()["detail"]


def test_missing_timestamp_rejected(client):
    req = _build(client, PROMPT)
    del req["created_at"]
    assert client.post("/check", json=req).status_code == 422


def test_stale_request_does_not_consume_nonce(client):
    """A rejected stale capture must not burn its nonce: the same nonce with a
    fresh timestamp is still accepted afterwards."""
    import time

    req = _build(client, PROMPT, nonce="surviving-nonce")
    req["created_at"] = time.time() - 10_000
    assert client.post("/check", json=req).status_code == 400

    fresh = _build(client, PROMPT, nonce="surviving-nonce")
    assert client.post("/check", json=fresh).status_code == 200


def test_modified_context_digest_rejected(client):
    req = _build(client, PROMPT)
    req["model_digest"] = "ff" * 32
    assert client.post("/check", json=req).status_code == 400
    req2 = _build(client, PROMPT)
    req2["policy_digest"] = "ee" * 32
    assert client.post("/check", json=req2).status_code == 400


def test_tampered_proof_rejected(client):
    import json as _json

    req = _build(client, PROMPT)
    body = client.post("/check", json=req).json()
    artifact = _json.loads(body["decision_proof_json"])
    artifact["verdict"] = "REJECT" if artifact["verdict"] == "ALLOW" else "ALLOW"
    v = client.post("/verify", json={"decision_proof_json": _json.dumps(artifact)})
    assert v.json()["valid"] is False


def test_no_plaintext_prompt_in_transcript(client):
    req = _build(client, PROMPT)
    assert client.post("/check", json=req).status_code == 200
    transcript_json = "\n".join(srv.server.transcript.received)
    for word in PROMPT.lower().split():
        assert word not in transcript_json.lower(), f"plaintext token leaked: {word}"
    assert "features" not in transcript_json


def test_verify_garbage(client):
    v = client.post("/verify", json={"decision_proof_json": "{not json"})
    assert v.status_code == 200 and v.json()["valid"] is False
