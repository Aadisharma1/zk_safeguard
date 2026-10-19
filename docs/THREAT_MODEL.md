# zk-SAFEGUARD Threat Model

An explicit statement of what this proof-of-concept does and does not defend
against. Every limitation below is also enforced by the code's structure or
tests — nothing here is aspirational.

## Assets and parties

| Party | Holds | Wants |
|---|---|---|
| Client | the plaintext prompt, the salt for its commitment, its own feature extraction | prove nothing about the prompt leaks; obtain a legitimate ACCEPT |
| Server | CKKS secret key, public policy + model digests, transcript of everything received | enforce the safety decision without learning prompt content |
| Verifier (third party) | only the decision artifact | detect tampering with a recorded decision |

Assets: the prompt's plaintext content; the plaintext feature vector; the
integrity of recorded decisions (verdict + commitment + digests + nonce).

## What genuinely protects what

| Mechanism | Protects | Does NOT protect |
|---|---|---|
| CKKS encryption (TenSEAL) | prompt plaintext and the feature vector from the server; only the aggregated scalar is decrypted | against a malicious server leaking the decrypted score side-channel; the score itself is visible |
| SHA-256 salted commitment | prompt binding after the fact (can't change the claimed prompt without the salt) | against a client that lies at commit time — the salt is the client's own |
| Nonce single-use (server set) | replaying an old captured request | nonce reuse across server restarts (the set is in-memory; see limitations) |
| Freshness window on `created_at` | stale captures being replayed after the window; clock-skewed future stamps | a live attacker with a fresh clock — freshness windows are not authentication |
| `FiatShamirPrototype` artifact | *tamper-evidence* for a recorded decision transcript: any modification of commitment/verdict/digests/nonce breaks challenge recomputation | **nothing against a malicious prover** — all fields are public, so anyone can mint a valid artifact for any verdict. This is NOT zero-knowledge and NOT sound. |
| Digest pinning (`policy_digest`, `model_digest`) | silently evaluating under a different policy/model than advertised | a colluding server that rotates both policy and artifacts together |

## Explicit non-claims

1. **No zk-SNARK.** The proof backend is a hash-bound transcript. It is
   labeled `fiat_shamir_prototype` in every artifact, and the abstract
   `ProofBackend` interface raises `NotImplementedError` rather than pretending
   a real proving system exists. Soundness requires a real backend (e.g. a
   SNARK circuit over the policy evaluation, or a zkVM proof); the interface is
   the documented swap point.
2. **No guarantee the model is a good safety classifier.** The encrypted model
   is a linear scorer over hashed token features, chosen to make the FHE path
   real. Its risk scores are not safety judgments of recordable quality.
3. **No hardware security.** The CKKS secret key lives in server process
   memory. No HSM, no key rotation, no secure enclave.
4. **No network security in this repo.** The API has no TLS here; in any real
   deployment it must sit behind TLS, with client authentication. The smoke
   tests talk over localhost by design.
5. **The scalar risk score is intentionally visible to the server.** The
   central service must enforce the decision; hiding the score too would
   require the client to hold the decision right, which changes the trust
   model entirely. This boundary is chosen and stated, not accidental.

## Attack tests and what each proves

| Test / smoke outcome | Proves |
|---|---|
| unsafe-constructed prompt → REJECT | the encrypted path actually drives the decision |
| tampered verdict in artifact → verify FAIL | artifact tamper-evidence works |
| modified model/policy digest → 400 | evaluation is pinned to the advertised policy+model |
| replayed nonce → 409 | single-use nonces work within process lifetime |
| stale `created_at` → 400, and the nonce is **not consumed** | freshness window works; rejection cannot poison the nonce set |
| transcript grep for prompt tokens → none | the server never receives plaintext context |
| public-context decrypt raises | the serialized client context truly lacks the secret key |

## Deployment gaps (the honest list)

- Nonce state and transcript are in-process only; a multi-instance deployment
  needs shared, append-only nonce storage (with the nonce set backed by the
  same store), or the replay protection evaporates behind a load balancer.
- The freshness window assumes roughly synchronized clocks (60s future skew is
  allowed); hostile clock manipulation is out of scope.
- The policy engine's regexes are example-grade. Real policy engines need
  versioning, audit trails of policy changes, and an approval process — the
  `policy_digest` mechanism exists so such changes are at least *detectable*.
- No rate limiting: the CKKS pipeline is CPU-expensive per request, and an
  unauthenticated `/setup` + `/check` pair is a DoS surface in this PoC.
