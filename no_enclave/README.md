# no_enclave — plain-ACA-Py verification baseline

The **no-enclave baseline**: the same DIDComm Verifiable Credential verification
flow as the SGX verifier, but the proof is verified **natively inside the ACA-Py
agent** instead of inside an Intel SGX enclave. It is used as the no-TEE
reference point for the performance and behaviour comparison — no enclave, no
remote attestation, no trust registry.

Three agents take part:

- **Verifier** (`demo/runners/verifier.py`) — publishes a multi-use invitation
  and, once a connection completes, auto-sends a proof request and verifies the
  presentation natively (`Proof 2.0 = True/False`).
- **Holder (Alice)** — holds a credential and presents proofs.
- **Issuer (Faber)** — seeds Alice's wallet with a credential.

The verifier's proof request always includes a `non_revoked` interval, so the
**same code runs both modes** — a plain (non-revocable) credential still
verifies, and a revocable one is checked against the ledger's revocation status.

---

## Prerequisites

| Component | Value |
|---|---|
| Python | 3.13 |
| Ledger | Hyperledger Indy — BCovrin test net (`http://test.bcovrin.vonx.io`) |
| Tails server | only for the revocation run (see below) |

---

## Install dependencies

Run these **in order**, from a clean machine. This order installs everything
once with no missing modules and no redundant re-installs.

```bash
cd ~/no_enclave/aries-cloudagent-python

# 1) create and activate a Python 3.13 virtual environment
python3.13 -m venv venv
source venv/bin/activate

# 2) upgrade pip first (avoids the "new pip available" notice mid-install)
pip install -U pip

# 3) ACA-Py itself, editable
#    (pulls in aiohttp, aries-askar, indy-vdr, anoncreds as declared dependencies)
pip install -e .

# 4) the demo-only requirements (asyncpg, prompt_toolkit, pygments, qrcode)
pip install -r demo/requirements.txt
```

Sanity check:

```bash
python -c "import aries_askar, indy_vdr, anoncreds, asyncpg, qrcode; print('venv OK')"
```

> **Activate the venv before every session.** From `demo/` use
> `source ../venv/bin/activate`. If `pip` prints
> `error: externally-managed-environment`, the venv is **not** active — it is
> hitting the system Python. Activate it; never use `--break-system-packages`.

---

## Run — without revocation

Three terminals, each with the venv active. No tails server needed.

```bash
# Faber (issuer, port 8020)
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.faber --port 8020 \
  --wallet-type askar-anoncreds
```

```bash
# Alice (holder, port 8030)
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.alice --port 8030 \
  --wallet-type askar-anoncreds
```

```bash
# Verifier (port 8040)
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.verifier --port 8040 \
  --wallet-type askar-anoncreds
```

**Flow**

1. Paste **Faber's** invitation into Alice, then Faber menu **(1) Issue Credential**.
2. On Alice, **(4) Input New Invitation** → paste the **Verifier's** invitation.
3. The connection completes → the verifier auto-sends the proof request → Alice
   presents → the verifier prints **`Proof 2.0 = True`**.

---

## Run — with revocation

Same as above, plus a tails server, and Faber launched with revocation flags.
**Alice and the Verifier commands are unchanged** (Alice needs no tails flag —
she reads the tails location from the ledger).

### One-time: install the tails server (its own venv)

```bash
git clone https://github.com/bcgov/indy-tails-server ~/indy-tails-server
python3.13 -m venv ~/indy-tails-server/venv
source ~/indy-tails-server/venv/bin/activate
pip install -U pip
cd ~/indy-tails-server && pip install .
```

### Terminal 1 — tails server (start first)

```bash
source ~/indy-tails-server/venv/bin/activate
mkdir -p ~/tails-files
tails-server --host 0.0.0.0 --port 9000 \
  --storage-path ~/tails-files \
  --log-config ~/indy-tails-server/tails_server/config/logging-config.yml
```

Confirm it is up: `curl http://localhost:9000/` → `404` is the expected
"listening and routing" signal.

### Terminal 2 — Faber (revocable issuance)

```bash
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.faber --port 8020 \
  --wallet-type askar-anoncreds \
  --revocation --tails-server-base-url http://localhost:9000
```

On startup the tails server logs **two `PUT` 200s** and two files appear under
`~/tails-files` — the revocation registry and its tails file.

### Terminal 3 — Alice (same command, no tails flag)

```bash
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.alice --port 8030 \
  --wallet-type askar-anoncreds
```

### Terminal 4 — Verifier (same command)

```bash
cd ~/no_enclave/aries-cloudagent-python/demo && source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.verifier --port 8040 \
  --wallet-type askar-anoncreds
```

**Flow (not-revoked → True, then revoked → False)**

1. Issue and verify as in the plain flow → **`Proof 2.0 = True`**.
2. **Revoke:** Faber menu **(5) Revoke Credential** → paste the **full**
   revocation registry ID (the complete `...:4:...:CL_ACCUM:0` string) + the
   credential revocation ID (`1`) → **Publish now? `Y`**. Alice logs a
   revocation notification.
3. On Alice, **(4) Input New Invitation** → paste the Verifier invitation again
   (a **fresh** connection, so the proof carries a post-revocation timestamp) →
   the verifier resolves the updated status list from the ledger → **`Proof 2.0
   = False`**.

> Paste the **complete** revocation registry ID in step 2 — a truncated one
> makes Faber crash at publish.

---

## Ports

| Port | Component |
|---|---|
| 8020 | Faber (issuer) |
| 8030 | Alice (holder) |
| 8040 | Verifier |
| 9000 | tails server (revocation run only) |
