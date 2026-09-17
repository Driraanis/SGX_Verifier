#one-shot Phase 0 bootstrap (scaffolding, not core contribution). runs once, before
#any DIDComm, to anchor the Verifier's identity on BCovrin: starts a temporary ACA-Py
#agent, creates the Verifier DID, registers it on the ledger, creates the schema and
#credential definition, writes verifier_config.json, and shuts the agent down.
#sole creator of the Verifier DID; attestation_module.py later reads it from the config
#and publishes the enclave MRENCLAVE under it. the MRENCLAVE ATTRIB is NOT published
#here (that needs the live enclave and belongs to attestation setup)
#
# Usage:
#   LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.bootstrap

import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from runners.vlog import vprint
from typing import Tuple

import aiohttp

#ledger endpoint. GENESIS_URL is derived from LEDGER_URL
LEDGER_URL = os.getenv("LEDGER_URL", "http://test.bcovrin.vonx.io")
GENESIS_URL = LEDGER_URL.rstrip("/") + "/genesis"
#BCovrin self-registration endpoint. HTTPS on purpose: the http form 308-redirects
#and urllib won't re-POST across the redirect
REGISTER_URL = "https://test.bcovrin.vonx.io/register"

#temporary ACA-Py agent identity + ports. the wallet name/key go into
#verifier_config.json so attestation_module.py can open the same wallet to sign
VERIFIER_LABEL = "Verifier"
VERIFIER_WALLET = "verifier.bootstrap"
VERIFIER_WALLET_KEY = "verifier.bootstrap.key"
VERIFIER_HTTP_PORT = 8040
VERIFIER_ADMIN_PORT = 8041
#bootstrap agent endpoint; not persisted or read downstream (the holder takes both the connection and the attestation host from the invitation). AGENT_ENDPOINT overrides for a cross-host bootstrap, else localhost
VERIFIER_ENDPOINT = os.getenv("AGENT_ENDPOINT", f"http://localhost:{VERIFIER_HTTP_PORT}")
ADMIN_URL = f"http://127.0.0.1:{VERIFIER_ADMIN_PORT}"

#schema must match Faber's "degree schema": AnonCreds proof requests match on
#schema_name + attribute names, so identical attrs let Faber-issued credentials
#satisfy the Verifier's request. the Verifier never issues credentials
SCHEMA_NAME = "degree schema"
SCHEMA_VERSION = "1.0"
SCHEMA_ATTRS = ["name", "date", "degree", "birthdate_dateint", "timestamp"]
CRED_DEF_TAG = "verifier.degree schema"

#output: the single source of truth downstream code (attestation, verifier) reads
CONFIG_FILE = Path(__file__).parent / "verifier_config.json"


async def admin_GET(session: aiohttp.ClientSession, path: str, params: dict = None) -> dict:
    """GET the ACA-Py admin API and return the parsed JSON."""
    #admin API is loopback-only (started with --admin-insecure-mode for bootstrap)
    async with session.get(f"{ADMIN_URL}{path}", params=params) as resp:
        resp.raise_for_status()
        return await resp.json()


async def admin_POST(
    session: aiohttp.ClientSession, path: str, body: dict = None, params: dict = None
) -> dict:
    """POST to the ACA-Py admin API and return the parsed JSON."""
    #empty body defaults to {} so the JSON content-type is always set
    async with session.post(f"{ADMIN_URL}{path}", json=body or {}, params=params) as resp:
        resp.raise_for_status()
        return await resp.json()


def start_acapy(genesis_txns: str) -> subprocess.Popen:
    """Start a temporary ACA-Py agent as a subprocess and return its handle.

    Uses an auto-provisioned askar-anoncreds wallet with the genesis passed inline.
    Lives only for the bootstrap and is terminated in main()'s finally block.

    Args: genesis_txns (BCovrin genesis as text). Returns: the ACA-Py subprocess handle.
    """
    #prefer the project venv's python if present, else the current one
    venv = Path(__file__).parent.parent.parent / "venv"
    python = str(venv / "bin" / "python3") if venv.exists() else sys.executable
    cmd = [
        python, "-m", "acapy_agent", "start",
        "--label", VERIFIER_LABEL,
        "--endpoint", VERIFIER_ENDPOINT,
        "--inbound-transport", "http", "0.0.0.0", str(VERIFIER_HTTP_PORT),
        "--outbound-transport", "http",
        #bind admin to loopback only: it's insecure-mode and we only reach it via
        #127.0.0.1, so it must not be network-reachable
        "--admin", "127.0.0.1", str(VERIFIER_ADMIN_PORT),
        #insecure admin is fine now that it's loopback-only + temporary
        "--admin-insecure-mode",
        "--wallet-type", "askar-anoncreds",
        "--wallet-name", VERIFIER_WALLET,
        "--wallet-key", VERIFIER_WALLET_KEY,
        "--auto-provision",
        "--genesis-transactions", genesis_txns,
        "--emit-new-didcomm-prefix",
        "--log-level", "error",
    ]
    vprint(f"[bootstrap] starting ACA-Py on {VERIFIER_HTTP_PORT}/{VERIFIER_ADMIN_PORT}...")
    #capture output so a startup failure can be inspected; agent is short-lived
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


async def wait_for_agent(session: aiohttp.ClientSession, timeout: int = 30) -> None:
    """Poll the admin /status endpoint until the agent is ready, or time out.

    Args: session, timeout (seconds before giving up).
    """
    #poll once a second; a /status with ready/label means it's up
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = await admin_GET(session, "/status")
            if resp.get("ready") or resp.get("label"):
                vprint("[bootstrap] ACA-Py ready.")
                return
        except Exception:
            #not up yet, keep polling
            pass
        await asyncio.sleep(1.0)
    raise TimeoutError("ACA-Py did not become ready in time.")


def _register_did_on_bcovrin(did: str, verkey: str) -> None:
    """Self-register the DID+verkey on BCovrin as a TRUST_ANCHOR (writes a NYM).

    Args: did, verkey.
    """
    #BCovrin's test net lets anyone self-register a NYM via this endpoint
    reg_data = json.dumps({
        "did": did,
        "verkey": verkey,
        "alias": "Verifier",
        "role": "TRUST_ANCHOR",
    }).encode()
    req = urllib.request.Request(
        REGISTER_URL,
        data=reg_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    #HTTPS endpoint; the http form 308-redirects and would drop the POST body
    with urllib.request.urlopen(req) as resp:
        reg = json.loads(resp.read())
    vprint(f"[bootstrap] BCovrin register: {reg}")


async def create_and_register_did(session: aiohttp.ClientSession) -> Tuple[str, str]:
    """Create the Verifier DID via ACA-Py, register it on BCovrin, set it public.

    Bootstrap is the sole creator of the Verifier DID; downstream code reads it
    from the config rather than making its own (single-DID rule).

    Args: session. Returns: (did, verkey).
    """
    #ACA-Py creates the ed25519 sov DID in its own wallet (managed keys)
    vprint("[bootstrap] creating DID via ACA-Py...")
    result = await admin_POST(session, "/wallet/did/create", {"method": "sov"})
    did = result["result"]["did"]
    verkey = result["result"]["verkey"]
    vprint(f"[bootstrap] DID {did}  verkey {verkey}")

    #anchor it on the ledger, then promote it to the wallet's public DID
    _register_did_on_bcovrin(did, verkey)
    await admin_POST(session, "/wallet/did/public", params={"did": did})
    #give the ledger a moment to propagate before schema/cred-def writes
    await asyncio.sleep(3.0)
    vprint(f"[bootstrap] public DID set: {did}")
    return did, verkey


async def _poll_for_id(
    session: aiohttp.ClientSession, path: str, key: str
) -> str:
    """Poll a list endpoint for the most recent id under `key`, or return "".

    Some anoncreds writes report the id asynchronously; if the create response
    didn't carry it, poll the list endpoint a few times.

    Args: session, path (list endpoint), key (field holding the id list).
    Returns: the newest id, or "" if none appeared.
    """
    #retry a few times; the write usually lands within seconds
    for _ in range(5):
        r = await admin_GET(session, path)
        ids = r.get(key, [])
        if ids:
            return ids[-1]
        await asyncio.sleep(2.0)
    return ""


async def create_schema(session: aiohttp.ClientSession, issuer_did: str) -> str:
    """Create the degree schema on BCovrin and return its schema_id.

    Args: session, issuer_did (owns the schema). Returns: the schema_id.
    """
    vprint(f"[bootstrap] creating schema '{SCHEMA_NAME}' v{SCHEMA_VERSION}...")
    body = {
        "schema": {
            "attrNames": SCHEMA_ATTRS,
            "issuerId": issuer_did,
            "name": SCHEMA_NAME,
            "version": SCHEMA_VERSION,
        },
        "options": {},
    }
    resp = await admin_POST(session, "/anoncreds/schema", body)
    await asyncio.sleep(3.0)
    #prefer the id from the create response, else poll the list endpoint
    schema_id = resp.get("schema_state", {}).get("schema_id")
    if not schema_id:
        schema_id = await _poll_for_id(session, "/anoncreds/schemas", "schema_ids")
    if not schema_id:
        raise RuntimeError("schema creation failed")
    vprint(f"[bootstrap] schema {schema_id}")
    return schema_id


async def create_cred_def(
    session: aiohttp.ClientSession, issuer_did: str, schema_id: str
) -> str:
    """Create the (irrevocable) credential definition and return its id.

    Args: session, issuer_did (owns the cred def), schema_id (its base schema).
    Returns: the credential_definition_id.
    """
    vprint("[bootstrap] creating credential definition...")
    body = {
        "credential_definition": {
            "tag": CRED_DEF_TAG,
            "schemaId": schema_id,
            "issuerId": issuer_did,
        },
        #irrevocable by design (revocation is out of scope)
        "options": {"support_revocation": False},
    }
    resp = await admin_POST(session, "/anoncreds/credential-definition", body)
    await asyncio.sleep(3.0)
    cred_def_id = resp.get("credential_definition_state", {}).get(
        "credential_definition_id"
    )
    if not cred_def_id:
        cred_def_id = await _poll_for_id(
            session, "/anoncreds/credential-definitions", "credential_definition_ids"
        )
    if not cred_def_id:
        raise RuntimeError("cred def creation failed")
    vprint(f"[bootstrap] cred def {cred_def_id}")
    return cred_def_id


def write_config(did: str, verkey: str, schema_id: str, cred_def_id: str) -> None:
    """Write verifier_config.json — the single source of truth for downstream code.

    Includes the wallet name/key so attestation_module.py can open the same wallet
    to sign the ATTRIB write.

    Args: did, verkey, schema_id, cred_def_id.
    """
    config = {
        "did": did,
        "verkey": verkey,
        "schema_id": schema_id,
        "cred_def_id": cred_def_id,
        "wallet_name": VERIFIER_WALLET,
        "wallet_key": VERIFIER_WALLET_KEY,
        "schema_name": SCHEMA_NAME,
        "schema_attrs": SCHEMA_ATTRS,
        "ledger_url": LEDGER_URL,
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    vprint(f"[bootstrap] wrote {CONFIG_FILE}")


def _fetch_genesis() -> str:
    """Fetch the BCovrin genesis transactions as text (host CA store; plain GET)."""
    with urllib.request.urlopen(GENESIS_URL) as r:
        return r.read().decode()


def _stop_acapy(proc: subprocess.Popen) -> None:
    """Terminate the temporary ACA-Py agent, killing it if it does not stop."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    vprint("[bootstrap] ACA-Py stopped.")


def _guard_not_already_bootstrapped() -> None:
    """Refuse to re-run if a config already exists, unless BOOTSTRAP_FORCE is set.

    Re-running would create a fresh DID/schema/cred def (ledger writes that can't
    be undone) and overwrite verifier_config.json, orphaning the old identity. So
    bootstrap is create-if-absent, else refuse loudly. Set BOOTSTRAP_FORCE=1 to
    bootstrap a new identity anyway.
    """
    #config present + no force -> stop before any ledger write
    if CONFIG_FILE.exists() and os.getenv("BOOTSTRAP_FORCE") != "1":
        vprint(f"[bootstrap] {CONFIG_FILE} already exists — refusing to re-bootstrap.")
        vprint("[bootstrap] this would create a new DID/schema/cred def on BCovrin and")
        vprint("[bootstrap] orphan the current identity. Set BOOTSTRAP_FORCE=1 to override.")
        sys.exit(1)


async def main() -> None:
    """Run the one-shot bootstrap: DID + schema + cred def -> verifier_config.json."""
    #refuse a re-run that would orphan the existing identity (ledger writes)
    _guard_not_already_bootstrapped()
    #fetch genesis, then start the temporary agent with it
    genesis_txns = _fetch_genesis()
    vprint(f"[bootstrap] genesis: {len(genesis_txns)} bytes")
    proc = start_acapy(genesis_txns)
    #give the process a moment before polling the admin API
    await asyncio.sleep(4.0)

    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            await wait_for_agent(session)
            #bootstrap creates the DID; schema and cred def are anchored under it
            did, verkey = await create_and_register_did(session)
            schema_id = await create_schema(session, did)
            cred_def_id = await create_cred_def(session, did, schema_id)
        finally:
            #always stop the temporary agent, even on failure
            _stop_acapy(proc)

    #persist the results for attestation_module.py and the verifier runner
    write_config(did, verkey, schema_id, cred_def_id)
    vprint("[bootstrap] complete.")


if __name__ == "__main__":
    asyncio.run(main())
