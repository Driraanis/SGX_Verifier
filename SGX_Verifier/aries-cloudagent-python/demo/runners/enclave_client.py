#REE-side client that forwards a presentation to the enclave and returns its verdict
#scaffolding: client half of the REE->TEE path, the actual verify runs in enclave_server.py

import aiohttp
import asyncio
import json
import os
from time import perf_counter
from typing import Tuple
from runners.vlog import vprint, VIOLET_STYLE
from runners.support.utils import log_msg

#enclave verify endpoint, loopback only, overridable via env for tests
ENCLAVE_URL = os.environ.get("ENCLAVE_VERIFY_URL", "http://127.0.0.1:5000/verify")
#longer timeout because the enclave hits the ledger for schema/cred def
REQUEST_TIMEOUT = float(os.environ.get("ENCLAVE_TIMEOUT", 30))

#health endpoint on the same host:port, polled for readiness
ENCLAVE_HEALTH_URL = os.environ.get("ENCLAVE_HEALTH_URL", "http://127.0.0.1:5000/health")


async def wait_for_enclave_ready(timeout: float = REQUEST_TIMEOUT) -> None:
    """Poll the enclave's /health endpoint until it returns 200 (ready).

    Blocks until /health answers 200, or raises after `timeout` seconds.

    Args: timeout (max seconds to wait before giving up).
    """
    #time deadline to get an answer from enclave
    deadline = perf_counter() + timeout
    async with aiohttp.ClientSession() as session:
        while perf_counter() < deadline:
            try:
                async with session.get(ENCLAVE_HEALTH_URL) as resp:
                    if resp.status == 200:
                        return
            except aiohttp.ClientError:
                #not up yet, retry
                pass
            await asyncio.sleep(0.1)
    #never got 200 in time
    raise RuntimeError(f"enclave not ready after {timeout}s")


async def verify_in_enclave(pres_req: dict, pres: dict) -> Tuple[bool, list]:
    """Send a presentation to the enclave and return its verdict.

    Same argument order as verify() so it can replace it directly in the
    handler. Returns the verdict on HTTP 200, raises RuntimeError otherwise or
    if the enclave can't be reached.

    Args: pres_req (proof request), pres (presentation). Returns: (verified, msgs).
    """
    #both are dicts, so a swapped order wouldn't be caught by type checking
    payload = {"pres_req": pres_req, "pres": pres}
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            #time the full REE round-trip: HTTP + enclave work
            roundtrip_t0 = perf_counter()
            async with session.post(ENCLAVE_URL, json=payload) as resp:
                #read as text first, error responses aren't always JSON
                text = await resp.text()
                if resp.status != 200:
                    raise RuntimeError(
                        f"Enclave could not evaluate (HTTP {resp.status}): {text}"
                    )
                log_msg(
                    f"[timing] verify (REE round-trip): {perf_counter() - roundtrip_t0:.6f} s",
                    color=VIOLET_STYLE,
                )
                body = json.loads(text)
                return (body["verified"], body["msgs"])
        except aiohttp.ClientConnectorError as err:
            #server unreachable: connection refused / down
            raise RuntimeError(
                f"Cannot reach enclave server at {ENCLAVE_URL}: {err}. "
                "Is enclave_server.py running inside Gramine?"
            ) from err
