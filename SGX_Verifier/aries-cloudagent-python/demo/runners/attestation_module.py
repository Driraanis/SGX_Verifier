#REE-side attestation module (core contribution): fetches the enclave's SGX quote
#over the loopback quote endpoint, verifies it via Intel DCAP against Intel PCS,
#and exposes the enclave's measured identity (MRENCLAVE) so the holder can compare it

import asyncio
import ctypes
import glob
import json
import os
import sys
import time
import urllib.request
from base64 import b64decode
from pathlib import Path
#shared violet printer, so this tool matches the rest of the project's output
from runners.vlog import vprint
from typing import Tuple

#ledger + wallet libs (REE side): indy_vdr builds/submits the ATTRIB, aries_askar
#loads the Verifier DID's signing key from the wallet bootstrap.py made. both must be in the REE venv
from aries_askar import Store
from indy_vdr import ledger, open_pool

#enclave quote endpoint, the loopback route the enclave serves the quote on
ENCLAVE_QUOTE_URL = "http://127.0.0.1:5000/quote"
#Azure DCAP client library, preloaded RTLD_GLOBAL for symbol visibility; the QVL
#is then pointed at the Intel QPL (see _load_dcap_libraries) so collateral comes
#from Intel PCS, not THIM (whose data for this platform expired in 2021)
AZURE_DCAP_CLIENT_PATH = "/usr/local/lib/libdcap_quoteprov.so"
#Intel DCAP Quote Verification Library, the TEE quote-verification calls
QVL_PATH = "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1"
#ledger endpoint, same contract as bootstrap.py: GENESIS_URL is derived from LEDGER_URL
LEDGER_URL = os.getenv("LEDGER_URL", "http://test.bcovrin.vonx.io")
GENESIS_URL = LEDGER_URL.rstrip("/") + "/genesis"
#Verifier DID config bootstrap.py writes beside this module; read to build the DID doc
CONFIG_PATH = Path(__file__).resolve().parent / "verifier_config.json"
#attestation output: the verifier_did.json this module writes, beside this file
DID_JSON_PATH = Path(__file__).resolve().parent / "verifier_did.json"

#wallet holding the Verifier DID's signing key, made by bootstrap.py; opened here
#only to sign the ATTRIB write. path must match where bootstrap.py provisions it.
#Askar sqlite:// URIs take two slashes before an absolute path, three fails
VERIFIER_WALLET = "verifier.bootstrap"
WALLET_DB_PATH = Path.home() / ".acapy_agent" / "wallet" / VERIFIER_WALLET / "sqlite.db"
#wallet key-derivation method. bootstrap.py passes no flag, so ACA-Py's default is
#used; confirmed on the VM to be kdf:argon2i:mod (this or None unlocks it, argon2i:int
#and raw fail "key method mismatch"). passed explicitly so we don't rely on the default
WALLET_KEY_DERIVATION = "kdf:argon2i:mod"

#MRENCLAVE is bytes 112..144 of the quote: 48-byte header + report body, whose
#MRENCLAVE sits at body offset 64 (48+64=112), 32 bytes long
MRENCLAVE_SLICE = slice(112, 144)

#keeps the Azure DCAP client library resident once loaded (RTLD_GLOBAL so the QVL sees its symbols)
_AZURE_DCAP_CLIENT = None


def fetch_quote() -> bytes:
    """Fetch the enclave's fresh SGX quote from its loopback quote endpoint.

    GETs the enclave, which answers a JSON object with the quote base64-encoded;
    decoding that field gives the raw quote bytes.

    Returns: the raw SGX quote as bytes.
    """
    #GET the quote endpoint and parse the JSON envelope
    with urllib.request.urlopen(ENCLAVE_QUOTE_URL) as resp:
        payload = json.load(resp)
    #the "quote" field is base64, decode back to raw bytes
    return b64decode(payload["quote"])


def extract_mrenclave(quote: bytes) -> str:
    """Extract MRENCLAVE from a raw SGX quote as a hex string.

    Slices the 32-byte MRENCLAVE out of the quote and renders it as 64 hex chars
    so the holder can compare it against the expected measurement.

    Args: quote (raw SGX quote bytes). Returns: the 64-char hex MRENCLAVE.
    """
    #slice the fixed 32-byte MRENCLAVE span and render as hex
    return quote[MRENCLAVE_SLICE].hex()


# --- DCAP quote-verification core (core contribution) -----------------------
#sgx_ql_qv_result_t values, taken from Intel's sgx_qve_header.h. these are NOT
#0/1/2: only OK is 0, every other verdict lives in the 0xA00x range. verdicts are
#classified by MEANING rather than kept as a fixed accept-list, so that a platform
#whose TCB status drifts over time does not silently break verification.
#kept identical to holder_attestation_verifier.py: both must agree on what
#"verified" means, since the holder re-checks what this module anchored
#quote is authentic AND the platform TCB is current -> clean pass
VERDICT_OK = (
    0x0000,  # OK
    0xA007,  # SW_HARDENING_NEEDED: TCB current, enclave-side mitigations advised
)
#quote is authentic but the platform is behind or misconfigured -> accept, but say
#so loudly. these weaken the platform guarantee without making the quote untrusted
VERDICT_WARN = (
    0xA001,  # CONFIG_NEEDED
    0xA002,  # OUT_OF_DATE
    0xA003,  # OUT_OF_DATE_CONFIG_NEEDED
    0xA008,  # CONFIG_AND_SW_HARDENING_NEEDED
)
#the quote itself cannot be trusted -> never accept, under any policy
VERDICT_REJECT = (
    0xA004,  # INVALID_SIGNATURE
    0xA005,  # REVOKED
    0xA006,  # UNSPECIFIED
)

#the Intel QPL honours /etc/sgx_default_qcnl.conf; the Azure DCAP client library
#ignores it and sources collateral from THIM, which serves collateral expired in
#2021 for this platform. the QVL's own dlopen picks the wrong one, so it is set explicitly
INTEL_QPL_GLOB = "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.*"
#sgx_qv_path_type_t: SGX_QV_QVE_PATH = 0, SGX_QV_QPL_PATH = 1
SGX_QV_QPL_PATH = 1


class SuppDataDescriptor(ctypes.Structure):
    """Supplemental-data output descriptor passed to tee_verify_quote.

    Version/size/buffer triple the QVL fills with supplemental verification data.
    Field order and types mirror the Intel C header exactly; ctypes lays it out by
    declaration order. Confirmed against the VM's QVL.
    """

    _fields_ = [
        #descriptor version the QVL writes supplemental data under
        ("major_version", ctypes.c_uint32),
        #size in bytes of the buffer p_data points at
        ("data_size", ctypes.c_uint32),
        #pointer to the caller-allocated supplemental-data buffer
        ("p_data", ctypes.c_void_p),
    ]


def _configure_dcap_signatures(qvl: ctypes.CDLL) -> None:
    """Declare argument and return types for the QVL C functions.

    ctypes defaults args and return to C int; on x86-64 that truncates 64-bit
    pointers to 32 bits and corrupts the calls. Declaring the signatures is what
    makes the pointer args pass intact.

    Args: qvl (the loaded QVL handle).
    """
    #tee_qv_get_collateral(quote, quote_size, *collateral, *collateral_size)
    qvl.tee_qv_get_collateral.restype = ctypes.c_uint32
    qvl.tee_qv_get_collateral.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32),
    ]
    #tee_qv_free_collateral(collateral): frees what get_collateral allocated
    qvl.tee_qv_free_collateral.restype = ctypes.c_uint32
    qvl.tee_qv_free_collateral.argtypes = [ctypes.c_void_p]
    #sgx_qv_get_quote_supplemental_data_size(*size): supplemental buffer size
    qvl.sgx_qv_get_quote_supplemental_data_size.restype = ctypes.c_uint32
    qvl.sgx_qv_get_quote_supplemental_data_size.argtypes = [
        ctypes.POINTER(ctypes.c_uint32),
    ]
    #tee_verify_quote(quote, size, collateral, exp_date, *exp_status, *result,
    #  qve_report_info, *supp_desc) — EIGHT args, verbatim from Intel's
    #sgx_dcap_quoteverify.h. the collateral is a bare pointer with NO size
    #argument: passing one shifts every later argument and the call fails 0xe001
    qvl.tee_verify_quote.restype = ctypes.c_uint32
    qvl.tee_verify_quote.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_long,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(SuppDataDescriptor),
    ]
    #sgx_qv_set_path(path_type, path): tells the QVL which QPL to load instead of
    #relying on its internal dlopen of the libdcap_quoteprov.so.1 soname
    qvl.sgx_qv_set_path.restype = ctypes.c_uint32
    qvl.sgx_qv_set_path.argtypes = [ctypes.c_int, ctypes.c_char_p]


def _load_dcap_libraries() -> ctypes.CDLL:
    """Load the Azure DCAP client library and the Intel QVL, in that order.

    The client library loads first with RTLD_GLOBAL so its symbols are visible when the
    QVL looks up the provider (loading it after, or locally, gives the
    provider-not-found failure). The handle is kept in a module global so it stays
    resident. Signatures are configured before returning.

    Returns: the configured QVL handle.
    """
    global _AZURE_DCAP_CLIENT
    #provider first, globally visible, kept resident via the module global
    _AZURE_DCAP_CLIENT = ctypes.CDLL(AZURE_DCAP_CLIENT_PATH, mode=ctypes.RTLD_GLOBAL)
    #QVL second; resolves the provider symbols already in the process
    qvl = ctypes.CDLL(QVL_PATH)
    _configure_dcap_signatures(qvl)
    #point the QVL at the Intel QPL. left to itself it dlopens the
    #libdcap_quoteprov.so.1 soname, which on this VM resolves to a provider that
    #sources collateral from THIM — expired since 2021 for this platform,
    #making every verification fail with SGX_QL_TCBINFO_CHAIN_ERROR (0xe03a)
    qpl = _find_intel_qpl()
    if qpl is None:
        vprint("[quote verification] warning: no Intel quote provider found, "
                "the collateral may be out of date")
    else:
        ret = qvl.sgx_qv_set_path(SGX_QV_QPL_PATH, qpl.encode())
        if ret != 0:
            vprint("[quote verification] warning: could not select the Intel quote "
                    f"provider (sgx_qv_set_path returned 0x{ret & 0xFFFFFFFF:08x})")
    return qvl


def _find_intel_qpl() -> "str | None":
    """Locate the Intel quote-provider library at run time.

    Globbed rather than pinned to a versioned filename so a package update that
    bumps the version does not silently break collateral retrieval. The newest
    match wins; ".bak"-suffixed copies are skipped.

    Returns: path to the Intel QPL, or None if none is present.
    """
    #newest version last; skip any renamed/backup copies
    candidates = sorted(c for c in glob.glob(INTEL_QPL_GLOB) if not c.endswith(".bak"))
    return candidates[-1] if candidates else None


def _get_collateral(
    qvl: ctypes.CDLL, quote: bytes
) -> Tuple[ctypes.c_void_p, ctypes.c_uint32]:
    """Fetch verification collateral (certs + revocation info) for a quote.

    The QVL calls the provider, which fetches collateral from Intel PCS and
    allocates it; we get an opaque pointer + size and never lay it out ourselves.
    Raises on a non-zero status so a provider or Intel PCS failure surfaces here instead
    of corrupting the later verify call.

    Args: qvl (QVL handle), quote. Returns: (collateral pointer, collateral size).
    """
    collateral = ctypes.c_void_p(0)
    collateral_size = ctypes.c_uint32(0)
    ret = qvl.tee_qv_get_collateral(
        ctypes.c_char_p(quote),
        ctypes.c_uint32(len(quote)),
        ctypes.byref(collateral),
        ctypes.byref(collateral_size),
    )
    if ret != 0:
        raise RuntimeError(f"tee_qv_get_collateral failed: 0x{ret & 0xFFFFFFFF:08x}")
    return collateral, collateral_size


def _make_supplemental_descriptor(
    qvl: ctypes.CDLL,
) -> Tuple[SuppDataDescriptor, "ctypes.Array"]:
    """Allocate the supplemental-data buffer and describe it for tee_verify_quote.

    Asks the QVL for the exact supplemental-data size (hardcoding it breaks across
    QVL versions), allocates that buffer, and wraps it in a descriptor. The buffer
    is returned alongside the descriptor because the descriptor only holds a raw
    pointer into it — the caller must keep the buffer alive or the pointer dangles.

    Args: qvl (QVL handle). Returns: (descriptor, backing buffer).
    """
    supp_size = ctypes.c_uint32(0)
    #ask for the exact size; a non-zero status means it's unreliable
    ret = qvl.sgx_qv_get_quote_supplemental_data_size(ctypes.byref(supp_size))
    if ret != 0:
        raise RuntimeError(
            f"sgx_qv_get_quote_supplemental_data_size failed: 0x{ret & 0xFFFFFFFF:08x}"
        )
    #allocate the buffer the QVL will fill; kept alive by being returned
    supp_buffer = (ctypes.c_uint8 * supp_size.value)()
    descriptor = SuppDataDescriptor(
        major_version=0,
        data_size=supp_size.value,
        p_data=ctypes.cast(supp_buffer, ctypes.c_void_p),
    )
    return descriptor, supp_buffer


def _verify_with_collateral(
    qvl: ctypes.CDLL,
    quote: bytes,
    collateral: ctypes.c_void_p,
    supp_desc: SuppDataDescriptor,
) -> Tuple[bool, int]:
    """Run tee_verify_quote and apply the acceptance policy to the verdict.

    Verifies the quote against the fetched collateral as of now, passing a null
    qve_report_info for host-side verification. Three signals decide the outcome:
    the call's own return code (a failure leaves the outputs unwritten, so it must
    be checked first), the collateral expiration status, and the verdict. Verdicts
    are classified by meaning — current-TCB accepted, platform-behind accepted with
    a warning, untrusted or unrecognised rejected (fail closed).

    Args: qvl, quote, collateral, supp_desc.
    Returns: (accepted, verdict code).
    """
    exp_status = ctypes.c_uint32(0)
    quote_verification_result = ctypes.c_uint32(0)
    ret = qvl.tee_verify_quote(
        ctypes.c_char_p(quote),
        ctypes.c_uint32(len(quote)),
        collateral,
        #check collateral expiry against the current time
        ctypes.c_long(int(time.time())),
        ctypes.byref(exp_status),
        ctypes.byref(quote_verification_result),
        #null qve_report_info: host-side (REE) verification, not QvE-attested
        None,
        ctypes.byref(supp_desc),
    )
    verdict = quote_verification_result.value
    #the return code MUST be checked first: on anything but SGX_QL_SUCCESS the QVL
    #sets the verdict to UNSPECIFIED and exp_status non-zero, so neither is a result.
    #skipping this check is what let every quote pass under the old 9-argument call,
    #where the outputs were written to shifted addresses and stayed at their initial 0
    if ret != 0:
        vprint(
            "[quote verification] could not run the DCAP check: "
            f"tee_verify_quote returned 0x{ret & 0xFFFFFFFF:08x}, so there is no verdict"
        )
        return False, verdict
    #expired collateral means the verdict was reached against stale trust data
    if exp_status.value != 0:
        vprint("[quote verification] rejected: the collateral used for the check has "
                f"expired (exp_status={exp_status.value})")
        return False, verdict
    #classify by meaning so platform-TCB drift cannot silently break verification
    if verdict in VERDICT_OK:
        return True, verdict
    if verdict in VERDICT_WARN:
        #authentic quote, but the platform is behind or misconfigured: accept and
        #report it, never silently. a production deployment should reject these
        vprint(
            f"[quote verification] accepted with a warning, verdict 0x{verdict:04x}: the quote "
            "is genuine but this platform is behind on patches or misconfigured"
        )
        return True, verdict
    #known-bad and anything unrecognised: fail closed rather than fail open
    vprint(f"[quote verification] rejected: verdict 0x{verdict:04x}, this quote is not trusted")
    return False, verdict


def verify_quote(quote: bytes) -> Tuple[bool, int]:
    """Verify an SGX quote via Intel DCAP against Intel PCS.

    Loads the DCAP libraries, fetches collateral, sizes and allocates the
    supplemental-data buffer, then verifies. Collateral is always freed
    afterwards, even on error. The supplemental buffer is held in a local across
    the verify call so the descriptor's pointer stays valid.

    Args: quote. Returns: (accepted, verdict code).
    """
    qvl = _load_dcap_libraries()
    collateral, _collateral_size = _get_collateral(qvl, quote)
    try:
        #keep supp_buffer referenced here: supp_desc points into it
        supp_desc, supp_buffer = _make_supplemental_descriptor(qvl)
        return _verify_with_collateral(qvl, quote, collateral, supp_desc)
    finally:
        #free the library-allocated collateral no matter the outcome
        qvl.tee_qv_free_collateral(collateral)


# --- Ledger side: publish/read the MRENCLAVE ATTRIB (attestation provisioning) --
#the REE writes exactly one thing to BCovrin: the MRENCLAVE, as an ATTRIB under the
#Verifier DID. it's provisioning data the holder looks up in Phase 2, never a
#verification trust anchor (the enclave fetches schema/cred-def itself). this write
#is REE-side by nature: it needs the DID's signing key, which lives in the REE wallet
#— the enclave has no wallet


def fetch_genesis(url: str) -> str:
    """Fetch the BCovrin genesis transactions as text.

    Runs on the normal host with its CA store, so plain urllib validates BCovrin's
    HTTP->HTTPS redirect without disabling TLS (unlike the enclave's fetch_genesis,
    which uses ssl=False because the Gramine LibOS has no CA store).

    Args: url. Returns: the genesis transactions as text.
    """
    #plain GET; urllib follows the redirect and validates against the system CAs
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode("utf-8")


async def open_attrib_pool(genesis_url: str) -> "open_pool":
    """Open the attestation-provisioning ledger pool.

    Publishes the MRENCLAVE ATTRIB (and reads it back); never fetches trust
    anchors — that is the enclave's job. open_pool takes the genesis text, not a
    URL, so it is fetched first.

    Args: genesis_url. Returns: an open indy_vdr pool handle.
    """
    #open_pool takes the genesis text, not a URL
    genesis_txns = fetch_genesis(genesis_url)
    return await open_pool(transactions=genesis_txns)


async def _load_signing_key(verkey: str, wallet_key: str):
    """Load the Verifier DID's signing key from the bootstrap wallet.

    Opens the ACA-Py-provisioned askar wallet and fetches the keypair the DID
    signs with. The key entry is stored under the verkey (verkey doubles as the
    entry name — the contract bootstrap.py sets). The store is closed here; only
    the Key material is returned, which is all the ATTRIB signing needs.

    Args: verkey (also the entry name), wallet_key (pass_key, from verifier_config.json).
    Returns: the aries_askar Key used to sign the request.
    """
    #sqlite:// + an absolute path is three slashes total — confirmed on the VM.
    #key_method must match how bootstrap.py provisioned it (ACA-Py default kdf:argon2i:mod)
    store = await Store.open(
        f"sqlite://{WALLET_DB_PATH}",
        key_method=WALLET_KEY_DERIVATION,
        pass_key=wallet_key,
    )
    try:
        async with store.session() as session:
            #the signing key is stored under the verkey as its entry name
            key_entry = await session.fetch_key(name=verkey)
            if not key_entry:
                raise RuntimeError(f"key not found in wallet for verkey: {verkey}")
            #return only the Key; publish_attrib calls .sign_message on it
            return key_entry.key
    finally:
        #always close the store, even if the key was missing
        await store.close()


async def publish_attrib(
    pool: "open_pool", did: str, verkey: str, wallet_key: str, mrenclave: str
) -> int:
    """Publish {"mrenclave": <hex>} as a raw ATTRIB under the Verifier DID.

    Self-attested: the DID is both submitter and target, so the Verifier vouches
    for its own measurement. The request is signed with the DID's wallet key and
    submitted. Returns the ledger sequence number of the accepted transaction.

    Args: pool, did (submitter and target), verkey (loads the key), wallet_key
    (opens the wallet), mrenclave (hex to anchor). Returns: the ATTRIB seqNo.
    """
    #build the raw ATTRIB: submitter=did, target=did (self-attested), value=json
    attrib_data = json.dumps({"mrenclave": mrenclave})
    req = ledger.build_attrib_request(did, did, None, attrib_data, None)

    #sign the request's signature input; set_signature takes the bytes only
    signing_key = await _load_signing_key(verkey, wallet_key)
    signature = signing_key.sign_message(req.signature_input)
    req.set_signature(signature)

    #submit and read the seqNo back; the reply nests it under one of two shapes
    result = await pool.submit_request(req)
    seq_no = (
        result.get("txnMetadata", {}).get("seqNo")
        or result.get("result", {}).get("txnMetadata", {}).get("seqNo")
    )
    return seq_no


async def verify_attrib(pool: "open_pool", did: str, expected: str) -> bool:
    """Read the MRENCLAVE ATTRIB back and confirm it matches expected.

    Anonymous GET_ATTRIB by DID + name "mrenclave" (no submitter needed for a
    read). Returns False if the ATTRIB is absent or the value differs.

    Args: pool, did, expected (the hex that should be on-ledger).
    Returns: True if the ledger value matches expected.
    """
    #anonymous read (submitter None) of the "mrenclave" ATTRIB under did
    req = ledger.build_get_attrib_request(None, did, "mrenclave", None, None)
    result = await pool.submit_request(req)

    #the stored value is a JSON string under "data"; absent means not published
    data = result.get("data")
    if not data:
        return False
    stored = json.loads(data).get("mrenclave")
    return stored == expected


# --- CLI: verify / publish_mrenclave -----------------------------------------


def _load_config() -> dict:
    """Read the Verifier config written by bootstrap.py (single DID source)."""
    #DID and verkey are never generated here; they come from bootstrap.py
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"{CONFIG_PATH} not found; run bootstrap.py first")
    return json.loads(CONFIG_PATH.read_text())


def _write_did_json(did: str, verkey: str, mrenclave: str, seq_no: int) -> None:
    """Write this module's attestation output to verifier_did.json."""
    #a record of what was anchored; nothing reads it back
    DID_JSON_PATH.write_text(json.dumps({
        "did": did,
        "verkey": verkey,
        "mrenclave": mrenclave,
        "attrib_seq_no": seq_no,
    }, indent=2))


async def _cmd_verify() -> None:
    """verify: fetch a live quote, verify it against Intel PCS, print MRENCLAVE."""
    #standalone check: no ledger, no config, just proves attestation works
    quote = fetch_quote()
    ok, _result = verify_quote(quote)
    if not ok:
        #the verification itself already printed why; say the outcome and stop
        vprint("[quote verification] failed")
        sys.exit(1)
    vprint("[quote verification] passed: genuine SGX quote from this platform")
    vprint(f"[quote verification] mrenclave: {extract_mrenclave(quote)}")


async def _cmd_publish_mrenclave() -> None:
    """publish_mrenclave: verify the live quote, then anchor its MRENCLAVE under the DID."""
    #DID/verkey/wallet_key come from bootstrap.py's config, never generated here
    config = _load_config()
    did, verkey, wallet_key = config["did"], config["verkey"], config["wallet_key"]

    #never anchor a MRENCLAVE from a quote that didn't verify
    quote = fetch_quote()
    ok, _result = verify_quote(quote)
    if not ok:
        #nothing is anchored unless the quote verified; the reason is already printed
        vprint("[quote verification] failed, nothing published")
        sys.exit(1)
    #same two lines the verify mode prints, so what is seen before a publish is
    #exactly what a standalone check shows. the failure paths print their own lines
    mrenclave = extract_mrenclave(quote)
    vprint("[quote verification] passed: genuine SGX quote from this platform")
    vprint(f"[quote verification] mrenclave: {mrenclave}")

    #one pool per command; publish then read back before recording success
    pool = await open_attrib_pool(GENESIS_URL)
    try:
        seq_no = await publish_attrib(pool, did, verkey, wallet_key, mrenclave)
        if not await verify_attrib(pool, did, mrenclave):
            raise RuntimeError("read-back mismatch: published MRENCLAVE not on ledger")
    finally:
        pool.close()

    _write_did_json(did, verkey, mrenclave, seq_no)
    vprint(f"published mrenclave {mrenclave} under {did} (seqNo {seq_no})")


def main() -> None:
    """Dispatch the CLI mode: verify | publish_mrenclave."""
    #mode selects the flow; asyncio.run drives the async ledger calls
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "verify":
        asyncio.run(_cmd_verify())
    elif mode == "publish_mrenclave":
        asyncio.run(_cmd_publish_mrenclave())
    else:
        vprint("usage: python3 -m runners.attestation_module {verify|publish_mrenclave}")
        sys.exit(1)


if __name__ == "__main__":
    main()
