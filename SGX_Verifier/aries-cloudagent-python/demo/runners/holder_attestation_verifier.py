#holder-side Phase 2 attestation (core contribution): before any DIDComm, the holder
#proves the Verifier is a genuine SGX enclave whose MRENCLAVE matches the value the
#Verifier published on BCovrin. it fetches the RA-TLS cert, extracts the embedded SGX
#quote, runs full Intel DCAP verification (so a forged quote is rejected — the holder
#runs off-SGX over an untrusted network, where a MRENCLAVE-only match would be forgeable
#since the value is public on the ledger), then compares the quote's MRENCLAVE to the
#ledger. proceed on success, abort on any failure

import asyncio
import ctypes
from runners.vlog import vprint
import glob
import json
import os
import socket
import ssl
import sys
import time
import urllib.request
from hashlib import sha256
from typing import Tuple

import aiohttp

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from indy_vdr import ledger, open_pool

#Azure DCAP client library, preloaded RTLD_GLOBAL so the QVL below can resolve its
#provider symbols; the QVL is then pointed at the Intel QPL (see _load_dcap_libraries)
#so collateral comes from Intel PCS, not THIM
AZURE_DCAP_CLIENT_PATH = "/usr/local/lib/libdcap_quoteprov.so"

#Intel Quote Verification Library, does the actual DCAP verification
QVL_PATH = "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1"

#BCovrin genesis endpoint; the ledger the Verifier published its MRENCLAVE ATTRIB to
GENESIS_URL = "http://test.bcovrin.vonx.io/genesis"

#the Verifier's RA-TLS port; its server cert carries the live SGX quote in an extension
RATLS_PORT = 5001

#the Verifier's pre-attestation hello port. the holder POSTs /session/hello here to
#wake the on-demand enclave, and only attests once it answers ready (avoids racing a cold enclave)
HELLO_PORT = int(os.environ.get("HELLO_PORT", 8049))

#the enclave cold-starts in a few seconds, so the first hello can land early; retry a bounded number
HELLO_MAX_ATTEMPTS = 5
#seconds between hello attempts while the enclave is still coming up
HELLO_RETRY_DELAY = 3

#OID of the standardized RA-TLS evidence extension (TCG DICE "tagged evidence").
#gramine emits this one and a legacy non-standard OID side by side; the legacy one is
#deprecated and will be dropped, so the standard one is what we read
DICE_EVIDENCE_OID = "2.23.133.5.4.9"

#the extension is CBOR: tag(60000) wrapping an array of [quote, claims]. these are the
#exact prefixes gramine writes, matched byte for byte so any other encoding is refused
#rather than parsed loosely
_CBOR_TAG_60000_ARRAY_2 = b"\xd9\xea\x60\x82"
#claims buffer: map(1) whose single key is the text "pubkey-hash", then a 36-byte string
_CBOR_CLAIMS_PREFIX = b"\xa1\x6bpubkey-hash\x58\x24"
#that string is array(2) = [1, 32-byte digest], where 1 identifies SHA-256
_CBOR_PUBKEY_HASH_PREFIX = b"\x82\x01\x58\x20"

#MRENCLAVE is bytes 112..144 of the quote: 48-byte header + report body, whose
#MRENCLAVE sits at body offset 64 (48+64=112), 32 bytes long
MRENCLAVE_SLICE = slice(112, 144)

#report_data is the last 64 bytes of the report body: 48-byte header + body offset
#320 = 368. in the standard extension gramine-ratls fills the first 32 bytes with
#SHA256(claims buffer) and zeroes the rest. confirmed against a live enclave cert on the VM
REPORT_DATA_SLICE = slice(368, 432)

#keeps the Azure DCAP client library resident once loaded (RTLD_GLOBAL so the QVL sees its symbols)
_AZURE_DCAP_CLIENT = None


# --- DCAP / Intel PCS quote-verification core (core contribution) -----------
#self-contained copy of the enclave-side DCAP verify core, so the holder needs
#nothing from the enclave module. verdict codes from the QVL's sgx_ql_qv_result_t
#enum: OK is a clean pass; CONFIG_NEEDED and OUT_OF_DATE mean it verified but the
#platform TCB is behind or needs config. which we accept is a trust-policy choice in _verify_with_collateral
#sgx_ql_qv_result_t values, taken from Intel's sgx_qve_header.h. these are NOT
#0/1/2: only OK is 0, every other verdict lives in the 0xA00x range. verdicts are
#classified by MEANING rather than kept as a fixed accept-list, so that a platform
#whose TCB status drifts over time does not silently break attestation
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
    declaration order.
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
        vprint("[attest] warning: no Intel quote provider found, "
               "the collateral may be out of date")
    else:
        ret = qvl.sgx_qv_set_path(SGX_QV_QPL_PATH, qpl.encode())
        if ret != 0:
            vprint("[attest] warning: could not select the Intel quote provider "
                   f"(sgx_qv_set_path returned 0x{ret & 0xFFFFFFFF:08x})")
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
            f"[attest] tee_verify_quote failed: 0x{ret & 0xFFFFFFFF:08x} "
            f"(verdict 0x{verdict:04x} not meaningful)"
        )
        return False, verdict
    #expired collateral means the verdict was reached against stale trust data
    if exp_status.value != 0:
        vprint("[attest] rejected: the collateral used for the check has "
               f"expired (exp_status={exp_status.value})")
        return False, verdict
    #classify by meaning so platform-TCB drift cannot silently break attestation
    if verdict in VERDICT_OK:
        return True, verdict
    if verdict in VERDICT_WARN:
        #authentic quote, but the platform is behind or misconfigured: accept and
        #report it, never silently. a production deployment should reject these
        vprint(
            f"[attest] accepted with a warning, verdict 0x{verdict:04x}: the quote "
            "is genuine but this platform is behind on patches or misconfigured"
        )
        return True, verdict
    #known-bad and anything unrecognised: fail closed rather than fail open
    vprint(f"[attest] rejected: verdict 0x{verdict:04x}, this quote is not trusted")
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


def extract_mrenclave(quote: bytes) -> str:
    """Extract MRENCLAVE from a raw SGX quote as a hex string.

    Slices the 32-byte MRENCLAVE out of the quote and renders it as 64 hex chars
    for comparison against the expected measurement read from the ledger.

    Args: quote. Returns: the 64-char hex MRENCLAVE.
    """
    #slice the fixed 32-byte MRENCLAVE span and render as hex
    return quote[MRENCLAVE_SLICE].hex()


# --- RA-TLS cert fetch + quote extraction (Holder-specific scaffolding) ------


def _fetch_ratls_cert_der(host: str, port: int) -> bytes:
    """Complete a TLS handshake with the Verifier and return its cert as DER.

    Connects to the RA-TLS port and takes the server cert from the handshake.
    Chain validation is off on purpose: an RA-TLS cert is self-signed, its trust
    is the embedded SGX quote (verified later via DCAP), not a CA chain. The
    handshake alone is the attestation — no application data is exchanged.

    Args: host, port (the RA-TLS port). Returns: the server cert as DER bytes.
    """
    #client context with chain validation off: trust is the embedded quote
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    #open the TLS connection and read the peer cert in binary (DER) form
    with socket.create_connection((host, port)) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _read_cbor_bytes(buf: bytes, pos: int) -> Tuple[bytes, int]:
    """Read one CBOR byte string at pos.

    Only byte strings appear at this level of the RA-TLS evidence, so anything else
    is an encoding we do not recognise and is refused rather than guessed at.

    Args: buf, pos (offset to read from). Returns: (value, offset after it).
    """
    #major type 2 is a byte string; the low five bits carry the length or its size
    head = buf[pos]
    if head >> 5 != 2:
        raise RuntimeError("expected a CBOR byte string in the RA-TLS evidence")
    info = head & 0x1F
    pos += 1
    #lengths under 24 are in the head itself, larger ones follow it
    if info < 24:
        length = info
    elif info == 24:
        length = buf[pos]
        pos += 1
    elif info == 25:
        length = int.from_bytes(buf[pos : pos + 2], "big")
        pos += 2
    elif info == 26:
        length = int.from_bytes(buf[pos : pos + 4], "big")
        pos += 4
    else:
        raise RuntimeError("unsupported CBOR byte-string length in the RA-TLS evidence")
    return buf[pos : pos + length], pos + length


def _extract_dice_evidence(der_cert: bytes) -> Tuple[bytes, bytes]:
    """Pull the SGX quote and the claims buffer out of an RA-TLS certificate.

    Reads the standardized DICE evidence extension, which holds both, rather than
    scanning the certificate for a quote header.

    Args: der_cert. Returns: (quote, claims buffer).
    """
    cert = x509.load_der_x509_certificate(der_cert)
    #a certificate without the extension is not an RA-TLS certificate at all
    ext = cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier(DICE_EVIDENCE_OID)
    )
    blob = ext.value.value
    #refuse anything that is not the tagged two-element array gramine writes
    if not blob.startswith(_CBOR_TAG_60000_ARRAY_2):
        raise RuntimeError("unexpected encoding in the RA-TLS evidence extension")
    quote, pos = _read_cbor_bytes(blob, len(_CBOR_TAG_60000_ARRAY_2))
    claims, _ = _read_cbor_bytes(blob, pos)
    return quote, claims


def _extract_quote_from_cert(der_cert: bytes) -> bytes:
    """Extract the raw SGX quote embedded in an RA-TLS certificate.

    Args: der_cert. Returns: the raw SGX quote bytes.
    """
    quote, _ = _extract_dice_evidence(der_cert)
    return quote


def _quote_binds_to_cert(quote: bytes, der_cert: bytes) -> bool:
    """Check the quote commits to this certificate's public key.

    This is what makes the quote non-replayable, and it holds in two steps: the
    quote's report_data is SHA256 of the claims buffer, and the claims buffer names
    SHA256 of the certificate's public key. Without it an attacker can lift a genuine
    quote from the real Verifier, embed it in its own self-signed cert with its own
    key, and pass DCAP and the MRENCLAVE compare while actually holding a different
    key — the handshake alone only proves the server holds its own key, which the
    quote never vouched for.

    Args: quote, der_cert. Returns: True if the quote names this cert's key.
    """
    _, claims = _extract_dice_evidence(der_cert)
    #what the enclave committed to when the quote was produced
    if sha256(claims).digest() != quote[REPORT_DATA_SLICE][:32]:
        return False
    #the claims buffer must be the single pubkey-hash claim, in the shape gramine writes
    if not claims.startswith(_CBOR_CLAIMS_PREFIX):
        return False
    inner = claims[len(_CBOR_CLAIMS_PREFIX) :]
    if not inner.startswith(_CBOR_PUBKEY_HASH_PREFIX):
        return False
    named_key = inner[len(_CBOR_PUBKEY_HASH_PREFIX) : len(_CBOR_PUBKEY_HASH_PREFIX) + 32]
    #the key the peer actually proved possession of during the handshake
    cert = x509.load_der_x509_certificate(der_cert)
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).digest() == named_key


# --- Ledger read: expected MRENCLAVE from the Verifier DID (Holder-specific) --


def _fetch_genesis(url: str) -> str:
    """Fetch the BCovrin genesis transactions as text.

    Runs on the normal holder host with its CA store, so plain urllib validates
    BCovrin's HTTP->HTTPS redirect without disabling TLS.

    Args: url. Returns: the genesis transactions as text.
    """
    #plain GET; urllib follows the redirect and validates against the system CAs
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode("utf-8")


async def _open_pool(genesis_url: str) -> "open_pool":
    """Open a read-only ledger pool for the MRENCLAVE lookup.

    open_pool takes the genesis text, not a URL, so it is fetched first.

    Args: genesis_url. Returns: an open indy_vdr pool handle.
    """
    #open_pool takes the genesis text, not a URL
    genesis_txns = _fetch_genesis(genesis_url)
    return await open_pool(transactions=genesis_txns)


async def _fetch_mrenclave_from_did(pool: "open_pool", verifier_did: str) -> str:
    """Read the expected MRENCLAVE from the Verifier DID's ATTRIB on BCovrin.

    Runs GET_ATTRIB(verifier_did, "mrenclave") and parses the published value. It
    was written as a raw ATTRIB keyed by "mrenclave", so anyone can read it from
    the DID alone — no seqNo. The ledger returns the payload at top-level "data"
    (no {"op":"REPLY","result":{...}} wrapper), a JSON string {"mrenclave": "<hex>"}.

    Args: pool, verifier_did. Returns: the expected MRENCLAVE as lowercase hex.
    """
    #GET_ATTRIB read request; submitter None (read-only)
    request = ledger.build_get_attrib_request(
        None, verifier_did, "mrenclave", None, None
    )
    response = await pool.submit_request(request)
    #the payload is at top-level "data" as a JSON string; missing => none
    data = response.get("data")
    if not data:
        raise RuntimeError(
            f"no 'mrenclave' ATTRIB found on ledger for DID {verifier_did}"
        )
    #parse {"mrenclave": "<hex>"} and normalize to lowercase hex
    attrib = json.loads(data)
    return attrib["mrenclave"].lower()


# --- Public entry point: the full attestation decision (the whole point) ------


async def send_hello(host: str) -> bool:
    """Wake the Verifier's on-demand enclave before attesting.

    POSTs to /session/hello, which starts the enclave (or reuses it if warm) and
    answers ready only once /health is green. Retries a bounded number of times so
    a first hello during cold start still succeeds. Returns True once ready.

    Args: host (hello port fixed at HELLO_PORT).
    Returns: True once the Verifier answers ready, else False after all attempts.
    """
    #the verifier's pre-attestation endpoint
    url = f"http://{host}:{HELLO_PORT}/session/hello"
    #per-request cap above the cold-start + readiness budget, so a slow first
    #start is waited out instead of tripping the client timeout
    timeout = aiohttp.ClientTimeout(total=35)
    #bounded retries; the enclave may still be cold-starting
    for attempt in range(1, HELLO_MAX_ATTEMPTS + 1):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url) as resp:
                    #200 with {"ready": true} means the enclave is up to attest
                    if resp.status == 200:
                        body = await resp.json()
                        if body.get("ready"):
                            vprint(f"[hello] verifier ready (attempt {attempt})")
                            return True
                    #any other response: not ready yet, fall through
                    vprint(
                        f"[hello] not ready yet (attempt {attempt}, HTTP {resp.status})"
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            #unreachable or timed out: not ready yet, retry
            vprint(f"[hello] no ready response (attempt {attempt}): {err}")
        #wait before the next attempt, unless this was the last
        if attempt < HELLO_MAX_ATTEMPTS:
            await asyncio.sleep(HELLO_RETRY_DELAY)
    #every attempt failed: don't proceed to attestation
    vprint("[hello] verifier never became ready")
    return False


async def verify_verifier_enclave(host: str, did: str) -> Tuple[bool, float, str]:
    """Attest the Verifier's enclave before any DIDComm exchange.

    Runs the full Phase 2 flow and times it end to end:
      1. fetch the Verifier's RA-TLS cert over TLS,
      2. extract the embedded SGX quote,
      3. verify the quote via full Intel DCAP (genuine, Intel-signed, current) —
         this is what makes a forged quote fail on the off-SGX holder,
      4. check the quote's report_data binds to this cert's public key, so a
         genuine quote cannot be replayed inside someone else's certificate,
      5. read the expected MRENCLAVE from the Verifier DID's ledger ATTRIB,
      6. require the quote's MRENCLAVE matches the ledger.

    All three must hold: a forged quote, a genuine quote replayed in a foreign
    cert, or a genuine bound quote with the wrong MRENCLAVE all abort. Any
    exception is an attestation failure (fail closed).

    Args: host (RA-TLS port fixed at RATLS_PORT), did (the MRENCLAVE trust anchor).
    Returns: (attestation_passed, duration_seconds, reason) where reason is one of
    "ok" | "dcap" | "binding" | "mrenclave" | "error" — the caller cannot otherwise
    tell WHY attestation failed, and the three failures mean very different things
    (forged quote vs replayed quote vs wrong enclave), so each warrants its own
    message. Nothing extra is computed: each branch already knows its own reason.
    """
    #time the whole flow so alice.py can log the attestation cost
    start = time.perf_counter()
    try:
        #1-2. fetch the RA-TLS cert and pull the raw SGX quote out of it
        der_cert = _fetch_ratls_cert_der(host, RATLS_PORT)
        quote = _extract_quote_from_cert(der_cert)

        #3. full DCAP verification: genuine, current Intel SGX quote?
        dcap_ok, verdict = verify_quote(quote)
        if not dcap_ok:
            vprint(f"[attest] DCAP verification failed (verdict={verdict})")
            return False, time.perf_counter() - start, "dcap"

        #4. bind the quote to this cert: report_data must name the key the peer
        #just proved it holds. without this a genuine quote lifted from the real
        #Verifier could be replayed inside an attacker's own cert
        if not _quote_binds_to_cert(quote, der_cert):
            vprint("[attest] report_data/pubkey mismatch: quote does not bind to this certificate")
            return False, time.perf_counter() - start, "binding"

        #5. read the expected MRENCLAVE the Verifier published on BCovrin
        pool = await _open_pool(GENESIS_URL)
        try:
            expected = await _fetch_mrenclave_from_did(pool, did)
        finally:
            #close the pool whatever the lookup did
            pool.close()

        #6. compare the quote's live MRENCLAVE against the ledger value
        live = extract_mrenclave(quote)
        if live != expected:
            vprint(f"[attest] MRENCLAVE mismatch: live={live} expected={expected}")
            return False, time.perf_counter() - start, "mrenclave"

        #all three checks passed: the Verifier is the attested enclave
        vprint(f"[attest] OK: genuine SGX quote bound to this cert, MRENCLAVE matches ledger ({live})")
        return True, time.perf_counter() - start, "ok"
    except Exception as err:
        #fail closed: any error aborts the connection
        vprint(f"[attest] attestation error: {err}")
        return False, time.perf_counter() - start, "error"


def main() -> None:
    """CLI entry point: attest a Verifier and exit non-zero on failure.

    Usage: python -m runners.holder_attestation_verifier <host> <did>
    The DID is required: in the flow the holder resolves it from the trusted registry,
    and a standalone run has no invitation to resolve from.
    """
    #first arg is the Verifier host; default localhost for a same-VM test
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    #second arg is the Verifier DID; without it there is nothing to compare MRENCLAVE to
    if len(sys.argv) < 3:
        vprint("usage: python -m runners.holder_attestation_verifier <host> <did>")
        sys.exit(2)
    did = sys.argv[2]
    #run the async attestation flow to completion
    passed, duration, reason = asyncio.run(verify_verifier_enclave(host, did))
    #report outcome and timing for a standalone run; on failure name the reason so a
    #standalone run says WHICH check rejected, not just that something did
    outcome = "PASSED" if passed else f"ABORTED ({reason})"
    vprint(f"attestation {outcome} in {duration:.3f} s")
    #exit non-zero on failure so scripts can detect the abort
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
