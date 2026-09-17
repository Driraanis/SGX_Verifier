#self-contained AnonCreds presentation verifier for the enclave-side service (core contribution)
#reproduces ACA-Py's AnonCredsVerifier.verify_presentation() pipeline: pre-validation,
#AnonCreds proof verification, and holder binding, over a presentation passed in at call time
#the logic is inlined, not imported: Gramine measures every file the enclave opens as a
#trusted file, so one self-contained module keeps the trusted-file set small

from time import perf_counter

#captured as early as possible so the startup timing covers this module's own import + setup
#the SGX enclave-creation cost before Python starts is measured separately by the launcher
_STARTUP_T0 = perf_counter()

import asyncio
import base64
import os
import socket
import ssl
import threading
import traceback
from anoncreds import AnoncredsError, Presentation
from flask import Flask, request, jsonify
from hashlib import sha256
from indy_vdr import ledger, open_pool
from time import sleep, time
from typing import Any, Tuple


#violet-wrap this enclave's stdout to match the rest of the project. inlined because the
#enclave runs on a minimal trusted-file set and can't import runners.vlog; it is a
#separate process with no prompt_toolkit, so raw ANSI renders on the inherited terminal.
#NOTE: this is a MEASURED trusted file — editing it changes MRENCLAVE, so re-sign and
#republish to BCovrin after this change
_VIOLET = "\033[38;2;138;43;226m"
_RESET = "\033[0m"


def _vprint(*args, **kwargs) -> None:
    #drop-in for print(): join args like print, wrap in violet, keep flush behaviour
    kwargs.setdefault("flush", True)
    print(f"{_VIOLET}{' '.join(str(a) for a in args)}{_RESET}", **kwargs)

#BCovrin ledger, the public Indy network we read schema and cred def from ourselves,
#never trusting the REE for trust anchors. the genesis (the ledger's trust root) is
#pinned: read from a file measured into MRENCLAVE, not fetched at runtime, so the
#untrusted host cannot substitute the pool the enclave trusts (see read_genesis)
GENESIS_PATH = os.environ.get(
    "GENESIS_PATH", "/home/anis/SGX_Verifier/enclave/bcovrin_genesis.txn"
)

#edge of the signed 32-bit range, values inside it stay as-is, anything else is hashed
#inlined from acapy_agent/messaging/util.py so the enclave needs nothing from ACA-Py
I32_BOUND = 2**31


def encode(orig: Any) -> str:
    """Encode a credential attribute value as an integer string.

    int32 values (and int32-valued strings) stay as-is; anything else becomes a
    stringified 256-bit SHA-256 integer. Inlined verbatim from
    acapy_agent/messaging/util.py.

    Args: orig (the attribute value). Returns: the encoded value as a string.
    """
    #real int already in range, stringify it (bools count as ints)
    if isinstance(orig, int) and -I32_BOUND <= orig < I32_BOUND:
        return str(int(orig))

    #string that parses as an int32, keep its numeric form
    try:
        i32orig = int(str(orig))  # don't encode floats as ints
        if -I32_BOUND <= i32orig < I32_BOUND:
            return str(i32orig)
    except (ValueError, TypeError):
        pass

    #everything else: SHA-256 digest read as a big-endian integer
    rv = int.from_bytes(sha256(str(orig).encode()).digest(), "big")

    return str(rv)


def canon(raw_attr_name: str) -> str:
    """Canonicalize an attribute name for AnonCreds proofs and offers.

    Lowercases and strips spaces; None and "" pass through unchanged. Inlined
    verbatim from acapy_agent/messaging/util.py.

    Args: raw_attr_name. Returns: the canonicalized name.
    """
    #guard None and "" (nothing to canonicalize)
    if raw_attr_name:
        return raw_attr_name.replace(" ", "").lower()
    return raw_attr_name


def extract_non_revocation_intervals_from_proof_request(proof_req: dict) -> dict:
    """Return non-revocation intervals keyed by requested-item referent.

    For each referent, uses its own "non_revoked" if present, else the request's
    global "non_revoked". Inlined verbatim from
    acapy_agent/anoncreds/models/utils.py (just this function).

    Args: proof_req. Returns: referent -> interval dict (or None if none applies).
    """
    non_revoc_intervals = {}
    #both attribute and predicate referents can carry an interval
    for req_item_type in ("requested_attributes", "requested_predicates"):
        for reft, req_item in proof_req[req_item_type].items():
            #referent-level interval wins over the global one
            interval = req_item.get(
                "non_revoked",
                proof_req.get("non_revoked"),
            )
            if interval:
                timestamp_from = interval.get("from")
                timestamp_to = interval.get("to")
                #from == to would reject the proof, relax from to 0
                if (timestamp_to is not None) and timestamp_from == timestamp_to:
                    interval["from"] = 0  # accommodate verify=False if from=to
            non_revoc_intervals[reft] = interval
    return non_revoc_intervals


def non_revoc_intervals(pres_req: dict, pres: dict, cred_defs: dict) -> list:
    """Remove superfluous non-revocation intervals from the proof request.

    An irrevocable credential is itself proof of non-revocation, but AnonCreds
    rejects a request that carries non-revocation intervals lining up with
    non-revocable credentials, so this finds and removes them. Mutates pres_req in
    place and returns warning codes. Ported from
    AnonCredsVerifier.non_revoc_intervals() as a plain function (no self upstream).
    A credential is revocable iff its cred def "value" has a "revocation" key.

    Args: pres_req (mutated in place), pres, cred_defs (by cred def id).
    Returns: warning codes for the intervals removed.
    """
    msgs = []
    #each requested-proof section maps to a proof-request section to clean up
    for req_proof_key, pres_key in {
        "revealed_attrs": "requested_attributes",
        "revealed_attr_groups": "requested_attributes",
        "predicates": "requested_predicates",
    }.items():
        #every referent disclosed in this section of the presentation
        for uuid, spec in pres["requested_proof"].get(req_proof_key, {}).items():
            #irrevocable cred def => no "revocation" key
            if (
                "revocation"
                not in cred_defs[
                    pres["identifiers"][spec["sub_proof_index"]]["cred_def_id"]
                ]["value"]
            ):
                #drop the referent-level interval if one was requested
                if uuid in pres_req[pres_key] and pres_req[pres_key][uuid].pop(
                    "non_revoked", None
                ):
                    #removed a referent-level non-revocation interval
                    msgs.append(f"RMV_RFNT_NRI::{uuid}")

    #the global interval is superfluous only if every identifier is timestamp-less
    #and irrevocable; if so, drop the request's global "non_revoked"
    if all(
        (
            spec.get("timestamp") is None
            and "revocation" not in cred_defs[spec["cred_def_id"]]["value"]
        )
        for spec in pres["identifiers"]
    ):
        pres_req.pop("non_revoked", None)
        #removed the global non-revocation interval
        msgs.append("RMV_GLB_NRI")
    return msgs


def check_timestamps(
    pres_req: dict,
    pres: dict,
    cred_defs: dict,
    rev_reg_defs: dict,
) -> list:
    """Check for suspicious, missing, and superfluous revocation timestamps.

    Raises ValueError on a timestamp that is in the future, on an irrevocable
    credential, superfluous, or missing. Ported from
    AnonCredsVerifier.check_timestamps(): the profile/registry dependency is
    dropped (it only re-fetched cred defs to read the revocation flag, so the
    already-fetched cred_defs dict is passed in instead), so it is a plain
    non-async function; revocability is read dict-style
    ("revocation" in cred_defs[id]["value"]); and the duplicate UNRVL_ATTR append
    is left to pre_verify.

    Args: pres_req, pres, cred_defs (by cred def id), rev_reg_defs (by rev reg id).
    Returns: warning codes (e.g. TS_OUT_NRI) for non-fatal anomalies.
    """
    msgs = []
    now = int(time())
    #resolve each requested item's applicable non-revocation interval
    non_revoc_intervals = extract_non_revocation_intervals_from_proof_request(pres_req)

    #a timestamp on an irrevocable credential is itself an error
    for index, ident in enumerate(pres["identifiers"]):
        cred_def_id = ident["cred_def_id"]
        #revocable iff the cred def "value" has a "revocation" key
        revocable = "revocation" in cred_defs[cred_def_id]["value"]
        if ident.get("timestamp"):
            if not revocable:
                raise ValueError(
                    f"Timestamp in presentation identifier #{index} "
                    f"for irrevocable cred def id {cred_def_id}"
                )

    #a timestamp must not be in the future and must have a matching rev reg def
    for ident in pres["identifiers"]:
        timestamp = ident.get("timestamp")
        rev_reg_id = ident.get("rev_reg_id")

        if not timestamp:
            continue

        if timestamp > now + 300:  # allow 5 min for clock skew
            raise ValueError(f"Timestamp {timestamp} is in the future")
        reg_def = rev_reg_defs.get(rev_reg_id)
        if not reg_def:
            raise ValueError(f"Missing registry definition for '{rev_reg_id}'")
        #txnTime predating checks are commented out upstream, omitted here too

    #a timestamp may be superfluous, missing, or outside the allowed interval
    revealed_attrs = pres["requested_proof"].get("revealed_attrs", {})
    unrevealed_attrs = pres["requested_proof"].get("unrevealed_attrs", {})
    revealed_groups = pres["requested_proof"].get("revealed_attr_groups", {})
    self_attested = pres["requested_proof"].get("self_attested_attrs", {})
    preds = pres["requested_proof"].get("predicates", {})

    #single requested attributes (carry a "name")
    for uuid, req_attr in pres_req["requested_attributes"].items():
        if "name" in req_attr:
            if uuid in revealed_attrs:
                index = revealed_attrs[uuid]["sub_proof_index"]
                #only revocable credentials carry timestamp expectations
                if "revocation" in cred_defs[
                    pres["identifiers"][index]["cred_def_id"]
                ]["value"]:
                    timestamp = pres["identifiers"][index].get("timestamp")
                    #timestamp and interval must both be present or both absent
                    if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                        raise ValueError(
                            f"Timestamp on sub-proof #{index} "
                            f"is {'superfluous' if timestamp else 'missing'} "
                            f"vs. requested attribute {uuid}"
                        )
                    #a present timestamp must fall inside the interval
                    if non_revoc_intervals.get(uuid) and not (
                        non_revoc_intervals[uuid].get("from", 0)
                        < timestamp
                        < non_revoc_intervals[uuid].get("to", now)
                    ):
                        msgs.append(f"TS_OUT_NRI::{uuid}")
            elif uuid in unrevealed_attrs:
                #unrevealed attribute: pre_verify emits UNRVL_ATTR, not here
                pass
            elif uuid not in self_attested:
                raise ValueError(
                    f"Presentation attributes mismatch requested attribute {uuid}"
                )

        elif "names" in req_attr:
            group_spec = revealed_groups.get(uuid)
            if (
                group_spec is None
                or "sub_proof_index" not in group_spec
                or "values" not in group_spec
            ):
                raise ValueError(f"Missing requested attribute group {uuid}")
            index = group_spec["sub_proof_index"]
            if "revocation" in cred_defs[
                pres["identifiers"][index]["cred_def_id"]
            ]["value"]:
                timestamp = pres["identifiers"][index].get("timestamp")
                if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                    raise ValueError(
                        f"Timestamp on sub-proof #{index} "
                        f"is {'superfluous' if timestamp else 'missing'} "
                        f"vs. requested attribute group {uuid}"
                    )
                if non_revoc_intervals.get(uuid) and not (
                    non_revoc_intervals[uuid].get("from", 0)
                    < timestamp
                    < non_revoc_intervals[uuid].get("to", now)
                ):
                    msgs.append(f"TS_OUT_NRI::{uuid}")

    #requested predicates
    for uuid, req_pred in pres_req["requested_predicates"].items():
        pred_spec = preds.get(uuid)
        if pred_spec is None or "sub_proof_index" not in pred_spec:
            raise ValueError(
                f"Presentation predicates mismatch requested predicate {uuid}"
            )
        index = pred_spec["sub_proof_index"]
        if "revocation" in cred_defs[
            pres["identifiers"][index]["cred_def_id"]
        ]["value"]:
            timestamp = pres["identifiers"][index].get("timestamp")
            if (timestamp is not None) ^ bool(non_revoc_intervals.get(uuid)):
                raise ValueError(
                    f"Timestamp on sub-proof #{index} "
                    f"is {'superfluous' if timestamp else 'missing'} "
                    f"vs. requested predicate {uuid}"
                )
            if non_revoc_intervals.get(uuid) and not (
                non_revoc_intervals[uuid].get("from", 0)
                < timestamp
                < non_revoc_intervals[uuid].get("to", now)
            ):
                msgs.append(f"TS_OUT_NRI::{uuid}")
    return msgs


def pre_verify(pres_req: dict, pres: dict) -> list:
    """Check the presentation for essential components and tampering.

    Cross-checks each encoded attribute value against its raw value and against
    the predicate bounds in the presentation, all against the proof request.
    Raises ValueError on any structural gap or mismatch (the caller turns that
    into a failed verification). Ported from AnonCredsVerifier.pre_verify() as a
    plain function using the local encode/canon. Emits UNRVL_ATTR for unrevealed
    attributes.

    Args: pres_req, pres. Returns: warning codes (e.g. UNRVL_ATTR).
    """
    msgs = []
    #structural guards: both request and presentation must be well-formed
    if not (
        pres_req
        and "requested_predicates" in pres_req
        and "requested_attributes" in pres_req
    ):
        raise ValueError("Incomplete or missing proof request")
    if not pres:
        raise ValueError("No proof provided")
    if "requested_proof" not in pres:
        raise ValueError("Presentation missing 'requested_proof'")
    if "proof" not in pres:
        raise ValueError("Presentation missing 'proof'")

    #each requested predicate must appear in the proof with a matching bound
    for uuid, req_pred in pres_req["requested_predicates"].items():
        try:
            canon_attr = canon(req_pred["name"])
            matched = False
            found = False
            pred = None
            #scan the ge_proofs of the sub-proof carrying this predicate
            for ge_proof in pres["proof"]["proofs"][
                pres["requested_proof"]["predicates"][uuid]["sub_proof_index"]
            ]["primary_proof"]["ge_proofs"]:
                pred = ge_proof["predicate"]
                if pred["attr_name"] == canon_attr:
                    found = True
                    if pred["value"] == req_pred["p_value"]:
                        matched = True
                        break
            if not matched:
                raise ValueError(f"Predicate not found: {canon_attr}")
            elif not found:
                raise ValueError(f"Missing requested predicate '{uuid}'")
        except (KeyError, TypeError):
            raise ValueError(f"Missing requested predicate '{uuid}'")

    revealed_attrs = pres["requested_proof"].get("revealed_attrs", {})
    unrevealed_attrs = pres["requested_proof"].get("unrevealed_attrs", {})
    revealed_groups = pres["requested_proof"].get("revealed_attr_groups", {})
    self_attested = pres["requested_proof"].get("self_attested_attrs", {})
    #find where each requested attribute is disclosed, then tamper-check it
    for uuid, req_attr in pres_req["requested_attributes"].items():
        if "name" in req_attr:
            if uuid in revealed_attrs:
                pres_req_attr_spec = {req_attr["name"]: revealed_attrs[uuid]}
            elif uuid in unrevealed_attrs:
                #unrevealed attribute: nothing to verify, just record it
                pres_req_attr_spec = {}
                msgs.append(f"UNRVL_ATTR::{uuid}")
            elif uuid in self_attested:
                #restricted attributes may not be self-attested
                if not req_attr.get("restrictions"):
                    continue
                raise ValueError(
                    "Attribute with restrictions cannot be self-attested: "
                    f"'{req_attr['name']}'"
                )
            else:
                raise ValueError(f"Missing requested attribute '{req_attr['name']}'")
        elif "names" in req_attr:
            group_spec = revealed_groups[uuid]
            pres_req_attr_spec = {
                attr: {
                    "sub_proof_index": group_spec["sub_proof_index"],
                    **group_spec["values"].get(attr),
                }
                for attr in req_attr["names"]
            }
        else:
            raise ValueError(f"Request attribute missing 'name' and 'names': '{uuid}'")

        #tamper check: the proof's encoded value must match the disclosed encoded
        #value and our locally recomputed encode(raw)
        for attr, spec in pres_req_attr_spec.items():
            try:
                primary_enco = pres["proof"]["proofs"][spec["sub_proof_index"]][
                    "primary_proof"
                ]["eq_proof"]["revealed_attrs"][canon(attr)]
            except (KeyError, TypeError):
                raise ValueError(f"Missing revealed attribute: '{attr}'")
            if primary_enco != spec["encoded"]:
                raise ValueError(f"Encoded representation mismatch for '{attr}'")
            if primary_enco != encode(spec["raw"]):
                raise ValueError(f"Encoded representation mismatch for '{attr}'")
    return msgs


def _issuer_did(object_id: str) -> str:
    """Extract the issuer DID from a ledger object id.

    Indy schema and cred def ids are colon-delimited and start with the issuer's
    DID, so we read it straight off the id and never take it from the REE.

    Args: object_id (a schema or cred def id). Returns: the issuer DID (first segment).
    """
    return object_id.split(":")[0]


def read_genesis(path: str) -> str:
    """Read the pinned BCovrin genesis transactions from a measured file.

    The genesis is the ledger's single trust root: it names the validator nodes
    and their keys, so whoever controls it controls the enclave's whole view of
    the ledger. Reading it from a file listed in sgx.trusted_files means the bytes
    are hash-measured into MRENCLAVE, so the untrusted host cannot substitute a
    different genesis without changing MRENCLAVE and failing attestation. It is
    provisioned once at trusted setup, not fetched over the network at runtime.

    Args: path. Returns: the genesis transactions as text.
    """
    #plain local read of a measured file: no network, no TLS, no host-provided CA
    with open(path) as f:
        return f.read()


async def open_ledger_pool():
    """Open a read-only indy_vdr pool against BCovrin.

    Reads the pinned genesis and opens the pool from it. No wallet, no keys: the
    verifier only does anonymous reads.

    Returns: an open indy_vdr Pool handle.
    """
    #open_pool takes the genesis text, not a URL; the text comes from the measured
    #trusted file, so the pool the enclave trusts is fixed at build time
    genesis_txns = read_genesis(GENESIS_PATH)
    return await open_pool(transactions=genesis_txns)


async def fetch_schema(pool, schema_id: str) -> dict:
    """Fetch a schema from the ledger by id.

    Anonymous GET_SCHEMA (submitter None; BCovrin allows anonymous reads).
    Returns the schema in the shape anoncreds expects, with issuerId injected
    (anoncreds-python 0.2+ needs it, the raw ledger response lacks it). Mirrors
    acapy_agent/ledger/indy_vdr.py.

    Args: pool, schema_id. Returns: serialized schema dict.
    """
    #anonymous read: submitter None, no key material needed
    request = ledger.build_get_schema_request(None, schema_id)
    response = await pool.submit_request(request)

    #response may be wrapped under "result" or returned directly
    result = response.get("result", response)
    data = result["data"]
    return {
        "ver": "1.0",
        "id": schema_id,
        #issuerId is the DID prefix of the schema id; anoncreds requires it
        "issuerId": _issuer_did(schema_id),
        "name": data["name"],
        "version": data["version"],
        "attrNames": data["attr_names"],
        "seqNo": result["seqNo"],
    }


async def fetch_cred_def(pool, cred_def_id: str) -> dict:
    """Fetch a credential definition from the ledger by id.

    Anonymous GET_CRED_DEF. Returns the cred def in the shape anoncreds expects,
    with issuerId injected. schemaId is the schema sequence-number string (the
    ledger "ref"), not the full schema id — that is what anoncreds-python wants.
    Mirrors acapy_agent/ledger/indy_vdr.py.

    Args: pool, cred_def_id. Returns: serialized cred def dict.
    """
    #anonymous read: submitter None
    request = ledger.build_get_cred_def_request(None, cred_def_id)
    response = await pool.submit_request(request)

    result = response.get("result", response)
    return {
        "ver": "1.0",
        "id": cred_def_id,
        #issuerId is the DID prefix of the cred def id; anoncreds requires it
        "issuerId": _issuer_did(cred_def_id),
        #schemaId is the seqNo string from the ledger "ref", not the schema id
        "schemaId": str(result["ref"]),
        "type": result["signature_type"],
        "tag": result.get("tag", "default"),
        #"value" holds the primary key (and "revocation" only when revocable)
        "value": result["data"],
    }


async def fetch_rev_reg_def(pool, rev_reg_id: str) -> dict:
    """Fetch a revocation registry definition from the ledger by id.

    Anonymous GET_REVOC_REG_DEF. Returns the rev reg def in the shape anoncreds
    expects, with issuerId injected (the raw ledger response lacks it). Request
    mirrors acapy_agent/ledger/indy_vdr.py get_revoc_reg_def; the anoncreds shape
    mirrors legacy_indy/registry.py get_revocation_registry_definition.

    Args: pool, rev_reg_id. Returns: serialized rev reg def dict.
    """
    #anonymous read: submitter None
    request = ledger.build_get_revoc_reg_def_request(None, rev_reg_id)
    response = await pool.submit_request(request)

    result = response.get("result", response)
    data = result["data"]
    value = data["value"]
    return {
        #issuerId is the DID prefix of the rev reg id; anoncreds requires it
        "issuerId": _issuer_did(rev_reg_id),
        "revocDefType": data["revocDefType"],
        "credDefId": data["credDefId"],
        "tag": data["tag"],
        #only the fields anoncreds wants; the ledger's issuanceType is dropped
        "value": {
            "publicKeys": value["publicKeys"],
            "maxCredNum": value["maxCredNum"],
            "tailsLocation": value["tailsLocation"],
            "tailsHash": value["tailsHash"],
        },
    }


async def fetch_rev_reg_status(pool, rev_reg_id: str, timestamp: int, max_cred_num: int) -> dict:
    """Fetch the revocation status list (accumulator + revoked indices) at a timestamp.

    Anonymous GET_REVOC_REG_DELTA from registry creation to timestamp. Builds the
    revocationList bit-array (issuance-by-default: 0 = valid, 1 = revoked) and the
    current accumulator, shaped for anoncreds RevocationStatusList. Request mirrors
    acapy_agent/ledger/indy_vdr.py get_revoc_reg_delta; the anoncreds shape mirrors
    legacy_indy/registry.py get_revocation_list.

    Args: pool, rev_reg_id, timestamp, max_cred_num. Returns: rev status list dict.
    """
    #from None -> timestamp gives the accumulator + every revoked index at that time
    request = ledger.build_get_revoc_reg_delta_request(None, rev_reg_id, None, timestamp)
    response = await pool.submit_request(request)

    result = response.get("result", response)
    reg = result["data"]["value"]
    #accum_to holds the accumulator value as of the requested timestamp
    accum = reg["accum_to"]["value"]["accum"]
    revoked = reg.get("revoked", [])
    #issuance-by-default: everyone valid (0), flip each revoked index to 1
    #length max_cred_num + 1 (indices 0..max_cred_num) to match ACA-Py _indexes_to_bit_array
    revocation_list = [0] * (max_cred_num + 1)
    for index in revoked:
        revocation_list[index] = 1
    return {
        "issuerId": _issuer_did(rev_reg_id),
        "revRegDefId": rev_reg_id,
        "revocationList": revocation_list,
        "currentAccumulator": accum,
        "timestamp": timestamp,
    }


async def verify(pres_req: dict, pres: dict) -> Tuple[bool, list]:
    """Verify a presentation end to end inside the enclave.

    Opens the ledger pool once, fetches the schema and cred def for every
    identifier straight from BCovrin (never trusting the REE), and for revocable
    identifiers also fetches the rev reg def + status list itself, runs the three
    pre-validation steps in order, then runs the AnonCreds proof verification
    (which also does holder binding and the non-revocation check). Any error
    returns (False, [error]) instead of raising.

    Args: pres_req, pres. Returns: (verified, msgs).
    """
    try:
        schemas = {}
        cred_defs = {}
        #populated below only for identifiers carrying a rev reg id + timestamp
        rev_reg_defs: dict = {}
        rev_lists: dict = {}

        #time the three non-overlapping sub-spans; they sum to the verify (enclave) total
        ledger_t0 = perf_counter()
        #open the pool once, always close it even on a fetch error
        pool = await open_ledger_pool()
        try:
            #fetch trust anchors for each identifier from the ledger itself
            for ident in pres["identifiers"]:
                schema_id = ident["schema_id"]
                cred_def_id = ident["cred_def_id"]
                if schema_id not in schemas:
                    schemas[schema_id] = await fetch_schema(pool, schema_id)
                if cred_def_id not in cred_defs:
                    cred_defs[cred_def_id] = await fetch_cred_def(pool, cred_def_id)
                #revocation: only for identifiers that carry a rev reg id + timestamp
                rev_reg_id = ident.get("rev_reg_id")
                timestamp = ident.get("timestamp")
                if rev_reg_id and timestamp is not None:
                    if rev_reg_id not in rev_reg_defs:
                        rev_reg_defs[rev_reg_id] = await fetch_rev_reg_def(pool, rev_reg_id)
                    #maxCredNum sizes the status bit-list; read it from the rev reg def
                    max_cred_num = rev_reg_defs[rev_reg_id]["value"]["maxCredNum"]
                    #rev_lists is keyed rev_reg_id -> timestamp -> status list; the crypto call flattens it
                    rev_lists.setdefault(rev_reg_id, {})
                    if timestamp not in rev_lists[rev_reg_id]:
                        rev_lists[rev_reg_id][timestamp] = await fetch_rev_reg_status(
                            pool, rev_reg_id, timestamp, max_cred_num
                        )
        finally:
            pool.close()
        #ledger span ends only after the pool is closed
        _vprint(f"[timing] verify: ledger fetch: {perf_counter() - ledger_t0:.6f} s", flush=True)

        #pre-validation: revocation hygiene, timestamps, structure + tamper
        prevalidation_t0 = perf_counter()
        msgs = []
        try:
            msgs += non_revoc_intervals(pres_req, pres, cred_defs)
            msgs += check_timestamps(pres_req, pres, cred_defs, rev_reg_defs)
            msgs += pre_verify(pres_req, pres)
        except ValueError as err:
            #a ValueError here is the holder's data failing pre-validation (e.g. a
            #predicate mismatch), which native ACA-Py reports as a genuine False with
            #a VALUE_ERROR:: message, NOT an internal fault. mirror it exactly: the
            #verifier appends VALUE_ERROR::{err} in insertion order, then ACA-Py's
            #handler stores list(set(verified_msgs)) UNCONDITIONALLY (handler.py:370,
            #both True and False verdicts), so this path gets the same list(set())
            #normalization as the success path. VALUE_ERROR:: is not VERIFY_ERROR::,
            #so the endpoint maps this to 200 (evaluation ran, verdict is "no").
            _vprint(f"[timing] verify: pre-validation: {perf_counter() - prevalidation_t0:.6f} s", flush=True)
            return (False, list(set(msgs + [f"VALUE_ERROR::{err}"])))
        _vprint(f"[timing] verify: pre-validation: {perf_counter() - prevalidation_t0:.6f} s", flush=True)

        #AnonCreds proof verification (includes holder binding) in Rust crypto;
        #run off the event loop since the call blocks
        crypto_t0 = perf_counter()
        presentation = Presentation.load(pres)
        try:
            verified = await asyncio.get_event_loop().run_in_executor(
                None,
                presentation.verify,
                pres_req,
                schemas,
                cred_defs,
                rev_reg_defs,
                [
                    rev_list
                    for timestamp_to_list in rev_lists.values()
                    for rev_list in timestamp_to_list.values()
                ],
            )
        except AnoncredsError as err:
            #a crypto-layer failure is native's VERIFY_ERROR:: path: verified=False
            #with the prefix, which the endpoint maps to 500 (could not evaluate → the
            #intercept records None). distinct from the VALUE_ERROR:: "no" above.
            _vprint(f"[timing] verify: crypto verification: {perf_counter() - crypto_t0:.6f} s", flush=True)
            return (False, [f"VERIFY_ERROR::{err}"])
        _vprint(f"[timing] verify: crypto verification: {perf_counter() - crypto_t0:.6f} s", flush=True)
        #dedupe via set() to mirror ACA-Py's handler (list(set(verified_msgs))); like
        #native the resulting order is hash-seeded, not the pipeline append order
        return (verified, list(set(msgs)))
    except Exception as err:
        #anything outside the two expected paths (e.g. ledger unreachable, a fetch
        #failure) is a genuine infrastructure fault, not a holder "no": report it as
        #VERIFY_ERROR:: (→ 500 → None) so it is never mislabelled as an invalid proof.
        #include the traceback so VM-side failures can be debugged
        return (False, [f"VERIFY_ERROR::{err}", traceback.format_exc()])


# --- SGX remote attestation (core contribution) ---------------------------
#Gramine exposes SGX attestation as two pseudo-files under /dev/attestation.
#we write exactly 64 bytes into user_report_data, then read quote: that read makes
#Gramine ask the hardware for a fresh quote carrying those 64 bytes plus this
#enclave's MRENCLAVE, signed via Intel DCAP. the 64 bytes are what we write in,
#not what comes back; the quote is variable-length and returned whole, unparsed

#Gramine reads the 64-byte report data from here before making a quote
USER_REPORT_DATA_PATH = "/dev/attestation/user_report_data"
#reading this pseudo-file triggers fresh quote generation by the hardware
QUOTE_PATH = "/dev/attestation/quote"
#the report-data field bound into the quote is always 64 bytes
REPORT_DATA_SIZE = 64


def get_quote() -> bytes:
    """Produce a fresh SGX attestation quote from the Gramine pseudo-files.

    Writes 64 bytes into user_report_data, then reads quote — that read makes
    Gramine request a fresh quote embedding the 64 bytes plus this enclave's
    MRENCLAVE, signed via Intel DCAP. The write must come first or the quote
    would not carry our report data. Here the report data is 64 zero bytes.

    Returns: the whole variable-length quote as raw bytes (unparsed).
    """
    #64 zero bytes of report data
    report_data = b"\x00" * REPORT_DATA_SIZE
    #write the report data first so the quote read below embeds it
    with open(USER_REPORT_DATA_PATH, "wb") as f:
        f.write(report_data)
    #reading the quote triggers hardware generation; read it whole (variable-length)
    with open(QUOTE_PATH, "rb") as f:
        return f.read()


#loopback host/port for the internal REE->TEE verification call; localhost only,
#never off-host, so plain HTTP is fine here
HOST = "127.0.0.1"
PORT = 5000

#RA-TLS listener. unlike the verify port this one is exposed (0.0.0.0) so the
#holder can attest over the network before any DIDComm. the cert/key are the
#RA-TLS pair gramine-ratls writes at startup; the cert embeds a live SGX quote
#(this enclave's MRENCLAVE) in an X.509 extension
RATLS_PORT = 5001
#/ratls is a tmpfs mount, so the pair stays in enclave memory and the private key
#is never written through to the host filesystem
RATLS_CERT_PATH = "/ratls/ratls.crt"
RATLS_KEY_PATH = "/ratls/ratls.key"
RATLS_HOST = "0.0.0.0"


def _wait_for_ratls_cert(timeout: int = 30) -> bool:
    """Wait until the RA-TLS cert and key files both exist on disk.

    gramine-ratls writes the cert/key just before it execs python, so this code
    can start a moment before both files are in place. Poll /ratls until both appear
    rather than failing on a missing file.

    Args: timeout (max seconds to wait). Returns: True if both appear in time, else False.
    """
    #deadline to stop polling
    deadline = perf_counter() + timeout
    while perf_counter() < deadline:
        #both cert and key must exist before the RA-TLS server can start
        if os.path.exists(RATLS_CERT_PATH) and os.path.exists(RATLS_KEY_PATH):
            return True
        sleep(0.1)
    #deadline passed with at least one file still missing
    return False

#verify() prepends this to an internally-raised error (vs a clean crypto "no"),
#so a false result with this prefix is a server-side failure (500), not a real "no" (200)
VERIFY_ERROR_PREFIX = "VERIFY_ERROR::"

#Flask app for the enclave-side verification service
app = Flask(__name__)


def _parse_request(body: Any) -> Tuple[dict, dict]:
    """Validate the request envelope and extract pres_req and pres.

    Envelope-only validation before any verification: the body must be a JSON
    object carrying both "pres_req" and "pres" as objects. Raises ValueError on
    any structural problem so the handler can answer 400.

    Args: body (the parsed JSON body). Returns: (pres_req, pres).
    """
    #the body itself must be a JSON object
    if not isinstance(body, dict):
        raise ValueError("Request body must be a JSON object")
    #both fields are required and must each be a JSON object
    pres_req = body.get("pres_req")
    pres = body.get("pres")
    if not isinstance(pres_req, dict):
        raise ValueError("Missing or non-object 'pres_req'")
    if not isinstance(pres, dict):
        raise ValueError("Missing or non-object 'pres'")
    return pres_req, pres


@app.get("/health")
def health_endpoint():
    #cheap liveness probe for the on-demand orchestrator; answers as soon as the
    #enclave is up and routing, no verification involved
    return jsonify({"status": "enclave up"}), 200


@app.post("/verify")
def verify_endpoint():
    """Verify a presentation; the status says whether evaluation happened, not the verdict.

    A false verdict is a successful evaluation whose answer is "no", so it returns
    200 with verified=False in the body. Status codes cover the cases where no
    verdict could be produced:

      200 evaluation ran — read verified (true or false) in the body
      400 malformed request envelope (bad JSON, missing pres/pres_req)
      500 internal failure inside verify() (the VERIFY_ERROR::-prefixed case)

    Returns: a Flask (json, status) response.
    """
    #400: body must be valid JSON with the required object fields
    try:
        body = request.get_json(force=True, silent=False)
        pres_req, pres = _parse_request(body)
    except Exception as err:
        return jsonify({"error": f"BAD_REQUEST::{err}"}), 400

    #run the verification core once (fresh event loop); time around the call only,
    #the core stays untouched. covers ledger fetch + pre-validation + crypto
    verify_t0 = perf_counter()
    verified, msgs = asyncio.run(verify(pres_req, pres))
    verify_elapsed = perf_counter() - verify_t0
    _vprint(f"[timing] verify (enclave): {verify_elapsed:.6f} s", flush=True)

    #500: a VERIFY_ERROR:: prefix on a false result means an internal failure
    #(e.g. ledger unreachable) where no verdict was produced
    if not verified and msgs and msgs[0].startswith(VERIFY_ERROR_PREFIX):
        return jsonify({"verified": False, "msgs": msgs}), 500

    #200: evaluation ran and produced a verdict (true or false in the body)
    return jsonify({"verified": verified, "msgs": msgs}), 200


@app.get("/quote")
def quote_endpoint():
    """Return a fresh SGX attestation quote for this enclave.

    Calls get_quote(), base64-encodes the raw bytes so they survive JSON, and
    wraps them in an object. The caller decodes and verifies the quote against
    Intel DCAP.

    Returns: a Flask (json, status) response carrying the base64 quote.
    """
    #500: quote generation failed (e.g. the attestation pseudo-files are absent
    #because we're not running under SGX)
    try:
        quote = get_quote()
    except Exception as err:
        return jsonify({"error": f"QUOTE_ERROR::{err}"}), 500
    #base64 so the raw bytes survive JSON transport
    quote_b64 = base64.b64encode(quote).decode("ascii")
    return jsonify({"quote": quote_b64}), 200


def _ratls_server_thread() -> None:
    """Serve the RA-TLS attestation endpoint on port 5001.

    Runs in its own thread alongside the loopback verify server. Its only job is
    to complete a TLS handshake presenting the RA-TLS cert (whose extension
    carries this enclave's live SGX quote and MRENCLAVE) so the holder can attest
    before any DIDComm. The HTTP body is irrelevant — the attestation is in the
    cert the handshake yields.
    """
    #cert/key are written by gramine-ratls at startup; wait for both
    if not _wait_for_ratls_cert():
        #never appeared in time: can't start the RA-TLS server
        _vprint("[ratls] cert/key not found; RA-TLS server not started", flush=True)
        return

    #load the RA-TLS cert/key into a server TLS context
    try:
        #plain server context; the RA-TLS cert is self-signed, trust is the embedded quote
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=RATLS_CERT_PATH, keyfile=RATLS_KEY_PATH)
    except Exception as err:
        #bad/unreadable cert/key: can't attest
        _vprint(f"[ratls] failed to load cert/key: {err}", flush=True)
        return

    #open the externally-reachable listening socket
    try:
        #plain TCP listener; each accepted connection is wrapped in TLS below
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #allow immediate rebind after a restart, no TIME_WAIT stall
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((RATLS_HOST, RATLS_PORT))
        listener.listen(5)
    except Exception as err:
        #port unavailable: the holder can never attest
        _vprint(f"[ratls] failed to open port {RATLS_PORT}: {err}", flush=True)
        return

    _vprint(f"[ratls] listening on {RATLS_HOST}:{RATLS_PORT}", flush=True)
    #accept forever, one attestation handshake per connection
    while True:
        conn, _addr = listener.accept()
        try:
            #wrap in TLS: this presents the RA-TLS cert and runs the handshake (the point)
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            try:
                #body doesn't matter, a minimal response is enough
                tls_conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                #holder hangs up as soon as the handshake gave it the cert, so this write
                #lands on a closed socket. attestation already succeeded, nothing to report
                pass
            tls_conn.close()
        except Exception as err:
            #one bad handshake must not kill the listener
            _vprint(f"[ratls] connection error: {err}", flush=True)
            #best-effort close if TLS wrapping failed
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    #self-reported startup: top of this module to readiness = Python import +
    #app setup inside the enclave. launcher total minus this = SGX/Gramine creation cost
    _vprint(f"[timing] enclave init (python/app): {perf_counter() - _STARTUP_T0:.3f} s", flush=True)
    #start the RA-TLS listener in a daemon thread before the verify server;
    #daemon=True so it doesn't block interpreter exit, runs on 5001 independently
    threading.Thread(target=_ratls_server_thread, daemon=True).start()
    #use_reloader=False: Gramine has no fork(). threaded=False: single sequential
    #caller and the per-request asyncio.run() must not race across threads. loopback only
    app.run(host=HOST, port=PORT, use_reloader=False, threaded=False)
