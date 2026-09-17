#trusted registry mapping a Verifier's invitation key to its did:indy, so Alice can tell an enclave Verifier from a plain issuer
#scaffolding: stands in for a trusted registry service, not part of the TEE core

import json
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

#json file the store is persisted to; env-overridable, defaults next to this module
REGISTRY_FILE = os.getenv("REGISTRY_FILE", os.path.join(os.path.dirname(__file__), "registry.json"))
#admission allowlist: the did:indy values permitted to register. this models the
#trusted registry's admission policy (EBSI-style); a real deployment uses EBSI.
ALLOWLIST_FILE = os.getenv("ALLOWLIST_FILE", os.path.join(os.path.dirname(__file__), "trusted_verifiers.json"))


#load the committed admission allowlist (a flat list of approved did:indy)
def _load_allowlist() -> set[str]:
    #a missing allowlist means nothing is approved: admit nobody, fail safe
    if not os.path.exists(ALLOWLIST_FILE):
        return set()
    try:
        with open(ALLOWLIST_FILE) as f:
            data = json.load(f)
        #only accept a list of strings; anything else admits nobody
        return set(d for d in data if isinstance(d, str)) if isinstance(data, list) else set()
    except (OSError, json.JSONDecodeError):
        return set()


#load the persisted store, or an empty store if the file is missing/unreadable
def _load_registry() -> dict[str, dict[str, str]]:
    #missing file on first run is normal: start empty
    if not os.path.exists(REGISTRY_FILE):
        return {}
    try:
        with open(REGISTRY_FILE) as f:
            data = json.load(f)
        #only accept a dict; a corrupt file falls back to empty rather than crashing
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


#write the current store to disk after each change
def _save_registry() -> None:
    with open(REGISTRY_FILE, "w") as f:
        json.dump(_registry, f)


#store keyed by Verifier name; persisted to REGISTRY_FILE, reloaded on restart
_registry: dict[str, dict[str, str]] = _load_registry()
#the set of did:indy allowed to register; loaded once at startup
_allowlist: set[str] = _load_allowlist()


#register or overwrite a Verifier's entry by name
@app.route("/register", methods=["POST"])
def register():
    #tolerate a missing/malformed content type
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid or missing JSON body"}), 400
    name = data.get("name")
    key = data.get("key")
    did = data.get("did")
    #all three must be present, non-empty strings
    if not all(isinstance(v, str) and v for v in (name, key, did)):
        return jsonify({"error": "missing or malformed fields: name, key, did"}), 400
    #admission control: only allowlisted did:indy may register (EBSI-style policy)
    if did not in _allowlist:
        return jsonify({"error": "untrusted verifier"}), 403
    #overwrite any previous entry for this name
    _registry[name] = {"key": key, "did": did}
    #persist so the entry survives a registry restart
    _save_registry()
    return jsonify({"status": "ok", "name": name}), 200


#resolve a did:indy by the invitation key it was registered under
@app.route("/resolve", methods=["GET"])
def resolve():
    key = request.args.get("key")
    #no key => bad request
    if not key:
        return jsonify({"error": "missing query parameter: key"}), 400
    #linear scan for the entry whose stored key matches
    for entry in _registry.values():
        if entry.get("key") == key:
            return jsonify({"did": entry["did"]}), 200
    return jsonify({"error": "not found"}), 404


if __name__ == "__main__":
    #bind all interfaces so agents on the same VM can reach it
    app.run(host="0.0.0.0", port=7777)
