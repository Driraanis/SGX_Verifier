#verifier runner (scaffolding, not core contribution). a lean AriesAgent subclass
#trimmed from the Faber demo: drops issuance, revocation, multitenant and the menu,
#keeps only what a verifier needs — open the bootstrap wallet, publish a multi-use
#OOB invitation, and auto-send a proof request once a DID Exchange completes.
#the VC verification is NOT here: it's inherited from handle_present_proof_v2_0 in
#agent_container.py (the enclave intercept), so any AriesAgent subclass gets it for
#free. this file only drives phases 1/3/4/5 (invitation -> DID exchange -> proof request -> presentation)
#
# Usage:
#   source ../venv/bin/activate
#   LEDGER_URL=http://test.bcovrin.vonx.io \
#       python3 -m runners.verifier --port 8040 --wallet-type askar-anoncreds

import asyncio
import json
import os
import sys
import time
import aiohttp
from aiohttp import web
from pathlib import Path

from runners.enclave_lifecycle import EnclaveState


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from runners.support.utils import log_msg, prompt_loop  # noqa:E402
from runners.vlog import vprint, vstatus, VIOLET_STYLE  # noqa:E402

#anoncreds format key because the wallet is askar-anoncreds; "indy" would be a format mismatch
CRED_FORMAT_ANONCREDS = "anoncreds"

#single source of truth from bootstrap.py: Verifier DID, wallet name/key, schema info. read-only here
CONFIG_FILE = Path(__file__).parent / "verifier_config.json"

#Trusted registry base URL; env-overridable so Alice can reuse the same base later
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:7777")


#Pull the invitation's recipient key out of the InvitationRecord, verbatim, with a shape guard
def extract_recipient_key(invi_rec: dict) -> str:
    #The inline out-of-band service we expect when the invitation is not a peer-DID invitation
    services = invi_rec.get("invitation", {}).get("services", [])
    #There must be at least one service to read a key from
    if not services:
        raise ValueError("invitation has no services; cannot extract recipient key")
    #The first service must be an inline dict carrying recipientKeys (peer-DID invitations fold it into a DID string instead)
    service = services[0]
    if not isinstance(service, dict) or "recipientKeys" not in service:
        raise ValueError("invitation service is not an inline dict with recipientKeys")
    #The recipientKeys list must be non-empty to give us a key
    keys = service["recipientKeys"]
    if not keys:
        raise ValueError("invitation service has empty recipientKeys")
    #Return the did:key string verbatim; no conversion to a bare verkey anywhere
    return keys[0]


#POST this verifier's invitation-key -> did:indy mapping to the trusted registry; fatal on any failure
async def register_in_registry(name: str, key: str, did: str) -> None:
    #Build the register endpoint from the shared base URL
    register_url = f"{REGISTRY_URL}/register"
    #The registry stores entries by name and resolves by key
    payload = {"name": name, "key": key, "did": did}
    #Explicit total timeout so a hung registry aborts startup rather than blocking forever
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        #Async POST so we never block the event loop
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(register_url, json=payload) as resp:
                #A non-200 means the registry rejected us — fatal, name the URL
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(
                        f"registry registration failed at {register_url}: "
                        f"{resp.status} {body}"
                    )
    #Connection refused, timeout, DNS, etc. — fatal, name the URL
    except aiohttp.ClientError as exc:
        raise RuntimeError(
            f"could not reach registry at {register_url}: {exc}"
        ) from exc

#Single enclave lifecycle manager shared by the hello endpoint (start) and the verification path (keep_warm)
enclave = EnclaveState()

#Port for the pre-attestation hello endpoint the holder
HELLO_PORT = int(os.environ.get("HELLO_PORT", 8049))


def load_verifier_config() -> dict:
    """Load verifier_config.json (written by bootstrap.py); exit if missing.

    The verifier can't run without the bootstrap identity, so a missing config is
    a hard stop, not a silent default.

    Returns: the parsed config dict (did, wallet_name, wallet_key, schema info, ...).
    """
    #no config means Phase 0 bootstrap hasn't run — refuse to continue
    if not CONFIG_FILE.exists():
        vprint(f"[verifier] {CONFIG_FILE} not found — run bootstrap first.")
        sys.exit(1)
    return json.loads(CONFIG_FILE.read_text())


async def handle_session_hello(request: web.Request) -> web.Response:
    """Pre-attestation trigger: bring the enclave up before the holder attests.

    The holder POSTs here right after getting the invitation. We start the enclave
    (or reuse it if warm) and only answer ready once /health is green, so the
    holder's remote attestation on port 5001 hits a live enclave.

    Args: request (body unused; presence is the signal).
    Returns: 200 {"ready": true} once up, or 503 {"ready": false, ...}.
    """
    try:
        #start on demand, or return at once if already warm
        await enclave.start()
    except Exception as err:
        #failed to come up: tell the holder it can't attest yet
        return web.json_response({"ready": False, "error": str(err)}, status=503)
    #arm the countdown here too, else an enclave nobody ever presents to stays up for good
    enclave.keep_warm()
    #up and /health green: the holder may attest
    return web.json_response({"ready": True}, status=200)


async def start_hello_server() -> web.AppRunner:
    """Build and start the standalone aiohttp server hosting POST /session/hello.

    Runs alongside the ACA-Py agent on HELLO_PORT, bound to 0.0.0.0 so a remote
    holder can reach it. Dedicated to the pre-attestation handshake, kept separate
    from the admin API.

    Returns: the AppRunner, so the caller can clean it up on shutdown.
    """
    #one route: the holder's pre-attestation hello
    app = web.Application()
    app.router.add_post("/session/hello", handle_session_hello)
    #AppRunner + TCPSite hosts aiohttp inside the already-running (agent) loop,
    #non-blocking, unlike web.run_app
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=HELLO_PORT)
    await site.start()
    vstatus(f"Hello endpoint listening on 0.0.0.0:{HELLO_PORT}/session/hello")
    return runner


class VerifierAgent(AriesAgent):
    """AriesAgent that anchors a verifier: bootstrap wallet in, proof request out.

    Inherits the enclave-backed handle_present_proof_v2_0 path unchanged; adds
    only the auto proof-request trigger on completed connections.
    """

    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        verifier_config: dict,
        no_auto: bool = False,
        log_file: str = None,
        log_config: str = None,
        log_level: str = None,
        **kwargs,
    ) -> None:
        #reuse the bootstrap wallet by passing wallet_name/wallet_key inside
        #params={...} (caught by DemoAgent's **params). NOT as direct kwargs or a
        #seed: a seed makes ACA-Py try to create a DID that conflicts with the
        #wallet's already-registered public DID (ConfigError). we just open it, not recreate
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Verifier",
            no_auto=no_auto,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            params={
                "wallet_name": verifier_config["wallet_name"],
                "wallet_key": verifier_config["wallet_key"],
            },
            **kwargs,
        )
        #route verification into the enclave. only the verifier sets this; the base
        #default (False) keeps every other agent on ACA-Py's native path. this is
        #the single switch that activates the intercept in handle_present_proof_v2_0
        self.use_enclave_verification = True
        #keep the config for the proof-request builder (schema restrictions)
        self.verifier_config = verifier_config
        #track which connections already got a proof request, so multiple webhook
        #events for one connection still send only one request
        self._proof_requested_connections: set = set()

    async def handle_connections(self, message) -> None:
        #call the base handler first: it sets the _connection_ready future the
        #invitation-wait loop needs. skipping it deadlocks invitation setup
        await super().handle_connections(message)

        conn_id = message.get("connection_id")

        #a completed DID Exchange (Phase 3 done) triggers Phase 4
        if message.get("rfc23_state") == "completed":
            #exactly one proof request per connection
            if conn_id not in self._proof_requested_connections:
                self._proof_requested_connections.add(conn_id)
                await self._send_proof_request(conn_id)

    async def handle_present_proof_v2_0(self, message) -> None:
        #run the inherited enclave-backed intercept unchanged
        await super().handle_present_proof_v2_0(message)
        #a verification just ran (verified or error) — that's activity, so reset
        #the warm window to keep the enclave alive for the next holder
        if message.get("state") == "presentation-received":
            enclave.keep_warm()

    async def _send_proof_request(self, connection_id: str) -> None:
        """Build and send the AnonCreds proof request over the given connection.

        Asks for three revealed attributes (name, date, degree) plus a
        birthdate_dateint <= age predicate, all restricted to the bootstrap
        schema. Sending it kicks off Phase 5 (the holder's VP).

        Args: connection_id (the completed connection to request over).
        """
        #restrict every attribute/predicate to the bootstrap schema, so only
        #credentials from the expected degree schema can satisfy it
        schema_name = self.verifier_config["schema_name"]
        restrictions = [{"schema_name": schema_name}]
        #18-years-ago cutoff as a YYYYMMDD int for the age predicate
        d = time.gmtime()
        cutoff = int(f"{d.tm_year - 18:04d}{d.tm_mon:02d}{d.tm_mday:02d}")
        req_attrs = [
            {"name": "name", "restrictions": restrictions},
            {"name": "date", "restrictions": restrictions},
            {"name": "degree", "restrictions": restrictions},
        ]
        req_preds = [
            {
                "name": "birthdate_dateint",
                "p_type": "<=",
                "p_value": cutoff,
                "restrictions": restrictions,
            }
        ]
        #AnonCreds proof-request shape: attrs/preds keyed by referent strings
        proof_request = {
            "name": "Proof of Education",
            "version": "1.0",
            "requested_attributes": {
                f"0_{a['name']}_uuid": a for a in req_attrs
            },
            "requested_predicates": {
                f"0_{p['name']}_GE_uuid": p for p in req_preds
            },
            #request a non-revocation proof valid as of now so a revoked credential fails
            "non_revoked": {"to": int(time.time())},
        }
        #anoncreds format key is mandatory for the askar-anoncreds wallet
        web_request = {
            "connection_id": connection_id,
            "presentation_request": {CRED_FORMAT_ANONCREDS: proof_request},
        }
        #fires from the connection webhook, so the menu prompt is up and a raw ANSI
        #colour would be escaped and printed literally: route it through log_msg
        log_msg(f"\n#20 Send proof request over connection {connection_id}", color=VIOLET_STYLE)
        await self.admin_POST("/present-proof-2.0/send-request", web_request)


async def main(args) -> None:
    """Start the verifier, publish a multi-use invitation, run until exit.

    Loads the bootstrap config, builds the agent container, constructs the
    VerifierAgent with auto-accept flags (so DID Exchange completes without manual
    steps), publishes one multi-use OOB invitation, and idles — each holder is
    handled via webhooks, not a blocking wait.

    Args: args (parsed CLI args from arg_parser).
    """
    #load the bootstrap identity before touching the network
    verifier_config = load_verifier_config()

    #no auto-accept flags here: AriesAgent.__init__ already appends
    #--auto-accept-invites/--auto-accept-requests/--auto-store-credential when
    #no_auto is False (default). passing them again would duplicate them
    verifier_container = await create_agent_with_args(args, ident="verifier")

    #the Verifier DID is already anchored from Phase 0. turn off public-DID
    #registration on container and agent so initialize() does NOT call register_did()
    #(that would make a second DID and a wrong endpoint). we only open the wallet
    verifier_container.public_did = False

    #handle to the hello server, set once it starts. init'd before the try so the
    #finally can check it even if startup fails earlier
    hello_runner = None

    try:
        vstatus("#1 Provision the verifier agent from the bootstrap wallet")
        agent = VerifierAgent(
            "verifier.agent",
            verifier_container.start_port,
            verifier_container.start_port + 1,
            verifier_config,
            genesis_data=verifier_container.genesis_txns,
            genesis_txn_list=verifier_container.genesis_txn_list,
            no_auto=verifier_container.no_auto,
            timing=verifier_container.show_timing,
            wallet_type=verifier_container.wallet_type,
            log_file=verifier_container.log_file,
            log_config=verifier_container.log_config,
            log_level=verifier_container.log_level,
        )
        #same reason on the agent object: never advertise/register a public DID
        agent.public_did = False

        #start ACA-Py with the bootstrap wallet (no schema creation, it's on the
        #ledger from Phase 0, and no DID registration either)
        await verifier_container.initialize(the_agent=agent)

        #a verifier serves many holders, so the invitation is multi-use and
        #non-blocking (wait=False): connections arrive via webhooks, each
        #triggering handle_connections -> proof request
        vstatus("#2 Publish a multi-use out-of-band invitation")
        #Capture the InvitationRecord so we can advertise its recipient key
        invi_rec = await verifier_container.generate_invitation(
            display_qr=True,
            multi_use_invitations=True,
            wait=False,
        )

        #Extract the did:key recipient key verbatim, with the inline-service shape guard
        recipient_key = extract_recipient_key(invi_rec)
        #Advertise this verifier so holders can tell it apart from a plain issuer;
        #fatal on failure — without it the whole attest-or-skip decision breaks.
        await register_in_registry("verifier.agent", recipient_key, verifier_config["did"])
        vstatus("#2b Registered invitation key in trusted registry as verifier.agent")

        #event-driven: all real work (connect -> proof request -> verify) happens
        #in the webhook handlers, so the menu is one line — press X to exit. we do
        #NOT reproduce Faber's issuer menu: those are manual issuer actions that
        #would clash with the automatic Phase 4 request this runner fires. catch
        #KeyboardInterrupt so Ctrl-C falls through to the same shutdown path as X,
        #instead of skipping the timing print via os._exit
        try:
            vstatus("Verifier ready — waiting for holders.")
            #bring up the pre-attestation hello endpoint now the agent is live;
            #keep the runner so the finally can tear it down
            hello_runner = await start_hello_server()
            async for option in prompt_loop("    (X) Exit?\n[X] "):
                if option is None or option.strip() in "xX":
                    break
        except KeyboardInterrupt:
            pass

    finally:
        #fetch/print the ACA-Py timing table BEFORE terminate() — the agent must
        #still be up for the /status fetch. runs on any exit (X or Ctrl-C), needs
        #--timing, wrapped so a shutdown-time failure can't mask the real exit reason
        if verifier_container.show_timing:
            try:
                timing = await verifier_container.agent.fetch_timing()
                if timing:
                    for line in verifier_container.agent.format_timing(timing):
                        vprint(line)
            except Exception as e:
                vprint(f"[timing] fetch failed at shutdown: {e}")

        #stop the enclave if running, so no SGX process is left behind
        await enclave.stop()
        #tear down the hello server, only if it actually started
        if hello_runner is not None:
            await hello_runner.cleanup()

        #always tear the agent down cleanly on exit
        terminated = await verifier_container.terminate()
        await asyncio.sleep(0.1)
        if not terminated:
            os._exit(1)


if __name__ == "__main__":
    #reuse the shared demo arg parser; default inbound port 8040 for the verifier
    parser = arg_parser(ident="verifier", port=8040)
    args = parser.parse_args()
    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        #a Ctrl-C can escape the loop before main()'s finally runs the async
        #enclave.stop(), orphaning the enclave so it keeps 5000/5001 for the next
        #run. force-kill it here so it never outlives the verifier; no-op if the
        #graceful stop() already ran
        enclave.force_stop()
        os._exit(1)
