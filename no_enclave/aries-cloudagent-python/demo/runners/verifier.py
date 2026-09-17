#no-enclave baseline verifier (scaffolding, not core contribution). the plain-ACA-Py
#counterpart to the TEE verifier: same proof request, same flow, but verification runs
#natively in the agent instead of inside an enclave — this is the performance baseline.
#trimmed from the Faber demo: drops issuance, revocation-issuing, multitenant and the
#menu, keeps only what a verifier needs — provision a fresh wallet, publish a multi-use
#OOB invitation, and auto-send a proof request once a DID Exchange completes.
#the VC verification is NOT written here: it's inherited from handle_present_proof_v2_0
#in agent_container.py (the native verify-presentation path), so this subclass gets it
#for free; we only wrap it in a wall-clock timer for the baseline number.
#
# Usage:
#   source ../venv/bin/activate
#   LEDGER_URL=http://test.bcovrin.vonx.io \
#       python3 -m runners.verifier --port 8040 --wallet-type askar-anoncreds

import asyncio
import datetime
import os
import sys
import time
from contextlib import asynccontextmanager

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from runners.support.utils import log_msg, prompt_loop  # noqa:E402
from runners.vlog import VIOLET_STYLE, vprint, vstatus  # noqa:E402

#anoncreds format key because the wallet is askar-anoncreds; "indy" would be a format mismatch
CRED_FORMAT_ANONCREDS = "anoncreds"

#schema the proof request is restricted to; matches the "degree schema" Faber issues from
SCHEMA_NAME = "degree schema"


@asynccontextmanager
async def phase_timer(label: str, via_log_msg: bool = False):
    """Print a wall-clock duration around an awaited block, per phase.

    Standalone on purpose: time.perf_counter() + our own violet output, no dependence
    on ACA-Py's --timing. One clean, reproducible number per phase boundary.

    Args: label (the phase step measured); via_log_msg (True for a line emitted while
    the menu prompt is active — routed through log_msg so prompt_toolkit renders the
    colour, since a raw ANSI code is escaped there; startup lines keep the raw vprint).
    """
    #startup lines go straight to the terminal (vprint); a webhook line prints while the
    #prompt is up, where raw ANSI is escaped, so it goes through log_msg instead
    emit = (lambda s: log_msg(s, color=VIOLET_STYLE)) if via_log_msg else vprint
    #perf_counter is monotonic, unaffected by wall-clock changes
    emit(f"[timing] {label}: start")
    start = time.perf_counter()
    try:
        yield
    finally:
        #emit the elapsed seconds even if the block raised
        elapsed = time.perf_counter() - start
        emit(f"[timing] {label}: {elapsed:.6f}s")


class VerifierAgent(AriesAgent):
    """AriesAgent that drives a no-enclave verifier: proof request out, native verify.

    Adds only the auto proof-request trigger on completed connections and a timer
    around the inherited native verification; no enclave, attestation or registry.
    """

    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        log_file: str = None,
        log_config: str = None,
        log_level: str = None,
        **kwargs,
    ) -> None:
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Verifier",
            no_auto=no_auto,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        #one proof request per connection, even if the webhook fires more than once
        self._proof_requested_connections: set = set()

    async def handle_connections(self, message) -> None:
        #base handler first: it sets the _connection_ready future the invitation wait needs
        await super().handle_connections(message)

        conn_id = message.get("connection_id")

        #a completed DID Exchange triggers the proof request
        if message.get("rfc23_state") == "completed":
            #exactly one proof request per connection
            if conn_id not in self._proof_requested_connections:
                self._proof_requested_connections.add(conn_id)
                await self._send_proof_request(conn_id)

    async def handle_present_proof_v2_0(self, message) -> None:
        #time the native verify-presentation (inherited from agent_container) so the
        #baseline number is directly comparable to the enclave path; nothing else changes
        if message.get("state") == "presentation-received":
            async with phase_timer("native verification (verification + ack)", via_log_msg=True):
                await super().handle_present_proof_v2_0(message)
        else:
            await super().handle_present_proof_v2_0(message)

    def generate_proof_request_web_request(self, connection_id: str) -> dict:
        """Build the anoncreds proof-request web request, mirroring the Faber demo.

        Same shape as faber.generate_proof_request_web_request (anoncreds branch):
        revealed name/date/degree restricted to the degree schema, and a
        birthdate_dateint <= (today - 18y) zero-knowledge predicate. The enclave
        verifier builds the identical request, so C1 and C3 stay comparable.

        Args: connection_id (the completed connection to request over).
        """
        #age cutoff computed exactly like faber: today minus 18 years, as a YYYYMMDD int
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        #restrict every attribute/predicate to the degree schema Faber issues from
        restrictions = [{"schema_name": SCHEMA_NAME}]
        req_attrs = [
            {"name": "name", "restrictions": restrictions},
            {"name": "date", "restrictions": restrictions},
            {"name": "degree", "restrictions": restrictions},
        ]
        req_preds = [
            {
                "name": "birthdate_dateint",
                "p_type": "<=",
                "p_value": int(birth_date.strftime(birth_date_format)),
                "restrictions": restrictions,
            }
        ]
        #AnonCreds proof-request shape: attrs/preds keyed by referent strings, exactly as faber
        proof_request = {
            "name": "Proof of Education",
            "version": "1.0",
            "requested_attributes": {
                f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
            },
            "requested_predicates": {
                f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
            },
            #a standalone verifier (Faber issues, this agent only verifies) must request
            #non-revocation proof itself so a revoked credential verifies False; faber omits
            #this in its non-revocation run only because it also issued the credential
            "non_revoked": {"to": int(time.time())},
        }
        #anoncreds format key is mandatory for the askar-anoncreds wallet
        return {
            "connection_id": connection_id,
            "presentation_request": {CRED_FORMAT_ANONCREDS: proof_request},
        }

    async def _send_proof_request(self, connection_id: str) -> None:
        """Send the anoncreds proof request over the given connection.

        Args: connection_id (the completed connection to request over).
        """
        web_request = self.generate_proof_request_web_request(connection_id)
        #fires from the connection webhook, so the menu prompt is up and a raw ANSI
        #colour would be escaped and printed literally: route it through log_msg
        log_msg(f"\n#20 Send proof request over connection {connection_id}", color=VIOLET_STYLE)
        await self.admin_POST("/present-proof-2.0/send-request", web_request)


async def main(args) -> None:
    """Start the verifier, publish a multi-use invitation, run until exit.

    Provisions a fresh wallet (no public DID — verification only reads the ledger),
    publishes one multi-use OOB invitation, and idles: each holder is handled via
    webhooks (connect -> proof request -> native verify), not a blocking wait.

    Args: args (parsed CLI args from arg_parser).
    """
    verifier_container = await create_agent_with_args(args, ident="verifier")

    #a verifier never issues, so it needs no public DID; skip registration entirely
    verifier_container.public_did = False

    try:
        vstatus("#1 Provision the no-enclave verifier agent")
        agent = VerifierAgent(
            "verifier.agent",
            verifier_container.start_port,
            verifier_container.start_port + 1,
            genesis_data=verifier_container.genesis_txns,
            genesis_txn_list=verifier_container.genesis_txn_list,
            no_auto=verifier_container.no_auto,
            timing=verifier_container.show_timing,
            wallet_type=verifier_container.wallet_type,
            log_file=verifier_container.log_file,
            log_config=verifier_container.log_config,
            log_level=verifier_container.log_level,
        )
        #same reason on the agent object: never advertise or register a public DID
        agent.public_did = False

        #start ACA-Py with a fresh wallet; no schema creation and no DID registration
        await verifier_container.initialize(the_agent=agent)

        #a verifier serves many holders, so the invitation is multi-use and non-blocking
        #(wait=False): connections arrive via webhooks, each triggering
        #handle_connections -> proof request
        vstatus("#2 Publish a multi-use out-of-band invitation")
        await verifier_container.generate_invitation(
            display_qr=True,
            multi_use_invitations=True,
            wait=False,
        )

        #event-driven: connect -> proof request -> verify all happen in the webhook
        #handlers, so the menu is one line — press X to exit. catch KeyboardInterrupt so
        #Ctrl-C falls through to the same shutdown path as X
        try:
            vstatus("Verifier ready — waiting for holders.")
            async for option in prompt_loop("    (X) Exit?\n[X] "):
                if option is None or option.strip() in "xX":
                    break
        except KeyboardInterrupt:
            pass

    finally:
        #fetch/print the ACA-Py timing table BEFORE terminate() — the agent must still be
        #up for the /status fetch. runs on any exit, needs --timing, guarded so a
        #shutdown-time failure can't mask the real exit reason
        if verifier_container.show_timing:
            try:
                timing = await verifier_container.agent.fetch_timing()
                if timing:
                    for line in verifier_container.agent.format_timing(timing):
                        vprint(line)
            except Exception as e:
                vprint(f"[timing] fetch failed at shutdown: {e}")

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
        os._exit(1)
