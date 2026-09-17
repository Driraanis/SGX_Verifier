import aiohttp
import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from time import perf_counter
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

#Phase 2 attestation entry point: run before DID Exchange to prove the Verifier is the expected SGX enclave
from runners.holder_attestation_verifier import (  # noqa:E402
    send_hello,
    verify_verifier_enclave,
)
from runners.vlog import vprint, VIOLET_STYLE  # noqa:E402

DEMO_EXTRA_AGENT_ARGS = os.getenv("DEMO_EXTRA_AGENT_ARGS")

#trusted registry base URL; same env var the verifier registers against
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:7777")

#abort message per attestation failure reason returned by verify_verifier_enclave.
#the three failures are different attacks, so each gets its own line: "dcap" = the
#quote is not a genuine Intel-signed SGX quote, "binding" = a genuine quote replayed
#inside a certificate whose key it does not commit to, "mrenclave" = a real enclave
#running the wrong build. "error" covers anything that raised
ATTEST_ABORT_MSGS = {
    "dcap": "invalid SGX quote, malicious attempt blocked",
    "binding": "quote not bound to this certificate, malicious attempt blocked",
    "mrenclave": "not matching MRENCLAVE, malicious attempt blocked",
    "error": "attestation failed, malicious attempt blocked",
}

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class AliceAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        aip: int = 20,
        endorser_role: str = None,
        log_file: str = None,
        log_config: str = None,
        log_level: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Alice",
            no_auto=no_auto,
            seed=None,
            aip=aip,
            endorser_role=endorser_role,
            log_file=log_file,
            log_config=log_config,
            log_level=log_level,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        #connections whose verifier we attested in Phase 2; the presentation gate
        #only lets Alice present a proof over a connection in this set
        self.attested_connections: set[str] = set()
        #set when an attestation/registry failure aborts the flow, so main() skips
        #the menu and drops to the shutdown path that frees the ports
        self.aborted = False
        #start of the full-flow holder timer (set at the hello in input_invitation);
        #read at the final ack (done state) to print the whole holder-perceived span
        self._flow_t0 = None

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    async def handle_present_proof_v2_0(self, message) -> None:
        #refuse a proof request on a not attested connection
        if message.get("state") == "request-received":
            conn_id = message.get("connection_id")
            if conn_id not in self.attested_connections:
                log_msg(f"NOT ALLOWED: proof request on unattested connection {conn_id}", color=VIOLET_STYLE)
                log_msg("Shutting down agent ...", color=VIOLET_STYLE)
                #yield so the loop runs log_msg's deferred run_in_terminal print (same as the connect await does for the other logs)
                await asyncio.sleep(0.3)
                #SIGKILL the subprocess to free 8030/8031, restore the terminal, hard-exit
                if self.proc:
                    self.proc.kill()
                os.system("stty sane")
                os._exit(1)
        #the shared handler does the holder's whole proof step on request-received:
        #query the wallet, build the ZKP, send it. bracket it so the full-flow span
        #below can be reconciled against its parts
        await super().handle_present_proof_v2_0(message)
        #full-flow holder timer ends at the final ack (done state): print the span from
        #the hello (set in input_invitation) to now
        if message.get("state") == "done" and self._flow_t0 is not None:
            log_msg(f"[timing] full flow timing: {perf_counter() - self._flow_t0:.3f} s", color=VIOLET_STYLE)
            self._flow_t0 = None


#look up the verifier DID for an invitation key in the trusted registry.
#returns (status, did): the HTTP status the registry answered and, on 200, its
#did:indy. an unreachable/timed-out registry is folded into a 503 so the caller
#branches on one value — 200 attest, 404 plain issuer, 400 malformed invitation,
#anything else registry error
async def resolve_verifier_did(recipient_key: str) -> tuple[int, str | None]:
    #resolve endpoint from the shared base URL
    resolve_url = f"{REGISTRY_URL}/resolve"
    #explicit total timeout so a hung registry doesn't block the flow
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        #async GET; the key travels verbatim as a query parameter
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(resolve_url, params={"key": recipient_key}) as resp:
                #only a 200 carries a DID; any other status carries none
                did = (await resp.json()).get("did") if resp.status == 200 else None
                return resp.status, did
    except (aiohttp.ClientError, asyncio.TimeoutError):
        #unreachable or timed out: report like a 5xx so the caller re-prompts
        return 503, None


async def input_invitation(agent_container):
    agent_container.agent._connection_ready = asyncio.Future()
    #only the 200 attest-pass sets this True; used after the connect to mark the attested for presentation
    attested = False
    async for details in prompt_loop("Invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            elif query and "oob=" in query:
                pos = query.index("oob=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                details = json.loads(details)
            except json.JSONDecodeError as e:
                #bad invitation JSON: log and re-prompt
                log_msg("Invalid invitation:", str(e))
                continue

            #a bare json scalar (4, true, null) is valid json, so it slips past the
            #error above and would only fail on the .get() below — re-prompt instead
            if not isinstance(details, dict):
                vprint("malformed invitation format — provide a valid invitation link.")
                continue

            #read the invitation's recipient key; a missing one is a malformed invite
            services = details.get("services", [])
            if (
                not services
                or not isinstance(services[0], dict)
                or not services[0].get("recipientKeys")
                or not urlparse(services[0].get("serviceEndpoint", "")).hostname
            ):
                vprint("malformed invitation format — provide a valid invitation link.")
                continue
            recipient_key = services[0]["recipientKeys"][0]

            #attest the host the invitation points at, never a configured one, so the box
            #that is attested is the box the exchange then runs against. no fallback: an
            #invitation with no host is rejected above rather than silently redirected
            verifier_host = urlparse(services[0]["serviceEndpoint"]).hostname

            #ask the trusted registry if the key belongs to an enclave trusted verifier
            status, resolved_did = await resolve_verifier_did(recipient_key)

            #400: bad key = malformed invitation, re-prompt
            if status == 400:
                vprint("malformed invitation format — provide a valid invitation link.")
                continue
            #500/503/anything else: the registry failed, re-prompt
            if status not in (200, 404):
                vprint("trusted registry error — please try again.")
                continue
            #404: not registered — a plain issuer, connect but leave it unattested
            if status == 404:
                vprint("Invitation key not registered — plain issuer, skipping attestation.")
                break

            #200: registered verifier — wake the enclave, then attest before connecting
            #start the full-flow holder timer at the hello; it ends at the final ack (done)
            agent_container.agent._flow_t0 = perf_counter()
            ready = await send_hello(verifier_host)
            if not ready:
                #enclave never came up: abort and shut down (frees the ports)
                vprint("ABORT: Verifier enclave did not become ready — shutting down.")
                #let the loop flush the log before we return into terminate()
                await asyncio.sleep(0.3)
                agent_container.agent.aborted = True
                return
            attested_ok, duration, reason = await verify_verifier_enclave(
                verifier_host, resolved_did
            )
            if not attested_ok:
                #a registry-trusted verifier can still fail attestation three different
                #ways, and they mean different things: a forged quote, a genuine quote
                #replayed inside someone else's cert, or the wrong enclave build. name
                #the actual one — a single "wrong MRENCLAVE" line would be false for
                #the other two
                vprint(ATTEST_ABORT_MSGS.get(reason, ATTEST_ABORT_MSGS["error"]))
                #let the loop flush the log before we return into terminate()
                await asyncio.sleep(0.3)
                agent_container.agent.aborted = True
                return
            #attestation passed: connect and mark this connection attested
            #vprint, not log_msg: no menu prompt is up here, and violet keeps our output
            #distinct from ACA-Py's pink built-in --timing table
            vprint(f"[timing] Verifier enclave attested OK in {duration:.3f} s")
            attested = True
            break

    with log_timer("Connect duration:"):
        connection = await agent_container.input_invitation(details, wait=True)

    #only a 200 attest-pass connection is marked attested
    if attested:
        conn_id = agent_container.agent.connection_id
        if conn_id:
            agent_container.agent.attested_connections.add(conn_id)


async def main(args):
    extra_args = None
    if DEMO_EXTRA_AGENT_ARGS:
        extra_args = json.loads(DEMO_EXTRA_AGENT_ARGS)
        print("Got extra args:", extra_args)
    alice_agent = await create_agent_with_args(
        args,
        ident="alice",
        extra_args=extra_args,
    )

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {alice_agent.wallet_type})"
                if alice_agent.wallet_type
                else ""
            )
        )
        agent = AliceAgent(
            "alice.agent",
            alice_agent.start_port,
            alice_agent.start_port + 1,
            genesis_data=alice_agent.genesis_txns,
            genesis_txn_list=alice_agent.genesis_txn_list,
            no_auto=alice_agent.no_auto,
            tails_server_base_url=alice_agent.tails_server_base_url,
            revocation=alice_agent.revocation,
            timing=alice_agent.show_timing,
            multitenant=alice_agent.multitenant,
            mediation=alice_agent.mediation,
            wallet_type=alice_agent.wallet_type,
            aip=alice_agent.aip,
            endorser_role=alice_agent.endorser_role,
            log_file=alice_agent.log_file,
            log_config=alice_agent.log_config,
            log_level=alice_agent.log_level,
            reuse_connections=alice_agent.reuse_connections,
            extra_args=extra_args,
        )

        await alice_agent.initialize(the_agent=agent)

        log_status("#9 Input faber.py invitation details")
        await input_invitation(alice_agent)

        #attestation/registry abort: skip the menu, finally frees the ports
        if agent.aborted:
            return

        options = "    (3) Send Message\n    (4) Input New Invitation\n"
        if alice_agent.endorser_role and alice_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if alice_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (X) Exit?\n[3/4/{}X] ".format(
            "W/" if alice_agent.multitenant else "",
        )
        try:
            async for option in prompt_loop(options):
                if option is not None:
                    option = option.strip()

                if option is None or option in "xX":
                    break

                elif option in "dD" and alice_agent.endorser_role:
                    endorser_did = await prompt("Enter Endorser's DID: ")
                    await alice_agent.agent.admin_POST(
                        f"/transactions/{alice_agent.agent.connection_id}/set-endorser-info",
                        params={
                            "endorser_did": endorser_did,
                            "endorser_name": "endorser",
                        },
                    )

                elif option in "wW" and alice_agent.multitenant:
                    target_wallet_name = await prompt("Enter wallet name: ")
                    include_subwallet_webhook = await prompt(
                        "(Y/N) Create sub-wallet webhook target: "
                    )
                    if include_subwallet_webhook.lower() == "y":
                        await alice_agent.agent.register_or_switch_wallet(
                            target_wallet_name,
                            webhook_port=alice_agent.agent.get_new_webhook_port(),
                            mediator_agent=alice_agent.mediator_agent,
                            taa_accept=alice_agent.taa_accept,
                        )
                    else:
                        await alice_agent.agent.register_or_switch_wallet(
                            target_wallet_name,
                            mediator_agent=alice_agent.mediator_agent,
                            taa_accept=alice_agent.taa_accept,
                        )

                elif option == "3":
                    msg = await prompt("Enter message: ")
                    if msg:
                        await alice_agent.agent.admin_POST(
                            f"/connections/{alice_agent.agent.connection_id}/send-message",
                            {"content": msg},
                        )

                elif option == "4":
                    # handle new invitation
                    log_status("Input new invitation details")
                    await input_invitation(alice_agent)
                    #a re-invitation can also abort; leave the menu to shut down
                    if agent.aborted:
                        break
        except KeyboardInterrupt:
            #Ctrl-C falls through to the shutdown path (timing print + terminate)
            #instead of hitting os._exit(1) in __main__ and skipping it
            pass

    finally:
        #print the ACA-Py timing table on any exit (X or Ctrl-C) while the agent is
        #still alive — before terminate(). needs --timing; guarded so a shutdown-time
        #failure can't mask the real exit
        if alice_agent.show_timing:
            try:
                timing = await alice_agent.agent.fetch_timing()
                if timing:
                    for line in alice_agent.agent.format_timing(timing):
                        log_msg(line)
            except Exception as e:
                vprint(f"[timing] fetch failed at shutdown: {e}")

        terminated = await alice_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="alice", port=8030)
    args = parser.parse_args()

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "Alice remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
