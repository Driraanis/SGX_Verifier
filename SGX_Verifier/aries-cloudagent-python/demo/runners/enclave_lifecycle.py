#manages the enclave process lifecycle for on-demand use: start it when a holder
#arrives, wait until ready, tear it down after an idle period
#scaffolding around the core TEE verification
from runners.enclave_client import wait_for_enclave_ready
import asyncio
import os
import socket
from signal import SIGTERM, SIGKILL
from time import perf_counter
from runners.vlog import VIOLET_STYLE
from runners.support.utils import log_msg

WARM_WINDOW = 600  # 10 minutes

#ports the enclave binds: 5000 loopback verify, 5001 RA-TLS. checked before every spawn
ENCLAVE_PORTS = (5000, 5001)


def _port_in_use(port: int) -> bool:
    #a successful TCP connect means something is already listening. used to spot an
    #enclave left over from a previous run before we spawn a new one on the same ports
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        #short timeout so the check never stalls startup
        sock.settimeout(0.2)
        #connect_ex returns 0 on success (a listener is there), an errno otherwise
        return sock.connect_ex(("127.0.0.1", port)) == 0



class EnclaveState:
    #tracks the enclave process's lifecycle state

    #not running
    DOWN = "DOWN"
    #launched but not yet ready to serve
    STARTING = "STARTING"
    #running and /health answers 200
    UP = "UP"

    def __init__(self) -> None:
        #starts DOWN since nothing runs on init
        self.state: str = EnclaveState.DOWN
        #handle to the enclave child process; None while DOWN so teardown always has something to check
        self.process: asyncio.subprocess.Process | None = None
        #task that stops the enclave after the warm window; None when no countdown is armed
        self._shutdown_timer: asyncio.Task | None = None

    async def start(self) -> None:
        #bring the enclave up on demand. safe to call concurrently: overlapping
        #callers converge on one running enclave instead of starting two

        #already up — nothing to do
        if self.state == EnclaveState.UP:
            return

        #a start is already running — wait for it instead of launching a second
        if self.state == EnclaveState.STARTING:
            await self._wait_until_up()
            return

        #DOWN: we own the start. flip to STARTING so concurrent callers wait above
        self.state = EnclaveState.STARTING
        #timestamp right before launch: the real cold-start path (DOWN -> spawn -> ready)
        spawn_t0 = perf_counter()
        try:
            #launch and block until /health returns 200
            await self._launch_and_wait_ready()
        except Exception:
            #start failed: reset to DOWN and re-raise, else later callers wait on a start that never ends
            self.state = EnclaveState.DOWN
            raise
        #ready — the enclave can serve requests now
        self.state = EnclaveState.UP
        #full spawn -> ready cold start incl. SGX/Gramine creation. separate from the
        #enclave's own "enclave init (python/app)" line (only the part after Python starts)
        log_msg(f"[timing] [enclave] cold-start (spawn -> ready): {perf_counter() - spawn_t0:.3f} s", color=VIOLET_STYLE)

    async def _wait_until_up(self) -> None:
        #wait for an in-progress start (by another caller) to reach UP. start() flips the
        #state to STARTING before launching, so polling it is enough: no second spawn can
        #happen while we wait
        while self.state == EnclaveState.STARTING:
            await asyncio.sleep(0.1)
        #a failed start resets to DOWN and re-raises in the owner, so a waiter that only
        #looped on STARTING would fall through and verify against an enclave that never
        #came up. raise here instead, mirroring what the owning caller sees
        if self.state != EnclaveState.UP:
            raise RuntimeError("enclave start failed while another caller was waiting")

    async def _launch_and_wait_ready(self) -> None:
        #launch the enclave process and poll /health until 200

        #dir holding enclave_server.manifest.sgx; gramine-sgx resolves "enclave_server" relative to it
        enclave_dir = "/home/anis/SGX_Verifier/enclave"
        #refuse to start if a previous enclave still holds our ports: otherwise its
        #stale /health would answer this run and silently serve verifications from
        #the old process. fail loudly instead of hijacking
        for port in ENCLAVE_PORTS:
            if _port_in_use(port):
                raise RuntimeError(
                    f"port {port} already in use — an enclave from a previous run is "
                    f"still up; kill it first (lsof -tiTCP:{port} -sTCP:LISTEN)"
                )
        #start the enclave under SGX; kept on self so teardown can signal/wait on it
        self.process = await asyncio.create_subprocess_exec(
            "gramine-sgx",
            "enclave_server",
            cwd=enclave_dir,
            #new session => this process is group leader, so gramine-sgx and its
            #forked children share one process group we can signal together
            start_new_session=True,
        )
        #block until /health returns 200 (ready)
        await self._wait_for_health()

    async def _wait_for_health(self) -> None:
        #poll the enclave's /health until it returns 200 (ready)

        #if the process already exited, it crashed on startup (returncode is None while alive)
        if self.process is not None and self.process.returncode is not None:
            raise RuntimeError(
                f"enclave process exited during startup "
                f"(returncode {self.process.returncode})"
            )
        #alive: wait for /health to report ready, or time out
        await wait_for_enclave_ready()

    async def stop(self) -> None:
        #tear down the enclave: signal the whole process group, wait, reset to DOWN

        #nothing running (never started or already exited): just normalise state and return
        if self.process is None or self.process.returncode is not None:
            self.state = EnclaveState.DOWN
            self.process = None
            return

        #gramine-sgx forks the actual loader; signalling only the parent can leave
        #that child alive and block wait() forever, so signal the whole group.
        #start_new_session=True means the child's PID is its group id (pgid)
        pgid = self.process.pid
        try:
            #ask the whole group to shut down
            os.killpg(pgid, SIGTERM)
            #gramine's wait() never returns cleanly after SIGTERM (child-reap quirk),
            #so we escalate to SIGKILL anyway — keep this window short (2s)
            await asyncio.wait_for(self.process.wait(), timeout=2)
        except ProcessLookupError:
            #group already gone between the check and the signal
            pass
        except asyncio.TimeoutError:
            #SIGTERM didn't take in 2s: force-kill the group and reap it
            try:
                os.killpg(pgid, SIGKILL)
            except ProcessLookupError:
                pass
            await self.process.wait()

        #enclave gone: reflect it in the state and drop the handle
        self.state = EnclaveState.DOWN
        self.process = None

    def force_stop(self) -> None:
        #synchronous last-resort teardown for exit paths where the event loop is
        #already gone — a Ctrl-C that escaped run_until_complete before the async
        #stop() could run. SIGKILL the whole group directly so no enclave is left
        #holding 5000/5001. idempotent: a no-op if stop() already ran

        #nothing running (never started, already stopped, or already exited)
        if self.process is None or self.process.returncode is not None:
            return
        #start_new_session=True made the child its own group leader, so pid == pgid
        pgid = self.process.pid
        try:
            #skip SIGTERM: gramine ignores it cleanly and always needs SIGKILL anyway
            os.killpg(pgid, SIGKILL)
        except ProcessLookupError:
            #group already gone between the check and the signal
            pass
        self.state = EnclaveState.DOWN
        self.process = None

    def keep_warm(self) -> None:
        #(re)arm the idle countdown. called after each verification so steady traffic
        #keeps the enclave warm; the window only elapses after WARM_WINDOW idle seconds

        #cancel any pending countdown so we start fresh from now, not the old deadline
        if self._shutdown_timer is not None and not self._shutdown_timer.done():
            self._shutdown_timer.cancel()
        #arm a new countdown that stops the enclave when it elapses
        self._shutdown_timer = asyncio.create_task(self._shut_down())

    async def _shut_down(self) -> None:
        #wait out the warm window with no new verification, then tear down. a fresh
        #keep_warm() cancels this task before the sleep returns, so the stop never happens
        await asyncio.sleep(WARM_WINDOW)
        #window elapsed with no new verification: shut down
        log_msg(f"[enclave] warm window ({WARM_WINDOW}s) elapsed — shutting down", color=VIOLET_STYLE)
        await self.stop()