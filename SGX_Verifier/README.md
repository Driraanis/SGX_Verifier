# SGX Verifier — DIDComm Verifiable Credential verification inside an Intel SGX enclave

This project runs the verification step of a DIDComm-based Verifiable Credential
exchange **inside an Intel SGX enclave**. The party that decides whether a
presented proof is valid runs in a hardware-protected Trusted Execution
Environment (TEE); before presenting a proof, the Holder **remotely attests** the
enclave (Intel DCAP over an RA-TLS channel) and checks the enclave's measurement
(`MRENCLAVE`) against a value published on a ledger. Verification therefore cannot
be forged by a compromised host.

Three parties take part:

- **Verifier** — an ACA-Py agent (untrusted host) fronting the SGX enclave that
  performs the actual proof verification.
- **Holder (Alice)** — an ordinary, off-SGX agent that holds a credential and
  presents proofs; it attests the Verifier before presenting.
- **Issuer (Faber)** — a standard issuer used to place a credential in the
  Holder's wallet.

---

## Prerequisites

Deployed on an Intel SGX–capable machine (developed on an Azure DCsv3 VM).

| Component | Version / location |
|---|---|
| Intel SGX driver | `/dev/sgx_enclave` |
| Gramine | 1.9 (`gramine-sgx`, `gramine-manifest`, `gramine-sgx-sign`, `gramine-ratls`) |
| Intel DCAP QVL | `libsgx_dcap_quoteverify.so.1` (1.13.103.0) |
| Azure DCAP client library | `/usr/local/lib/libdcap_quoteprov.so` |
| Python | 3.13 |
| Ledger | Hyperledger Indy — BCovrin test net (`http://test.bcovrin.vonx.io`) |
| Attestation collateral | THIM (`global.acccache.azure.net`) for generation, Intel PCS for verification |

---

## Azure VM (provision, start, connect, deallocate)

The project was developed on an Azure **DCsv3** VM, the SGX-capable
confidential-computing size. All commands below use the Azure CLI (`az login`
first) and a single resource group, `<resource_group>`.

### Create

Create the resource group, then the VM. `Standard_DC2s_v3` is the SGX-enabled
size; Ubuntu 24.04 LTS and a 64 GB OS disk give enough room for Gramine, the
venv, and the Askar wallets.

The DCsv3 vCPU limit is 0 on a new subscription, so `az vm create` fails until a
quota increase for the Standard DCSv3 Family is requested in the portal, under
Quotas, and approved. One VM of this size needs two vCPUs.

```bash
az group create \
  --name <resource_group> \
  --location germanywestcentral

az vm create \
  --resource-group <resource_group> \
  --name <vm_name> \
  --image Canonical:ubuntu-24_04-lts:server:latest \
  --size Standard_DC2s_v3 \
  --admin-username <username> \
  --generate-ssh-keys \
  --location germanywestcentral \
  --os-disk-size-gb 64
```

`--generate-ssh-keys` writes a key pair to `~/.ssh` and installs the public key
on the VM. On success `az vm create` prints the `publicIpAddress`.

### Start

```bash
az vm start --resource-group <resource_group> --name <vm_name>
```

### Connect

SSH in as the admin user chosen at creation (`--admin-username` above), at the
VM's public IP. The IP is static — it stays the same across deallocate/start
cycles, so you can always connect to the same address:

```bash
ssh <username>@<public_IP>
```

If needed, the current public IP can be confirmed with:

```bash
az vm show -d --resource-group <resource_group> --name <vm_name> \
  --query publicIps -o tsv
```

### Deallocate

Deallocate when the VM is idle — this releases the compute and **stops compute
billing** (the OS disk is retained, so state and wallets survive). Restart later
with `az vm start`; the same static IP comes back, so the SSH command above is
unchanged.

```bash
az vm deallocate --resource-group <resource_group> --name <vm_name>
```

---

## Layout

```
SGX_Verifier/
├── enclave/                     enclave code + Gramine manifest (the TEE side)
│   ├── enclave_server.py        in-enclave verification service (verify / quote / health / RA-TLS)
│   ├── enclave_server.manifest.template   Gramine manifest source (tracked)
│   └── bcovrin_genesis.txn      pinned ledger genesis, measured into MRENCLAVE
├── Trusted_Registry_Server/
│   ├── registry_server.py       trust registry: invitation key → Verifier DID, with an admission allowlist
│   └── trusted_verifiers.json   allowlist of approved Verifier DIDs (ships empty)
└── aries-cloudagent-python/
    └── demo/runners/            the agents (bootstrap, verifier, alice, faber)
        ├── enclave_lifecycle.py  starts the enclave on demand, warm window, teardown
        ├── enclave_client.py     the Verifier's /verify call into the enclave
        ├── holder_attestation_verifier.py  Holder side: RA-TLS, quote check, MRENCLAVE vs ledger
        ├── attestation_module.py verify a live quote / publish its MRENCLAVE
        └── vlog.py               the shared violet output helper
```

---

## Setup (once, from a clean machine)

### System packages

Four repositories are needed: Intel's for the DCAP stack, Gramine's for Gramine,
Microsoft's for the Azure DCAP client library and the deadsnakes PPA for Python
3.13, which Ubuntu 24.04 does not ship. Microsoft builds that library for Ubuntu
22.04 and earlier, so its 22.04 repository is the one used here.

```bash
sudo apt update
sudo apt install -y curl gnupg software-properties-common

sudo add-apt-repository -y ppa:deadsnakes/ppa

curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
  https://packages.gramineproject.io/gramine-keyring-noble.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ noble main" \
  | sudo tee /etc/apt/sources.list.d/gramine.list

curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" \
  | sudo tee /etc/apt/sources.list.d/microsoft-prod.list

sudo apt update
sudo apt install -y libsgx-enclave-common libsgx-dcap-ql \
  libsgx-dcap-default-qpl sgx-pck-id-retrieval-tool \
  gramine \
  az-dcap-client \
  python3.13 python3.13-venv
```

The Gramine package brings `gramine-ratls`, which the enclave runs first, and
`az-dcap-client` installs the Azure library at
`/usr/local/lib/libdcap_quoteprov.so`, the path the next section points the
default provider at.

### The code

```bash
git clone https://github.com/Driraanis/SGX_Verifier.git ~/repo
mv ~/repo/SGX_Verifier ~/
rm -rf ~/repo
```

The repository carries both deployments, so it is cloned to a temporary folder
and only `SGX_Verifier` is moved into the home directory, where every command
below expects it. `no_enclave`, the native baseline, is moved the same way if it
is wanted.

### Virtual environment

Create and activate the project virtual environment (one level above `demo/`):

```bash
cd ~/SGX_Verifier/aries-cloudagent-python
python3.13 -m venv venv && source venv/bin/activate
pip install -U pip
pip install -e .
pip install -r demo/requirements.txt
pip install flask
```

`aries-askar`, `anoncreds`, `indy-vdr` and `aiohttp` are declared dependencies of
ACA-Py and arrive with the editable install, so they need no line of their own.
`demo/requirements.txt` adds what the demo runners need (`prompt_toolkit`,
`qrcode`, `pygments`, `asyncpg`), and Flask is used by the enclave server and the
trust registry.

> Activate the venv from `demo/` with `source ../venv/bin/activate`. If that
> prints "No such file or directory" it did not activate — confirm `(venv)` in
> your prompt before launching an agent.

---

## DCAP attestation collateral — required setup (split-source)

Remote attestation needs two different data sources, and on this Azure VM they
must come from **two different services**:

- **Quote generation** (the enclave producing its SGX quote) needs the platform's
  **PCK certificate**, which on a managed Azure VM must come from **THIM** — the
  tenant cannot fetch it from Intel PCS, since the platform provisioning data is
  not accessible to the tenant. Generation is therefore locked to the Azure DCAP
  client library.
- **Quote verification** (checking a quote via Intel DCAP) needs current **TCB
  collateral**, and THIM serves collateral that **expired in 2021** for this
  platform's FMSPC. Fresh collateral is available from **Intel PCS** directly.

So generation uses Azure and verification uses Intel. This is configured once:

```bash
# 1) make the default quote-provider library (used by quote GENERATION / AESM)
#    the Azure DCAP client library — it fetches the PCK cert from THIM and ignores qcnl.conf
sudo ln -sf /usr/local/lib/libdcap_quoteprov.so \
            /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1

# 2) point the two collateral keys at their services — read by the Intel QPL that
#    VERIFICATION selects (holder_attestation_verifier.py / attestation_module.py
#    call sgx_qv_set_path to the Intel QPL, which reads this file).
#    pccs_url retrieves PCK certificates and is therefore a THIM endpoint;
#    collateral_service retrieves everything else and points at Intel PCS
sudo tee /etc/sgx_default_qcnl.conf > /dev/null <<'EOF'
{
  "pccs_url": "https://global.acccache.azure.net/sgx/certification/v3/",
  "use_secure_cert": true,
  "pccs_api_version": "3.1",
  "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "retry_times": 6,
  "retry_delay": 10
}
EOF
sudo systemctl restart aesmd
```

> If attestation later fails with `0xe011` or `0xe03a`, re-apply the two commands
> above.

---

## One-time bootstrap (Verifier DID, schema, credential definition)

Creates the Verifier's ledger identity and the credential schema/definition, and
writes `verifier_config.json`:

```bash
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.bootstrap
```

Bootstrap prints the Verifier DID it created. Add it to the trust registry's
admission allowlist in `Trusted_Registry_Server/trusted_verifiers.json`, which
ships empty:

```json
["<the DID bootstrap printed>"]
```

The registry admits nobody by default, so until this is done it answers the
Verifier's registration with `403 untrusted verifier`, and the Verifier treats a
refused registration as fatal and exits on launch.

---

## Provision the pinned ledger genesis (once)

The enclave reads the ledger's genesis transactions from a local file rather than
fetching them at run time. The file is listed in the manifest's `sgx.trusted_files`,
so its contents are measured into `MRENCLAVE` at signing — the enclave's ledger
trust root is fixed at build time and any later change to the file changes
`MRENCLAVE`. Fetch it once before signing:

```bash
cd ~/SGX_Verifier/enclave
curl -sSL http://test.bcovrin.vonx.io/genesis -o bcovrin_genesis.txn
# sanity: expect a small number of JSON node-transaction lines
wc -l bcovrin_genesis.txn
```

The path is `GENESIS_PATH` in the manifest (`enclave/bcovrin_genesis.txn`) and is
overridable via the `GENESIS_PATH` environment variable. If the ledger's genesis
ever changes, refresh this file and re-sign + re-publish (the steps below), since
`MRENCLAVE` will change.

---

## Build and sign the enclave

**On a machine other than the one this was developed on, edit the paths first.**
`enclave_server.manifest.template` contains absolute paths under `/home/anis/`
in eight places: the script in `loader.argv`, `loader.env.PYTHONPATH`,
`loader.env.GENESIS_PATH`, two `fs.mounts` entries and three `sgx.trusted_files`
entries. Replace `/home/anis` with your own home directory throughout before
building. The manifest renders and signs cleanly either way, so a wrong path
shows up only as an enclave that cannot find its own script at run time.

One source file carries the same path: `enclave_lifecycle.py` sets
`enclave_dir = "/home/anis/SGX_Verifier/enclave"`, the directory the Verifier
runs `gramine-sgx enclave_server` from. Change it to your own home as well, or
the Verifier cannot start the enclave.

Gramine signs with a key it expects at `~/.config/gramine/enclave-key.pem`,
generated once per machine with `gramine-sgx-gen-private-key`.

The Gramine manifest is built in two steps — render the template, then sign it
(signing produces the `MRENCLAVE` measurement). Run this whenever the `.sgx` is
missing or the manifest changed:

```bash
cd ~/SGX_Verifier/enclave
gramine-manifest enclave_server.manifest.template enclave_server.manifest
gramine-sgx-sign --manifest enclave_server.manifest --output enclave_server.manifest.sgx
```

Always run both steps, in this order, and check that the first one succeeded.
If `gramine-manifest` fails (for example on an undefined Jinja variable) it writes
no manifest, and `gramine-sgx-sign` then signs the one left over from an earlier
build. The result looks like a successful build and neither command reports a
problem, but the enclave is the old one. `gramine-sgx-sign` prints the
measurement it produced, so the tell is a `MRENCLAVE` that has not changed after
an edit that should have changed it.

---

## Publish the expected MRENCLAVE to the ledger

Signing changes the `MRENCLAVE`, so the ledger anchor must be (re)published after
each rebuild — otherwise Holder attestation fails on a mismatch. Publishing needs
a live quote, so bring the enclave up standalone first:

```bash
# terminal 1 — start the enclave standalone (stays up)
cd ~/SGX_Verifier/enclave
gramine-sgx enclave_server

# terminal 2 — check the live quote first (no ledger involved)
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
python3 -m runners.attestation_module verify

# terminal 2 — publish the current MRENCLAVE under the Verifier DID
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.attestation_module publish_mrenclave
```

`verify` fetches the live quote and checks it against Intel, then prints the
`MRENCLAVE` it carries. It never opens the ledger, so it takes no `LEDGER_URL` and
writes nothing — run it to confirm attestation works before the publish.

Stop the standalone enclave (Ctrl-C) once `publish_mrenclave` confirms the read-back. For
the actual run below, the Verifier starts its own enclave on demand — you do not
keep a separate enclave terminal open.

---

## Run the full demo

All agents run with `--wallet-type askar-anoncreds`. **Order matters:** start the
trust registry first — the Verifier registers with it on launch and treats a
missing registry as a fatal error. Each command runs in its own terminal.

On a same-host run no extra environment is needed: `REGISTRY_URL` defaults to
`http://localhost:7777` (set it only for a cross-host run). The Holder takes the
attestation host from the invitation itself, so a cross-host run needs the
Verifier started with `--endpoint http://<host>:8040` — otherwise its invitation
advertises `localhost` and the Holder attests its own machine, which fails
closed.

```bash
# 1) Trust registry (port 7777) — start first
cd ~/SGX_Verifier/Trusted_Registry_Server
source ../aries-cloudagent-python/venv/bin/activate
python3 registry_server.py

# 2) Verifier — registers its invitation key on launch; starts the enclave on demand
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.verifier --port 8040 --wallet-type askar-anoncreds

# 3) Holder (Alice) — resolves the Verifier DID from the registry
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.alice --port 8030 --wallet-type askar-anoncreds

# 4) Issuer (Faber) — seeds Alice's wallet with a credential
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.faber --port 8020 --wallet-type askar-anoncreds
```

Paste the Faber invitation into Alice first (to obtain a credential), then the
Verifier invitation (to run the attested verification).

---

## Faber with revocation

To issue a **revocable** credential, the tails server must be running **before**
Faber. The tails server hosts the revocation registry's tails file: the Issuer
uploads it when creating the registry, and the Holder downloads it to build a
non-revocation proof.

Start the tails server first, in its own virtual environment:

```bash
source ~/indy-tails-server/venv/bin/activate
tails-server --host 0.0.0.0 --port 9000 \
  --storage-path ~/tails-files \
  --log-config ~/indy-tails-server/tails_server/config/logging-config.yml
```

Then launch Faber with revocation enabled, pointed at the tails server:

```bash
cd ~/SGX_Verifier/aries-cloudagent-python/demo
source ../venv/bin/activate
LEDGER_URL=http://test.bcovrin.vonx.io python3 -m runners.faber --port 8020 \
  --wallet-type askar-anoncreds \
  --revocation --tails-server-base-url http://localhost:9000
```

---

## Ports

| Port | Component |
|---|---|
| 5000 | enclave verify / health (loopback only) |
| 5001 | enclave RA-TLS (attestation) |
| 7777 | trust registry |
| 8049 | enclave wake endpoint (`/session/hello`) |
| 8040 | Verifier agent |
| 8030 | Holder (Alice) agent |
| 8020 | Issuer (Faber) agent |
| 9000 | tails server (revocation run only) |
