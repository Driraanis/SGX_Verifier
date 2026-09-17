# Verification of DIDComm based Verifiable Credentials in Trusted Execution Environment

Implementation submitted for the bachelor thesis at TU Berlin.
Two deployments of one DIDComm verification flow: in the first the credential
verification runs inside an Intel SGX enclave, in the second it runs natively,
so the two can be compared.

| folder | what it is |
|---|---|
| `SGX_Verifier/` | the Verifier whose verification runs inside the enclave, with remote attestation, an on-demand enclave lifecycle and a trusted registry |
| `no_enclave/` | the same flow verifying natively, the baseline every measurement is compared against |

Each folder has its own README covering setup from a clean machine through to the
demo run. Start there.

## Stack

ACA-Py 1.6.0 with Askar, DIDComm v1, AnonCreds, Hyperledger Indy on the BCovrin
test network, Intel SGX v2 under Gramine 1.9 with DCAP attestation, Python 3.13.
