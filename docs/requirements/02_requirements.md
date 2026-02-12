# Requirements

## Core TPM 2.0 Command Suite

These are the standard commands that must be implemented to support the required "CreatePrimary -> Create -> Load -> Sign" workflow:

* **`TPM2_CreatePrimary`**: Required to establish the initial seed and root of trust (Hierarchy Provisioning).
* **`TPM2_Create`**: Required to generate sensitive child objects, specifically RSA Key Pairs, under the primary hierarchy.
* **`TPM2_Load`**: Required to move the created objects into the simulation's volatile memory so they can be used.
* **`TPM2_Sign`**: Required to demonstrate the functional utility of the keys by performing cryptographic signing.
* **`TPM2_ReadPublic`**: Required to read the public portion of the keys to verify generation and utility.

## Internal Functional Requirements

In addition to the standard commands, the specification requires the implementation of these internal logic functions to support the peripheral:

* **MMIO Interface Logic:** To handle data transfer via the S32K358 system bus.
* **Command/Tag Validation:** To parse headers and ensure parameter sizes are correct before execution.
* **Native Endianness Processing:** Logic to handle multi-byte fields in the host's native format (ignoring standard Big-Endian swapping).
* **RSA Backend Integration:** Functions to bridge the TPM commands to the host's cryptographic libraries.

## Explicitly Excluded Functions

For clarity, the specification notes that the following are **not** needed for this phase (Section 5):

* Platform Configuration Registers (PCRs)
* Non-Volatile (NV) Storage functions
* Attestation commands (e.g., `TPM2_Quote`)
