# Specification: TPM 2.0 Simulation Peripheral for S32K358

## 1. Project Objective

The goal is to design and implement a generic Trusted Platform Module (TPM) 2.0 simulation within QEMU, specifically tailored for the **S32K358** platform. The implementation focuses on establishing a functional command-response chain and a robust cryptographic key management module.

---

## 2. Functional Scope

The peripheral serves as a security co-processor simulation, providing the host firmware with an interface to perform sensitive cryptographic operations without exposing private key material to the main system memory.

### 2.1 Supported TPM 2.0 Command Suite

To support a realistic key lifecycle, the following command subset is required:

* **Hierarchy Provisioning:** Implementation of `TPM2_CreatePrimary` to establish the initial seed and root of trust within the simulation.
* **Object Creation:** Implementation of `TPM2_Create` to generate sensitive child objects (RSA Key Pairs) under the primary hierarchy.
* **Context Management:** Implementation of `TPM2_Load` to move objects into the simulation's volatile memory for active use.
* **Cryptographic Operations:** Implementation of `TPM2_Sign` and `TPM2_ReadPublic` to demonstrate functional utility of the generated keys.

### 2.2 Data Integrity and Format

* **Native Endianness:** To optimize for development simplicity, the simulation will process all multi-byte fields using the **native endianness** of the host/target environment. The implementation will not enforce TCG-standard Big-Endian byte swapping.
* **Command Validation:** The system must validate command tags and parameter sizes before execution to ensure simulation stability.

---

## 3. Technical Architecture

The project follows a modular architecture to separate the emulation logic from the cryptographic providers.

### 3.1 Simulation Interface Layer

* **Interface Type:** Memory-Mapped I/O (MMIO) interface integrated into the S32K358 system bus.
* **Command Transport:** A simplified FIFO-based mechanism for binary byte-stream transmission between the guest firmware and the QEMU backend.
* **State Machine:** A logical state manager to handle transitions between "Idle," "Receiving," "Executing," and "Completion" phases.

### 3.2 Cryptographic Module

* **Engine:** Backend integration with host-side cryptographic libraries to perform RSA math.
* **Key Storage Simulation:** A volatile storage model for tracking "Loaded" vs. "Saved" objects within the simulation.
* **Lifecycle Management:** Logic to handle the generation, usage, and eviction of cryptographic handles.

---

## 4. Deliverables

The project will be considered complete upon the delivery of the following items:

* **Modified QEMU Source Code:** A dedicated fork of the QEMU repository containing the integrated S32K358 TPM peripheral and necessary machine-specific wiring.
* **Verification Firmware:** A minimal C-based driver/application for the S32K358 that demonstrates a successful "CreatePrimary -> Create -> Load -> Sign" workflow.
* **Design Documentation:** A high-level overview of the simulation logic and a guide for interacting with the peripheral from guest software.

---

## 5. Potential Future Expansions

While outside the immediate scope, the architecture is designed to eventually support:

1. **Platform Configuration Registers (PCR):** For measured boot simulations.
2. **Non-Volatile (NV) Storage:** For persistent key storage across QEMU reboots.
3. **Attestation:** Support for Quote commands and identity keys.
