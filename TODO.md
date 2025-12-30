# Trusted Platform Module (TPM) Implementation Project

## Project Objective
Design and implement a generic TPM simulation in Qemu with a focus on practical command chain implementation and a selected module development.

## Technical Specification
### Reference Documentation
- TCG TPM 2.0 Library Specification Part 3 (Part 3 Version 1.84) https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-3-Version-184_pub.pdf
- Focus on core TPM functionality and command structure

## Implementation Components

### 1. TPM Command Chain Implementation
#### Key Command Structures

- [X] Command Preparation
- [X] Command Transmission
- [X] Response Handling
- [X] Error Management

### 2. Selected TPM Module: Cryptographic Key Management
#### Chosen Module: Key Generation and Storage

#### Specific Implementation Features

- [ ] [ ] Asymmetric Key Pair Generation
- [ ] [ ] Secure Key Storage
- [ ] [ ] Key Lifecycle Management
- [X] [ ] Basic Cryptographic Operations

## Proposed Technical Architecture
1. **Software Simulation Layer**
   - [X] Command Parsing Mechanism: When the simulator receives a command, this component reads that byte stream. It decodes the command to figure out which TPM command is being requested.
   - [?] State Management: A real TPM maintains internal state.
   - [X] Simulated Hardware Interaction: It defines the API or mechanism through which external software sends commands to the simulator and receives responses from it. It manages the flow of command/response data.

2. **Cryptographic Module**
   - [ ] RSA Key Generation
   - [ ] Key Integrity Verification
   - [ ] Secure Storage Simulation

## Practical Implementation Approach
- Language: C/C++
- Simulation Platform: User-space software TPM
- Compliance: Partial implementation of TCG specifications

## Development Milestones
1. [X] Basic Command Chain Framework
2. [ ] Features Implementation
3. [ ] Validation and Testing
4. [ ] Documentation of Implementation Details

## Recommended Additional Modules (Optional Future Expansion)
1. [ ] Platform Configuration Registers (PCR)
2. [ ] Attestation Functionality
3. [ ] Sealed Storage Mechanisms

## Technical Challenges
- Accurate simulation of hardware-level security
- Implementing cryptographic primitives
- Maintaining specification compliance

## Expected Deliverables
- Custom QEMU version with TPM simulator
- Test Suite Demonstrating Module Functionality
- Full documentation covering design, implementation, and testing

# Next Steps

1. Implement
    - [ ] `TPM2_Create`
    - [ ] `TPM2_Load`
    - [ ] `TPM2_ReadPublic`
    - [ ] `TPM2_ObjectChangeAuth`
2. Implement firmware tests for
    - [ ] `TPM2_Create`
    - [ ] `TPM2_Load`
    - [ ] `TPM2_ReadPublic`
    - [ ] `TPM2_ObjectChangeAuth`
3. Solve `[MANSOUR]` warnings in `/include/hw/misc/tpm2_spec_protocol.h`

- [ ] Giovanni & Mateus: 1
- [ ] Tommaso: 2
- [ ] Mansour: 3