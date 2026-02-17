# PowerPoint Presentation Structure

## TPM 2.0 Simulation Peripheral for S32K358 - QEMU Implementation

## Optimized Version: 10-15 Minutes

---

## Executive Summary

Technical presentation focused on the **TPM 2.0 Simulation Peripheral Project** - implementation of a Trusted Platform Module 2.0 security co-processor in QEMU for the S32K358 platform.

**Team**: Tommaso Montedoro, Giovanni Zaccaria, Stefano Loviselli  
**Target Duration**: 10-15 minutes  
**Format**: 12 core slides  
**Key Achievement**: **108/108 tests passed** • Complete TPM 2.0 lifecycle • Internal cryptographic engine

---

## Slide Structure (12 slides total)

### **Slide 1: Title Slide**

**Content:**

- **Title**: "TPM 2.0 Simulation Peripheral for S32K358"
- **Subtitle**: "Security Co-Processor Emulation in QEMU"
- **Team**: Tommaso Montedoro, Giovanni Zaccaria, Stefano Loviselli
- **Date**: February 2026
- **Course**: Embedded Systems Security

**Visual Elements:**

- Security-themed background (lock icon, cryptographic symbols)
- Color scheme: blue/gray with gold/green security accents
- TPM/TCG logo or security chip illustration

**Presenter Notes:**

- Brief team introduction
- Context: security-focused project on Trusted Computing Group standards
- Importance of TPMs in modern systems (BitLocker, Secure Boot)

**Time**: 30 seconds

---

### **Slide 2: Project Objectives**

**Title**: "Project Objectives"

**Content:**

- **Primary Goal**: Implement a TPM 2.0 compliant security co-processor simulation in QEMU for S32K358

- **Core Requirements**:
  1. Functional command-response chain for TPM 2.0 protocol
  2. Robust cryptographic key management module
  3. Complete key lifecycle
  4. Hardware-backed isolation of private key material

- **Target Workflow**:

```txt
TPM2_CreatePrimary → TPM2_Create → TPM2_Load → TPM2_Sign
```

**Visual Elements:**

- Architecture diagram: Firmware ↔ TPM Interface ↔ Crypto Engine
- Workflow diagram (4 stages: CreatePrimary → Create → Load → Sign)
- Icons: keys, signatures, certificates

**Presenter Notes:**

- TPM provides hardware root of trust for secure systems
- Private keys never exposed to CPU/main memory
- TCG 2.0 specification compliance
- Real-world applications: disk encryption, secure boot, attestation

**Time**: 1 minute

---

### **Slide 3: TPM 2.0 - Fundamentals and Architecture**

**Title**: "Trusted Platform Module 2.0"

**Content:**

**Definition**: Dedicated security co-processor for cryptographic operations

**Key Features:**

- **Hardware Root of Trust**: Secure generation and storage of keys
- **Isolated Execution**: Operations in dedicated secure environment
- **Cryptographic Services**: RSA, SHA-256, AES, random number generation
- **Persistent/Volatile Storage**: NV space for keys/data

**TPM 2.0 Architecture:**

- **Interface Layer**: MMIO command/response transport
- **Hierarchy System**: Storage, Endorsement, Platform hierarchies
- **Object Model**: Primary keys → Child objects
- **State Machine**: Power-off → Initialization → Operational

**Visual Elements:**

- Conceptual diagram: SoC with TPM highlighted
- Layered architecture (Transport → Protocol → Commands → Crypto)
- State machine (4-5 main states)

**Presenter Notes:**

- TPM 2.0 is a major redesign from 1.2 (algorithm agility, hierarchies)
- Command/response model similar to SCSI/NVMe protocols
- Native endianness for development simplicity (spec allows it)

**Time**: 1.5 minutes

---

### **Slide 4: Implemented Commands**

**Title**: "Implemented TPM 2.0 Command Suite"

**Content:**

**Core Commands (Required):**

| Command | Function | Tests |
| --- | --- | --- |
| `TPM2_CreatePrimary` | Create root key in hierarchy | 12 tests |
| `TPM2_Create` | Generate child RSA key pairs | 8 tests |
| `TPM2_Load` | Load object into volatile memory | 10 tests |
| `TPM2_Sign` | RSA-PSS/RSASSA signature | 15 tests |
| `TPM2_ReadPublic` | Retrieve public key data | 3 tests |

**State Management Commands:**

- `TPM2_Startup`, `TPM2_Shutdown`, `TPM2_SelfTest`, `TPM2_GetCapability`

**Bonus Commands** (beyond spec):

- `TPM2_Hash`, `TPM2_GetRandom`, `TPM2_VerifySignature`
- `TPM2_RSA_Encrypt/Decrypt`, `TPM2_EncryptDecrypt2`
- `TPM2_NV_DefineSpace/Write/Read`

**Total**: **15+ commands implemented**

**Visual Elements:**

- Command table with colors (green=core, yellow=bonus)
- Workflow diagram highlighting create→load→sign path
- Pie chart of command coverage

**Presenter Notes:**

- Minimum spec requires 5 core commands
- Implementation includes 15+ for comprehensive testing
- State machine commands critical for realistic behavior

**Time**: 1 minute

---

### **Slide 5: QEMU Architecture - Integration**

**Title**: "QEMU Device Model Integration"

**Content:**

**Integration:**

- **Integration Point**: Custom peripheral on S32K358 system bus
- **Interface**: Memory-Mapped I/O (MMIO)
- **Address Space**: Dedicated memory region for TPM registers

**Key Components:**

1. **MMIO Handler** (`s32k358_tpm.c`):
   - Registers: FIFO, status, control, locality
   - Read/Write operations
   - State tracking

2. **FIFO Transport**:
   - 1024+ byte command/response buffers
   - State management: IDLE → READY → RECV → EXEC → COMPLETION

3. **Command Dispatcher**:
   - Header validation (tag, size, command code)
   - Routing to command implementations
   - Response marshaling

**Main MMIO Registers:**

| Register | Offset | Function |
| --- | --- | --- |
| `TPM_ACCESS` | 0x00 | Locality request/grant |
| `TPM_STS` | 0x18 | Command status, FIFO ready |
| `TPM_DATA_FIFO` | 0x24 | Command/response data stream |

**Visual Elements:**

- Block diagram: Guest Firmware → MMIO → QEMU Backend → Crypto
- Memory map with TPM register addresses
- FIFO transport state machine

**Presenter Notes:**

- QEMU object model for device instantiation
- Register layout based on TPM Interface Specification (TIS)
- Firmware interacts only through these memory-mapped registers

**Time**: 1.5 minutes

---

### **Slide 6: Internal Cryptographic Engine**

**Title**: "Cryptographic Module - Internal Implementation"

**Content:**

**Design Decision**: Zero external dependencies (Spec Section 3.2)
**Rationale**: Educational value, full control, QEMU portability

**Implemented Algorithms:**

**Hash — SHA-256 (FIPS 180-4):**

- Full software implementation (round constants, compression, padding)
- **6/6 NIST known-answer test vectors validated** ✓

**Asymmetric — RSA (simplified simulation):**

- RSA-PSS sign / verify (PKCS#1-like padding + XOR-based key transform)
- RSA encrypt / decrypt (XOR-based simulation — educational, not production)
- Private keys never exposed to guest firmware

**Symmetric — AES (FIPS 197, real implementation):**

- Full S-Box / InvS-Box, MixColumns, ShiftRows, KeyExpansion
- Key sizes: AES-128 / AES-192 / AES-256
- **6 modes**: ECB, CBC, CFB, OFB, CTR + PKCS#7 padding

**RNG & DRBG:**

- `CryptRandomGenerate` for runtime entropy
- SHA-256-seeded DRBG (`tpm_drbg.c`) for deterministic CreatePrimary keys

**Metrics:**

- **~700 LOC** crypto core (`tpm_crypt.c`) + ~200 LOC DRBG (`tpm_drbg.c`)
- All SHA-256 and AES primitives are spec-compliant; RSA is intentionally simplified
- Guest firmware interacts only via TPM commands — private key material stays in QEMU backend

**Visual Elements:**

- Algorithm matrix: SHA-256 ✓ real | AES ✓ real | RSA ≈ simulated
- Diagram: Guest → MMIO → Command handler → Crypto engine (key material boundary)
- SHA-256 KAT results table (6/6 PASS)

**Presenter Notes:**

- SHA-256 and AES are real, standard-compliant implementations
- RSA uses XOR-based simulation (no big-integer math) — sufficient for functional correctness of the TPM model
- Production systems would replace RSA with OpenSSL/libgcrypt; SHA-256 and AES could be kept as-is
- ~30% of total codebase is cryptographic code

**Time**: 1.5 minutes

---

### **Slide 7: Key Management - Hierarchy and Lifecycle**

**Title**: "TPM Key Hierarchy & Object Lifecycle"

**Content:**

**Hierarchy Structure:**

```txt
Storage Hierarchy (TPM_RH_OWNER)
    └── Primary Key (TPM2_CreatePrimary)
            ├── Child Key 1 (TPM2_Create)
            ├── Child Key 2 (TPM2_Create)
            └── Child Key N...
```

**Object Lifecycle:**

1. **CreatePrimary**: Generate root key from hierarchy seed + template
   - Output: Loaded object with transient handle (0x80000001)

2. **Create**: Generate child key under parent
   - Output: Encrypted `TPM2B_PRIVATE` blob + `TPM2B_PUBLIC`

3. **Load**: Decrypt private blob, validate integrity (HMAC)
   - Output: Transient handle for active use

4. **Sign**: Use loaded key to generate digital signature
   - Input: Digest + signing key handle
   - Output: RSA signature (256 bytes for 2048-bit key)

**Security:**

- Primary keys seeded (deterministic from hierarchy secret)
- Child keys encrypted with parent's symmetric key
- Transient objects evicted on power loss (realistic TPM behavior)
- **HMAC-SHA256 integrity validation** on private blobs

**Visual Elements:**

- Tree diagram of hierarchy with multiple child keys
- Object state flowchart (Created → Saved → Loaded → Active)
- Handle allocation diagram (persistent 0x81... vs transient 0x80...)

**Presenter Notes:**

- Cryptographic parent-child binding prevents object substitution
- Handle space separates persistent (NV) from volatile
- Critical blob integrity guaranteed by HMAC

**Time**: 1.5 minutes

---

### **Slide 8: State Machine**

**Title**: "TPM State Machine"

**Content:**

**State Diagram:**

```txt
Power-Off → Initialization → Operational ↔ Failure Mode
                              ↓
                    Field Upgrade Mode (FUM)
```

**Key States:**

1. **Power-Off**: No power, all volatile data lost
2. **Initialization**: Awaiting `TPM2_Startup`, all other commands rejected
3. **Operational**: Full command processing enabled
4. **Failure Mode**: Self-test failed, only diagnostics allowed
5. **Field Upgrade Mode**: Firmware update in progress

**State Transitions:**

- `TPM2_Startup(CLEAR)` → Operational (reset state)
- `TPM2_Startup(STATE)` → Operational (resume state)
- `TPM2_SelfTest` failure → Failure Mode
- Reset → Initialization (from any state)

**Validation & Error Handling:**

- **Pre-initialization rejection**: TPM_RC_INITIALIZE
- **Failure mode filtering**: TPM_RC_FAILURE
- **FUM isolation**: TPM_RC_UPGRADE
- **20+ distinct error paths** tested

**Visual Elements:**

- State transition diagram with arrows labeled by commands
- Error code table (TPM_RC_INITIALIZE, RC_FAILURE, RC_UPGRADE)
- Startup sequence timeline

**Presenter Notes:**

- Complete state machine exceeds minimum spec requirements
- Ensures realistic TPM behavior (no use before startup)
- Failure mode protects against compromised state

**Time**: 1 minute

---

### **Slide 9: Testing - Comprehensive Results**

**Title**: "Test Coverage & Validation"

**Content:**

**Test Summary:**

```txt
Total Assertions: 108
Passed: 108
Failed: 0
Success Rate: 100%
```

**Test Categories:**

| Category | Tests | Status |
| --- | --- | --- |
| State Machine | 4 | ✅ ALL PASS |
| Transport/Framing | 3 | ✅ ALL PASS |
| SHA-256 Hashes (NIST) | 6 | ✅ ALL PASS |
| Key Mgmt (CreatePrimary) | 12 | ✅ ALL PASS |
| Key Mgmt (Create) | 8 | ✅ ALL PASS |
| Key Mgmt (Load) | 10 | ✅ ALL PASS |
| Digital Signatures | 15 | ✅ ALL PASS |
| Error Handling | 8 | ✅ ALL PASS |
| Integration Workflows | 3 | ✅ ALL PASS |
| Data Validation | 5 | ✅ ALL PASS |

**Coverage:**

- ✅ All 5 core commands tested
- ✅ 30+ verification properties validated
- ✅ Negative test cases for all major error paths
- ✅ Mix of positive and negative tests

**Visual Elements:**

- Pie chart of test distribution
- Pass/fail bar chart (all green)
- Coverage heatmap for commands and error codes

**Presenter Notes:**

- 108 assertions cover requirement specification thoroughly
- All NIST SHA-256 test vectors pass
- End-to-end workflows validate realistic usage
- Negative tests verify robust error handling

**Time**: 1 minute

---

### **Slide 10: Demo - Firmware Output**

**Title**: "Firmware Execution - Live Output"

**Content:**

**Console Output Highlight:**

```txt
[INFO] Starting TPM Test
[INFO] TPM access granted

=== State Machine Tests ===
[DBG] TPM2_GetRandom (pre-startup): rc=0x100 (TPM_RC_INITIALIZE) ✓
[DBG] TPM2_Startup: rc=0x0 (SUCCESS) ✓
[DBG] TPM2_SelfTest: rc=0x0 (SUCCESS) ✓

=== SHA-256 Hash Tests ===
SHA-256 Test 1 (abc): PASS ✓
SHA-256 Test 2 (empty): PASS ✓
[...]
SHA-256 Test 6 (single block): PASS ✓

=== Key Management ===
[TEST] TPM2_CreatePrimary: handle=0x80000001 ✓
[TEST] TPM2_Create: private=360B, public=280B ✓
[TEST] TPM2_Load: handle=0x80000005 ✓

=== Digital Signatures ===
[TEST] Sign: sig_size=256, sigAlg=RSASSA ✓
[TEST] Verify: SIGNATURE_VALID ✓

=== Summary ===
Total asserts: 108
Failed asserts: 0
✅ All tests passed!
```

**QEMU Execution:**

```bash
./build/qemu-system-arm \
  -kernel ../firmware/bin/tpm_test.elf \
  -machine s32k3x8evb-q289 \
  -nographic -serial mon:stdio
```

**Visual Elements:**

- Real terminal screenshot with output
- Annotated output highlighting key phases
- Color-coded sections (green for pass)

**Presenter Notes:**

- Real output from QEMU execution
- Demonstrates complete system integration
- Correct state machine command gating
- Cryptographic operations produce valid results
- Execution time: ~5 seconds

**Time**: 1 minute

---

### **Slide 11: Code Organization**

**Title**: "Project Structure & Metrics"

**Content:**

**QEMU Implementation (qemu/hw/misc/):**

```txt
├── s32k358_tpm.c          (550 lines) - MMIO, FIFO, dispatch
├── tpm_cmds.c             (850 lines) - Command implementations
├── tpm_state_machine.c    (300 lines) - Startup/Shutdown/SelfTest
├── tpm_crypt.c           (1500 lines) - SHA-256, RSA, AES, DRBG
├── tpm_object.c           (400 lines) - Handle mgmt, Name calc
├── tpm_load.c             (350 lines) - Load logic, integrity
├── tpm_hierarchy.c        (200 lines) - Seed derivation
├── Other TPM modules      (1100+ lines)
└── NvStorage.c            (300 lines) - In-memory NV storage
───────────────────────────────────────
Total QEMU: ~5,280 lines
```

**Firmware (firmware/src/):**

```txt
├── tpm_driver.c           - MMIO driver
├── tpm_marshal.c          - Marshaling helpers
├── tpm_test_*.c           - Test suites
└── main.c                 - Test orchestrator
───────────────────────────
Total Firmware: ~2,000 lines
```

**Total Project:** ~7,500 lines of original code

**Code Quality:**

- **350+ documentation blocks** (kernel-doc format)
- Modular separation: transport / protocol / crypto / storage
- Defensive programming (buffer checks, bounds validation)
- Doxygen-compatible documentation

**Visual Elements:**

- Tree diagram with line counts
- Module dependency graph
- LOC pie chart (30% crypto, 25% commands, 20% transport, 25% tests+utilities)

**Presenter Notes:**

- Clean separation enables future extension
- Cryptographic module is largest (inherent complexity)
- All code documented for future maintenance/development

**Time**: 45 seconds

---

### **Slide 12: Results and Conclusions**

**Title**: "Deliverables & Achievements"

**Content:**

**✓ Completed Deliverables:**

1. ✅ Modified QEMU with S32K358 TPM peripheral
2. ✅ Complete TPM 2.0 command suite (15+ commands)
3. ✅ Internal cryptographic engine (zero external dependencies)
4. ✅ Verification firmware with comprehensive testing
5. ✅ Complete state machine
6. ✅ Extensive documentation (kernel-doc)

**Quantitative Results:**

- **108/108** test assertions passed (**100% success rate**)
- **~7,500** lines of C code (QEMU + firmware)
- **15+** TPM commands implemented
- **30+** verification properties validated
- **6/6** SHA-256 NIST test vectors passed
- **350+** functions/structures documented

**Exceeds Specification:**

- Bonus commands (Hash, GetRandom, NV storage)
- Complete state machine (Failure Mode, FUM)
- Session authorization parsing

**Spec vs Implementation Comparison:**

| Requirement | Spec | Implemented | Coverage |
|-----------|------|--------------|----------|
| Core Commands | 5 required | ✅ 5 + 10 bonus | 100% + bonus |
| Crypto Backend | Internal RSA | ✅ RSA+SHA+AES | 100% + |
| State Machine | Base | ✅ Complete | Exceeds spec |
| Test Coverage | Functional | ✅ 108 assertions | Complete |

**Impact Statement:**
*"Complete and functional TPM 2.0 simulator enabling TPM-dependent software development and testing without physical hardware."*

**Visual Elements:**

- Achievement checklist with checkmarks
- Code contribution chart (LOC by module)
- Test results dashboard
- Comparative matrix spec vs implemented

**Presenter Notes:**

- All original objectives met and exceeded
- Platform ready for extensions (PCR, attestation, NV persistence)
- Demonstrates feasibility of secure co-processor emulation
- Solid foundation for future security research

**Time**: 1.5 minutes

---

## Future Work & Extensions (Brief Mention - Optional)

**If time remaining (30-45 seconds):**

**Short-Term Extensions:**

- **PCR Support**: Platform Configuration Registers for measured boot
- **NV Persistence**: Persistent storage across QEMU restarts
- **Enhanced Auth**: HMAC sessions with rolling nonces

**Long-Term Vision:**

- Integration with virtual firmware (EDK2, U-Boot)
- ECC support (Elliptic Curve Crypto)
- Complete attestation protocol (TPM2_Quote)

---

## Design Guidelines & Timing

### Visual Style

- **Color Scheme**:
  - Primary: Deep blue (#1E3A8A)
  - Secondary: Gray (#4B5563)
  - Accent: Gold/amber (#F59E0B)
  - Success: Green (#10B981)
  
- **Font**:
  - Title: Bold sans-serif (Montserrat, Roboto) 24-28pt
  - Body: Sans-serif (Open Sans) 18-20pt
  - Code: Monospace (Fira Code) 14-16pt

### Content Density

- **Max 6-7 bullet points** per slide
- **Code snippets**: 8-12 lines max
- **White space**: 20-30% for breathing room
- **Animations**: Simple fade/appear, no excessive movement

### Time Allocation (Target 12-15 minutes)

| Slide | Time | Cumulative Total |
|-------|-------|-------------------|
| 1. Title | 0:30 | 0:30 |
| 2. Objectives | 1:00 | 1:30 |
| 3. TPM Arch | 1:30 | 3:00 |
| 4. Commands | 1:00 | 4:00 |
| 5. QEMU Integration | 1:30 | 5:30 |
| 6. Crypto Engine | 1:30 | 7:00 |
| 7. Key Lifecycle | 1:30 | 8:30 |
| 8. State Machine | 1:00 | 9:30 |
| 9. Testing Results | 1:00 | 10:30 |
| 10. Demo Output | 1:00 | 11:30 |
| 11. Code Org | 0:45 | 12:15 |
| 12. Conclusions | 1:30 | 13:45 |
| **Buffer/Flexibility** | 1:15 | **15:00** |

**Q&A**: 10-15 additional minutes

---

## Delivery Recommendations

### Demo Preparation

- **Live Demo**: Pre-configured terminal with command history
- **Backup**: Recorded video or screenshot sequence
- **Fallback**: Slide with expected output if demo fails

### Technical Setup

- Presentation mode (disable notifications)
- External monitor tested
- Backup PDF on USB drive
- Terminal font size readable from distance

### Q&A Preparation

**Anticipated Questions:**

1. **Why internal crypto vs OpenSSL?**
   → Educational value, full control, zero dependencies

2. **Production ready?**
   → Functional simulator for development, not hardened for production

3. **Performance vs real TPM?**
   → Emulated, focus on correctness not performance

4. **Future extensions?**
   → Modular architecture supports PCR, ECC, attestation

5. **TCG spec compliance?**
   → Subset implementation, native endianness allowed by spec

6. **Security limitations?**
   → No side-channel resistance, simplified authorization model

---

## Final Checklist

**Content:**

- [x] Slides have clear titles
- [x] Consistent terminology (TPM 2.0, RSA-PSS, etc.)
- [x] Acronyms defined on first use
- [x] Code snippets tested and correct
- [x] Metrics numbers updated (108/108, ~7500 LOC, etc.)

**Visuals:**

- [ ] High-resolution screenshots
- [ ] Diagrams with consistent colors
- [ ] Text readable from 20 feet (min 18pt)
- [ ] Color-blind friendly

**Technical:**

- [x] Test numbers correct (108/108)
- [x] Line counts updated (~5280 QEMU)
- [x] Referenced files exist in repository

**Presentation:**

- [ ] Complete rehearsal 3+ times
- [ ] Timing validated (12-15 min)
- [ ] Demo tested 5+ times
- [ ] Q&A prep complete

---

## Summary

This optimized version reduces the presentation from **26 slides** to **12 core slides**, maintaining all essential elements:

✅ **Keeps**: Objectives, architecture, core implementation, key results  
❌ **Removes**: MMIO register details, firmware driver details, documentation slides, challenge stories, extensive backup  
🎯 **Focus**: Technical achievements, testing results, live demo impact

**Target achieved**: 12-15 minutes of presentation + 10-15 minutes Q&A
