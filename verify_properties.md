Based on the provided TPM 2.0 Library Part 3 specification, here is a report detailing the functional features a firmware (operating as a test harness or OS) should verify to assess the correct implementation of `TPM2_Load` and `TPM2_ReadPublic` within a software simulator environment.

### **Firmware Verification Report: TPM2_Load and TPM2_ReadPublic**

This report outlines the critical functional behaviors and constraints defined in the TPM 2.0 specification that firmware should validate to ensure a TPM software simulator (e.g., QEMU) is compliant.

---

#### **1. TPM2_Load Verification Features**

The `TPM2_Load` command loads objects into the TPM using a parent key. Firmware can assess correct implementation by verifying the following specific behaviors:

**A. Attribute Consistency Checks**
The firmware should verify that the simulator enforces attribute rules before loading:

* 
**Sign/Encrypt Logic:** If the object is not a `keyedHash`, the firmware must verify that the simulator rejects the command with `TPM_RC_ATTRIBUTES` if both `sign` and `encrypt` attributes are CLEAR.


* 
**Key Size Consistency:** The firmware should verify that the size of the key in the sensitive area is consistent with the key size indicated in the public area; a mismatch must return `TPM_RC_KEY_SIZE`.



**B. Cryptographic Binding and Integrity**
The simulator must validate the link between public and private data. The firmware should perform tests to ensure:

* 
**Binding Validation:** The simulator must check that the public and sensitive portions are cryptographically linked. If they are not properly linked (e.g., if the firmware modifies `inPublic` but keeps `inPrivate` constant), the TPM must return `TPM_RC_BINDING`.


* 
**Integrity Check Order:** The firmware should verify that the simulator checks the integrity value of the private area *before* decrypting and unmarshaling it.


* 
**Weak Key Detection:** If the firmware attempts to load a known weak symmetric key in the sensitive portion, the simulator should return `TPM_RC_KEY`.



**C. Name Computation**
The firmware can verify the simulator's hashing implementation by checking the command outputs:

* 
**Name Generation:** The command returns the `Name` of the loaded object. The firmware should independently calculate the hash of the `inPublic` structure (using the object's `nameAlg`) and confirm it matches the `Name` returned by the simulator.


* 
**Unique Field Handling:** For symmetric objects, the firmware should verify that the `unique` value in the public area is derived correctly (digest of the sensitive key and obfuscation value).



**D. Input Validation**

* 
**Zero-Length Private Area:** The firmware should confirm that if `inPrivate.size` is zero, the load fails.



---

#### **2. TPM2_ReadPublic Verification Features**

The `TPM2_ReadPublic` command allows access to the public area of a loaded object. Firmware verification should focus on data fidelity and access control nuances.

**A. Data Fidelity (Input vs. Output)**

* **Public Area Match:** The firmware should load an object via `TPM2_Load` and immediately call `TPM2_ReadPublic` on the returned handle. It must verify that the `outPublic` structure returned exactly matches the `inPublic` structure originally provided.


* 
**Name Consistency:** The firmware must verify that the `name` returned by `TPM2_ReadPublic` matches the `name` returned by the `TPM2_Load` command for that same object.



**B. Authorization Independence**

* 
**No Authorization Required:** The firmware should verify that `TPM2_ReadPublic` executes successfully without requiring an authorization session (e.g., using `TPM_ST_NO_SESSIONS`), as the command allows access to the public area without authorization.



**C. Object Type Restrictions**

* **Sequence Objects:** The firmware should attempt to call `TPM2_ReadPublic` on a handle referencing a sequence object. The simulator must correctly identify the object type and return `TPM_RC_SEQUENCE`.



**D. Returned Identifiers**

* 
**Qualified Name:** The firmware should verify that the response includes not just the `name` but also the `qualifiedName` of the object, allowing the firmware to verify the simulator's calculation of the object's lineage.



---

### **Summary of Expected Failures (Negative Testing)**

To robustly assess the simulator, the firmware should trigger the following expected error codes:

* 
**TPM_RC_BINDING:** When `inPublic` and `inPrivate` do not mathematically correspond.


* 
**TPM_RC_ATTRIBUTES:** When a non-keyedHash object has `sign`=0 and `encrypt`=0.


* 
**TPM_RC_KEY_SIZE:** When sensitive key size differs from public parameter definition.


* 
**TPM_RC_SEQUENCE:** When attempting to read the public area of a sequence object.



**Next Step:** Would you like me to generate a specific test case scenario (e.g., a "Golden Data" test) for `TPM2_Load` using specific byte-values to verify the name computation?