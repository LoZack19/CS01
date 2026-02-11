Based on the provided specification, here are the details for the **TPM2_Load** and **TPM2_ReadPublic** commands.

---

## **TPM2_Load**

This command is used to load an object into the TPM when both the public (**TPM2B_PUBLIC**) and private (**TPM2B_PRIVATE**) areas are available.

### **General Description**

* 
**Purpose**: Loads a protected object so it can be used by the TPM. It is distinct from restoring a saved object context.


* 
**Attributes Check**: The TPM validates the object's `TPMA_OBJECT` attributes. If the object is not a `keyedHash` and both `sign` and `encrypt` attributes are CLEAR, the TPM returns `TPM_RC_ATTRIBUTES`.


* 
**Naming**: The object is assigned a Name, which is the concatenation of the `nameAlg` and the digest of the public area using that algorithm.


* **Validation**:
* The integrity of the private area is checked before decryption/unmarshaling to prevent "fuzzing" attacks.


* The sensitive area key size must match the size indicated in the public area (`TPM_RC_KEY_SIZE`).


* The TPM validates the cryptographic link between the public and sensitive portions before the object can be used (e.g., in a policy command). Failure to link results in `TPM_RC_BINDING`.




* 
**Persistence**: The returned handle remains valid until the object is flushed via `TPM2_FlushContext()` or until the next `TPM2_Startup()`.



### **Command and Response Schematics**

| Section | Field | Type | Description |
| --- | --- | --- | --- |
| **Command** | **@parentHandle** | `TPMI_DH_OBJECT` | Handle of the parent key (Auth: USER).

 |
|  | **inPrivate** | `TPM2B_PRIVATE` | The private portion of the object.

 |
|  | **inPublic** | `TPM2B_PUBLIC` | The public portion of the object.

 |
| **Response** | **objectHandle** | `TPM_HANDLE` | Transient handle for the loaded object.

 |
|  | **name** | `TPM2B_NAME` | The TPM-computed Name of the object.

 |

---

## **TPM2_ReadPublic**

This command allows a caller to read the public area of a loaded object.

### **General Description**

* 
**Scope**: Specifically for reading public areas of loaded objects and NV indices of type `TPM_HT_NV_INDEX`.


* 
**Authorization**: Use of the `objectHandle` for this command **does not require authorization**.


* 
**Restrictions**: If the `objectHandle` references a sequence object, the TPM will return `TPM_RC_SEQUENCE`.


* 
**Usage Note**: Because the caller may not know the public area beforehand, the Name of the object is not included in the `cpHash` computation for this command.



### **Command and Response Schematics**

| Section | Field | Type | Description |
| --- | --- | --- | --- |
| **Command** | **objectHandle** | `TPMI_DH_OBJECT` | TPM handle of the object to be read.

 |
| **Response** | **outPublic** | `TPM2B_PUBLIC` | Structure containing the object's public area.

 |
|  | **name** | `TPM2B_NAME` | The Name of the object.

 |
|  | **qualifiedName** | `TPM2B_NAME` | The Qualified Name of the object.

 |

---

**Would you like me to extract the specific error codes and their meanings associated with these commands?**