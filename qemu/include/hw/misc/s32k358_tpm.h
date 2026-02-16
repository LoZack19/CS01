/**
 * @file s32k358_tpm.h
 * @brief S32K358 TPM device model — state structure and register map.
 *
 * Defines the QOM type, TIS register fields, reset values, FIFO
 * sizes, and NV-memory limits for the emulated TPM device.
 *
 * @see s32k358_tpm.c          for the device implementation.
 * @see tpm_state_machine.c    for lifecycle command helpers.
 */

#ifndef HW_MISC_S32K358_TPM_H
#define HW_MISC_S32K358_TPM_H

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/irq.h"
#include "qom/object.h"
#include "qemu/log.h"

#include "hw/registerfields.h"
#include "hw/misc/tpm2_spec_protocol.h"

#define TYPE_S32K358_TPM "s32k358_tpm"
OBJECT_DECLARE_SIMPLE_TYPE(S32k358TPMState, S32K358_TPM)

#define S32K358_TPM_MEM_SIZE 0x4000

#define S32K358_TPM_INFIFO_SIZE  4096
#define S32K358_TPM_OUTFIFO_SIZE 4096

#define TPM_STATE_RST TPM_S_INIT

#define TPM_ACCESS_RST         0x00
#define TPM_INT_ENABLE_RST     0x00000000
#define TPM_INT_VECTOR_RST     0x00
#define TPM_INT_STATUS_RST     0x00000000
#define TPM_INTF_CAPS_RST      0x00000000
#define TPM_STS_RST            0x00000000
#define TPM_STS_burstCount_RST 64
#define TPM_DATA_FIFO_RST      0x00000000
#define TPM_INTERFACE_ID_RST   0x00000000
#define TPM_XDATA_FIFO_RST     0x00000000
#define TPM_DID_VID_RST        0x00000000
#define TPM_RID_RST            0x00

// NV Memory Configuration
#define S32K358_TPM_NV_MEM_SIZE             1024  /**< Total NV memory pool (bytes). */
#define S32K358_TPM_MAX_NV_BUFFER_SIZE      1024  /**< Max single NV buffer (bytes). */
#define S32K358_TPM_NV_MEM_FIRST_VALID_ADDR 0x04  /**< First allocatable NV offset. */

/**
 * @brief Write the completed response into the output FIFO.
 *
 * Sets @c dataAvail, updates @c burstCount, and transitions
 * the device to @c TPM_S_CMPL.
 *
 * @param[in,out] s  Device state.
 */
void tpm_finalize_response(S32k358TPMState *s);

/**
 * @brief Build and send a standard TPM response.
 *
 * Constructs a @c tpm_rsp_header_t with the given return code,
 * appends optional output data, and calls @ref tpm_finalize_response.
 *
 * @param[in,out] s     Device state.
 * @param[in]     rc    Response code.
 * @param[in]     data  Pointer to output payload (may be @c NULL).
 * @param[in]     size  Payload size in bytes.
 */
void tpm_send_response(S32k358TPMState *s, TPM_RC rc, const void *data,
                       size_t size);

/**
 * @brief Convenience wrapper — send an error response with no payload.
 *
 * Equivalent to @code tpm_send_response(s, rc, NULL, 0) @endcode.
 *
 * @param[in,out] s   Device state.
 * @param[in]     rc  Error code to return to the guest.
 */
static inline void tpm_send_error_response(S32k358TPMState *s, TPM_RC rc) {
    tpm_send_response(s, rc, NULL, 0);
}

/**
 * @brief Per-instance state of the S32K358 TPM device.
 *
 * Contains TIS registers, FIFO buffers, NV memory, hierarchy
 * enables, state-machine flags, and seed material.
 */
struct S32k358TPMState {
    SysBusDevice parent_obj; /**< Parent QOM object. */

    MemoryRegion iomem;  /**< MMIO region mapped to the system bus. */

    /** @brief Current TIS state-machine state. */
    enum {
        TPM_S_INIT,  /**< Power-on / reset, awaiting locality. */
        TPM_S_IDLE,  /**< Locality granted, awaiting commandReady. */
        TPM_S_READY, /**< Accepting command bytes via data FIFO. */
        TPM_S_RECV,  /**< Receiving command data. */
        TPM_S_EXEC,  /**< Executing the dispatched command. */
        TPM_S_CMPL   /**< Command complete, response available. */
    } tpm_state;

    TPM2B_SEED endorsement_seed; /**< Endorsement hierarchy seed. */
    TPM2B_SEED platform_seed;    /**< Platform hierarchy seed. */
    TPM2B_SEED owner_seed;       /**< Owner hierarchy seed. */
    TPM2B_SEED null_seed;        /**< Null hierarchy seed. */

    uint8_t tpm_access;
    uint32_t tpm_int_enable;
    uint8_t tpm_int_vector;
    uint32_t tpm_int_status;
    uint32_t tpm_intf_caps;
    uint32_t tpm_sts;
    uint32_t tpm_data_fifo;
    uint32_t tpm_interface_id;
    uint32_t tpm_xdata_fifo;
    uint32_t tpm_did_vid;
    uint8_t tpm_rid;

    // Fields for the NV index implementation
    uint8_t mem[S32K358_TPM_NV_MEM_SIZE];
    uint32_t nvmem_size;
    char *filename;

    /** @name State-machine lifecycle flags
     *  @{ */
    bool initialized;            /**< True after a successful TPM2_Startup. */
    bool in_failure_mode;        /**< True when the TPM is in failure mode. */
    bool in_fum_mode;            /**< True when in Field-Upgrade Mode. */
    bool orderly_shutdown;       /**< True after a successful TPM2_Shutdown. */
    bool startup_clear_required; /**< Force Startup(CLEAR) on next init. */
    bool read_only_mode;         /**< True when the TPM is read-only. */
    TPM_SU last_shutdown_type;   /**< Last shutdown type (CLEAR / STATE). */
    TPM_RC self_test_result;     /**< Self-test result code. */
    bool self_test_done;         /**< True after TPM2_SelfTest completes. */
    /** @} */

    state_clear_data gc;

    Fifo8 infifo;
    Fifo8 outfifo;
};

REG8(TPM_ACCESS, 0x0000) // Access Control Register
FIELD(TPM_ACCESS, requestUse, 1, 1)
FIELD(TPM_ACCESS, activeLocality, 5, 1)
REG32(TPM_INT_ENABLE, 0x0008)      // Interrupt Enable Register
REG8(TPM_INT_VECTOR, 0x000C)       // Interrupt Vector Register
REG32(TPM_INT_STATUS, 0x0010)      // Interrupt Status Register
REG32(TPM_INTF_CAPS, 0x0014)       // Interface Capabilities Register
REG32(TPM_STS, 0x0018)             // Status Register
FIELD(TPM_STS, Expect, 3, 1)       // Data can be sent to TPM
FIELD(TPM_STS, dataAvail, 4, 1)    // Data can be received from TPM
FIELD(TPM_STS, tpmGo, 5, 1)        // Start command execution
FIELD(TPM_STS, commandReady, 6, 1) // Start receiving
FIELD(TPM_STS, burstCount, 8,
      16) // Data that can be sent/received without waiting
REG32(TPM_DATA_FIFO,
      0x0024) // Data Register (ReadFIFO / WriteFIFO depending on direction)
REG32(TPM_INTERFACE_ID, 0x0030) // Interface ID Register
REG32(TPM_XDATA_FIFO, 0x0080)   // Extended Data FIFO Register (ReadFIFO /
                                // WriteFIFO depending on direction)
REG32(TPM_DID_VID, 0x0F00)      // Device ID and Vendor ID Register
REG8(TPM_RID, 0x0F04)           // Revision ID Register

#endif
