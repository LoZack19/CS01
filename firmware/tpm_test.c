#include <stdint.h>
#include <stddef.h>
#include <string.h>

// MMIO Register Definitions
#define TPM_BASE         0x40000000

#define TPM_ACCESS       (*(volatile uint8_t*)(TPM_BASE + 0x0000)) // Used to request and check access to the TPM
#define TPM_STS          (*(volatile uint32_t*)(TPM_BASE + 0x0018))  // only 3 bytes used
#define TPM_DATA_FIFO    (*(volatile uint8_t*)(TPM_BASE + 0x0024)) // The FIFO register for sending commands and reading responses.

// Bitmask Constants
#define TPM_ACCESS_REQUEST_USE   0x02
#define TPM_ACCESS_ACTIVE_LOCAL  0x20

#define TPM_STS_COMMAND_READY    0x40
#define TPM_STS_GO               0x20
#define TPM_STS_DATA_AVAIL       0x10
#define TPM_STS_EXPECT           0x08

// Sample Command: TPM2_GetCapability
// This command queries the TPM for its properties.
uint8_t tpm_cmd[] = {
    0x80, 0x01,                         // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0C,             // command size = 12
    0x00, 0x00, 0x01, 0x7A,             // TPM2_CC_GetCapability
    0x00, 0x00, 0x00, 0x06              // TPM_CAP_TPM_PROPERTIES
};

// TODO: Replace with actual expected response from TPM implementation
uint8_t tpm_rsp_expected[] = {
    // Fill this in after running and capturing a real response
};

// Requests access to TPM locality 0 and waits until it is granted.
void tpm_wait_access() {
    TPM_ACCESS = TPM_ACCESS_REQUEST_USE;
    while (!(TPM_ACCESS & TPM_ACCESS_ACTIVE_LOCAL));
}

// Writes the command to the TPM FIFO, handling burst size as reported by TPM_STS.
void tpm_wait_burst_and_write(const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        uint32_t sts = TPM_STS;
        uint16_t burst = (sts >> 8) & 0xFFFF;
        if (burst == 0) continue; // Wait for burst to become available

        size_t count = (burst < (len - offset)) ? burst : (len - offset);
        for (size_t i = 0; i < count; ++i)
            TPM_DATA_FIFO = data[offset + i]; // Write data byte-by-byte

        offset += count;
    }
}

// Reads the TPM response from the FIFO into buf, up to max_len bytes.
// Sets actual_len to the number of bytes read.
void tpm_read_response(uint8_t* buf, size_t max_len, size_t* actual_len) {
    while (!(TPM_STS & TPM_STS_DATA_AVAIL));  // Wait for response to be available

    // Read the 10-byte TPM response header (tag, size, code)
    for (int i = 0; i < 10; ++i)
        buf[i] = TPM_DATA_FIFO;

    // Extract total response size from header
    uint32_t total = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
    if (total > max_len) total = max_len;

    // Read the rest of the response
    for (size_t i = 10; i < total; ++i)
        buf[i] = TPM_DATA_FIFO;

    *actual_len = total;
}

int main() {
    uint8_t rsp_buf[4096];
    size_t rsp_len;

    // 1. Request and wait for access to TPM locality 0
    tpm_wait_access();

    // 2. Prepare TPM for a new command
    TPM_STS = TPM_STS_COMMAND_READY;  // Enter Ready state

    // 3. Send the TPM2_GetCapability command to the TPM FIFO
    tpm_wait_burst_and_write(tpm_cmd, sizeof(tpm_cmd));

    // 4. Signal TPM to start processing the command
    TPM_STS = TPM_STS_GO;             // Begin execution

    // 5. Read the response from the TPM FIFO
    tpm_read_response(rsp_buf, sizeof(rsp_buf), &rsp_len);

    // 6. Validate the response length
    if (rsp_len != sizeof(tpm_rsp_expected)) {
        while (1); // Error: unexpected response length (loops forever)
    }

    // 7. Validate the response content
    if (memcmp(rsp_buf, tpm_rsp_expected, rsp_len) != 0) {
        while (1); // Error: response mismatch (loops forever)
    }

    // 8. Success: loop forever to indicate test passed
    while (1);
    return 0;
} 