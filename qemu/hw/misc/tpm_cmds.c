#include "hw/misc/s32k358_tpm.h"
#include "hw/misc/tpm_crypt.h"
#include <string.h>
#include <stdlib.h>

/* TPM responses */

void tpm_error_response(S32k358TPMState *s, TPM_RC rc) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header);
    rsp_header.responseCode = rc;

    // Marshal the response header onto the output FIFO
    tpm_rsp_header_marshal(&s->outfifo, &rsp_header);

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
}

void tpm_success_response(S32k358TPMState *s, const uint8_t *data, size_t size, void marshal_func(Fifo8 *fifo, const uint8_t *data)) {
    tpm_rsp_header_t rsp_header;

    rsp_header.tag = TPM_ST_NO_SESSIONS; // No sessions for this response
    rsp_header.responseSize = sizeof(rsp_header) + size;
    rsp_header.responseCode = TPM_RC_SUCCESS;

    // Marshal the response header onto the output FIFO
    tpm_rsp_header_marshal(&s->outfifo, &rsp_header);

    // Marshal the actual data onto the output FIFO
    marshal_func(&s->outfifo, data);

    // Update status to indicate data is available
    s->tpm_state = TPM_S_CMPL; // Transition to complete state
    s->tpm_sts |= R_TPM_STS_dataAvail_MASK;
    s->tpm_sts |= R_TPM_STS_commandReady_MASK;
    
    qemu_log_mask(LOG_GUEST_ERROR, "(INFO) TPM: Command executed successfully, response sent\n");
}

/* TPM Commands */

TPM_RC TPM2_GetRandom(GetRandom_In *in, GetRandom_Out *out) {
    // Truncate size to maximum supported digest size
    if(in->bytesRequested > sizeof(TPMU_HA)) {
        qemu_log_mask(LOG_GUEST_ERROR,
            "TPM2_GetRandom: Requested size %u exceeds maximum %zu, truncating\n",
            in->bytesRequested, sizeof(TPMU_HA)
        );

        out->randomBytes.size = sizeof(TPMU_HA);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
            "TPM2_GetRandom: Requested size %u is within limits, generating random bytes\n",
            in->bytesRequested
        );

        out->randomBytes.size = in->bytesRequested;
    }
    
    // Generate random bytes
    CryptRandomGenerate((uint16_t)out->randomBytes.size, (uint8_t *)out->randomBytes.buffer);
    
    return TPM_RC_SUCCESS;
}

/* Cryptographic Operations */

// SHA-256 hash function (improved implementation)
static void CryptHash(const BYTE *data, UINT16 dataSize, BYTE *digest) {
    SHA256_Calculate((const uint8_t *)data, (size_t)dataSize, (uint8_t *)digest);
}

// TPM 2.0 AES S-box (SubBytes substitution table)
static const BYTE AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// TPM 2.0 AES Inverse S-box (for decryption)
static const BYTE AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// TPM 2.0 AES Round Constants for key expansion
static const BYTE AES_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// TPM 2.0 AES Key Expansion (for AES-128, AES-192, AES-256)
static void AES_KeyExpansion(const BYTE *key, UINT16 keySize, BYTE *roundKeys) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    UINT16 numWords = (numRounds + 1) * 4;
    
    // Copy original key
    memcpy(roundKeys, key, keySize);
    
    // Generate round keys
    for (UINT16 i = keySize / 4; i < numWords; i++) {
        BYTE temp[4];
        memcpy(temp, &roundKeys[(i - 1) * 4], 4);
        
        if (i % (keySize / 4) == 0) {
            // RotWord and SubWord
            BYTE t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];
            
            temp[0] ^= AES_RCON[i / (keySize / 4)];
        } else if (keySize > 24 && i % (keySize / 4) == 4) {
            // Extra SubWord for AES-256
            temp[0] = AES_SBOX[temp[0]];
            temp[1] = AES_SBOX[temp[1]];
            temp[2] = AES_SBOX[temp[2]];
            temp[3] = AES_SBOX[temp[3]];
        }
        
        // XOR with previous word
        for (UINT16 j = 0; j < 4; j++) {
            roundKeys[i * 4 + j] = roundKeys[(i - keySize / 4) * 4 + j] ^ temp[j];
        }
    }
}

// TPM 2.0 AES SubBytes transformation
static void AES_SubBytes(BYTE *state) {
    for (UINT16 i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

// TPM 2.0 AES InvSubBytes transformation
static void AES_InvSubBytes(BYTE *state) {
    for (UINT16 i = 0; i < 16; i++) {
        state[i] = AES_INV_SBOX[state[i]];
    }
}

// TPM 2.0 AES ShiftRows transformation
static void AES_ShiftRows(BYTE *state) {
    BYTE temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// TPM 2.0 AES InvShiftRows transformation
static void AES_InvShiftRows(BYTE *state) {
    BYTE temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// TPM 2.0 AES MixColumns transformation
static void AES_MixColumns(BYTE *state) {
    for (UINT16 i = 0; i < 4; i++) {
        BYTE s0 = state[i * 4];
        BYTE s1 = state[i * 4 + 1];
        BYTE s2 = state[i * 4 + 2];
        BYTE s3 = state[i * 4 + 3];
        
        state[i * 4] = AES_GFMul(0x02, s0) ^ AES_GFMul(0x03, s1) ^ s2 ^ s3;
        state[i * 4 + 1] = s0 ^ AES_GFMul(0x02, s1) ^ AES_GFMul(0x03, s2) ^ s3;
        state[i * 4 + 2] = s0 ^ s1 ^ AES_GFMul(0x02, s2) ^ AES_GFMul(0x03, s3);
        state[i * 4 + 3] = AES_GFMul(0x03, s0) ^ s1 ^ s2 ^ AES_GFMul(0x02, s3);
    }
}

// Forward declaration for AES Galois Field multiplication
static BYTE AES_GFMul(BYTE a, BYTE b);

// TPM 2.0 AES InvMixColumns transformation
static void AES_InvMixColumns(BYTE *state) {
    for (UINT16 i = 0; i < 4; i++) {
        BYTE s0 = state[i * 4];
        BYTE s1 = state[i * 4 + 1];
        BYTE s2 = state[i * 4 + 2];
        BYTE s3 = state[i * 4 + 3];
        
        state[i * 4] = AES_GFMul(0x0e, s0) ^ AES_GFMul(0x0b, s1) ^ AES_GFMul(0x0d, s2) ^ AES_GFMul(0x09, s3);
        state[i * 4 + 1] = AES_GFMul(0x09, s0) ^ AES_GFMul(0x0e, s1) ^ AES_GFMul(0x0b, s2) ^ AES_GFMul(0x0d, s3);
        state[i * 4 + 2] = AES_GFMul(0x0d, s0) ^ AES_GFMul(0x09, s1) ^ AES_GFMul(0x0e, s2) ^ AES_GFMul(0x0b, s3);
        state[i * 4 + 3] = AES_GFMul(0x0b, s0) ^ AES_GFMul(0x0d, s1) ^ AES_GFMul(0x09, s2) ^ AES_GFMul(0x0e, s3);
    }
}

// TPM 2.0 AES Galois Field multiplication
static BYTE AES_GFMul(BYTE a, BYTE b) {
    BYTE result = 0;
    for (UINT16 i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        BYTE carry = a & 0x80;
        a <<= 1;
        if (carry) {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    return result;
}

// TPM 2.0 AES AddRoundKey transformation
static void AES_AddRoundKey(BYTE *state, const BYTE *roundKey) {
    for (UINT16 i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// TPM 2.0 AES Block Encryption (ECB mode)
static void AES_EncryptBlock(const BYTE *plaintext, const BYTE *roundKeys, UINT16 numRounds, BYTE *ciphertext) {
    BYTE state[16];
    memcpy(state, plaintext, 16);
    
    // Initial round
    AES_AddRoundKey(state, roundKeys);
    
    // Main rounds
    for (UINT16 round = 1; round < numRounds; round++) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_MixColumns(state);
        AES_AddRoundKey(state, &roundKeys[round * 16]);
    }
    
    // Final round (no MixColumns)
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_AddRoundKey(state, &roundKeys[numRounds * 16]);
    
    memcpy(ciphertext, state, 16);
}

// TPM 2.0 AES Block Decryption (ECB mode)
static void AES_DecryptBlock(const BYTE *ciphertext, const BYTE *roundKeys, UINT16 numRounds, BYTE *plaintext) {
    BYTE state[16];
    memcpy(state, ciphertext, 16);
    
    // Initial round
    AES_AddRoundKey(state, &roundKeys[numRounds * 16]);
    
    // Main rounds
    for (UINT16 round = numRounds - 1; round > 0; round--) {
        AES_InvShiftRows(state);
        AES_InvSubBytes(state);
        AES_AddRoundKey(state, &roundKeys[round * 16]);
        AES_InvMixColumns(state);
    }
    
    // Final round (no InvMixColumns)
    AES_InvShiftRows(state);
    AES_InvSubBytes(state);
    AES_AddRoundKey(state, roundKeys);
    
    memcpy(plaintext, state, 16);
}

// TPM 2.0 AES CBC Mode Encryption
static void AES_CBC_Encrypt(const BYTE *plaintext, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *ciphertext, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE currentIV[16];
    memcpy(currentIV, iv, 16);
    
    // Process full blocks
    for (size_t i = 0; i < dataSize; i += 16) {
        BYTE block[16];
        
        // XOR plaintext with IV
        for (int j = 0; j < 16; j++) {
            block[j] = plaintext[i + j] ^ currentIV[j];
        }
        
        // Encrypt block
        AES_EncryptBlock(block, roundKeys, numRounds, &ciphertext[i]);
        
        // Update IV for next block
        memcpy(currentIV, &ciphertext[i], 16);
    }
    
    // Copy final IV for output
    memcpy(ivOut, currentIV, 16);
}

// TPM 2.0 AES CBC Mode Decryption
static void AES_CBC_Decrypt(const BYTE *ciphertext, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *plaintext, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE currentIV[16];
    memcpy(currentIV, iv, 16);
    
    // Process full blocks
    for (size_t i = 0; i < dataSize; i += 16) {
        BYTE block[16];
        BYTE nextIV[16];
        
        // Save current ciphertext block for next IV
        memcpy(nextIV, &ciphertext[i], 16);
        
        // Decrypt block
        AES_DecryptBlock(&ciphertext[i], roundKeys, numRounds, block);
        
        // XOR with IV
        for (int j = 0; j < 16; j++) {
            plaintext[i + j] = block[j] ^ currentIV[j];
        }
        
        // Update IV for next block
        memcpy(currentIV, nextIV, 16);
    }
    
    // Copy final IV for output
    memcpy(ivOut, currentIV, 16);
}

// TPM 2.0 AES CFB Mode Encryption
static void AES_CFB_Encrypt(const BYTE *plaintext, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *ciphertext, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE currentIV[16];
    memcpy(currentIV, iv, 16);
    
    // Process full blocks
    size_t fullBlocks = dataSize / 16;
    for (size_t i = 0; i < fullBlocks; i++) {
        BYTE encryptedIV[16];
        
        // Encrypt IV
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR with plaintext
        for (int j = 0; j < 16; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ encryptedIV[j];
        }
        
        // Update IV for next block
        memcpy(currentIV, &ciphertext[i * 16], 16);
    }
    
    // Process partial block if any
    size_t remainingBytes = dataSize % 16;
    if (remainingBytes > 0) {
        BYTE encryptedIV[16];
        BYTE oldIV[16]; // Keep copy of current IV before processing
        
        // Save current IV (shift register) before processing
        memcpy(oldIV, currentIV, 16);
        
        // Encrypt IV for partial block
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR only remaining bytes
        for (size_t j = 0; j < remainingBytes; j++) {
            ciphertext[fullBlocks * 16 + j] = plaintext[fullBlocks * 16 + j] ^ encryptedIV[j];
        }
        
        // Update shift register: left_shift(oldSR, remainingBytes) || ciphertext_tail(remainingBytes)
        // Drop first remainingBytes bytes and append ciphertext tail
        memmove(currentIV, oldIV + remainingBytes, 16 - remainingBytes);
        memcpy(currentIV + (16 - remainingBytes), &ciphertext[fullBlocks * 16], remainingBytes);
    }
    
    // Copy final IV for output
    memcpy(ivOut, currentIV, 16);
}

// TPM 2.0 AES CFB Mode Decryption
static void AES_CFB_Decrypt(const BYTE *ciphertext, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *plaintext, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE currentIV[16];
    memcpy(currentIV, iv, 16);
    
    // Process full blocks
    size_t fullBlocks = dataSize / 16;
    for (size_t i = 0; i < fullBlocks; i++) {
        BYTE encryptedIV[16];
        
        // Encrypt IV
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR with ciphertext
        for (int j = 0; j < 16; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ encryptedIV[j];
        }
        
        // Update IV for next block
        memcpy(currentIV, &ciphertext[i * 16], 16);
    }
    
    // Process partial block if any
    size_t remainingBytes = dataSize % 16;
    if (remainingBytes > 0) {
        BYTE encryptedIV[16];
        BYTE oldIV[16]; // Keep copy of current IV before processing
        
        // Save current IV (shift register) before processing
        memcpy(oldIV, currentIV, 16);
        
        // Encrypt IV for partial block
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR only remaining bytes
        for (size_t j = 0; j < remainingBytes; j++) {
            plaintext[fullBlocks * 16 + j] = ciphertext[fullBlocks * 16 + j] ^ encryptedIV[j];
        }
        
        // Update shift register: left_shift(oldSR, remainingBytes) || ciphertext_tail(remainingBytes)
        // Drop first remainingBytes bytes and append ciphertext tail
        memmove(currentIV, oldIV + remainingBytes, 16 - remainingBytes);
        memcpy(currentIV + (16 - remainingBytes), &ciphertext[fullBlocks * 16], remainingBytes);
    }
    
    // Copy final IV for output
    memcpy(ivOut, currentIV, 16);
}

// TPM 2.0 AES OFB Mode (same for encryption and decryption)
static void AES_OFB_Process(const BYTE *input, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *output, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE currentIV[16];
    memcpy(currentIV, iv, 16);
    
    // Process full blocks
    size_t fullBlocks = dataSize / 16;
    for (size_t i = 0; i < fullBlocks; i++) {
        BYTE encryptedIV[16];
        
        // Encrypt IV
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR with input
        for (int j = 0; j < 16; j++) {
            output[i * 16 + j] = input[i * 16 + j] ^ encryptedIV[j];
        }
        
        // Update IV for next block
        memcpy(currentIV, encryptedIV, 16);
    }
    
    // Process partial block if any
    size_t remainingBytes = dataSize % 16;
    if (remainingBytes > 0) {
        BYTE encryptedIV[16];
        
        // Encrypt IV for partial block
        AES_EncryptBlock(currentIV, roundKeys, numRounds, encryptedIV);
        
        // XOR only remaining bytes
        for (size_t j = 0; j < remainingBytes; j++) {
            output[fullBlocks * 16 + j] = input[fullBlocks * 16 + j] ^ encryptedIV[j];
        }
        
        // Update IV for next operation
        memcpy(currentIV, encryptedIV, 16);
    }
    
    // Copy final IV for output
    memcpy(ivOut, currentIV, 16);
}

// TPM 2.0 AES CTR Mode (same for encryption and decryption)
static void AES_CTR_Process(const BYTE *input, size_t dataSize, const BYTE *key, UINT16 keySize, 
                           const BYTE *iv, BYTE *output, BYTE *ivOut) {
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    BYTE roundKeys[240];
    AES_KeyExpansion(key, keySize, roundKeys);
    
    BYTE counter[16];
    memcpy(counter, iv, 16);
    
    // Process full blocks
    size_t fullBlocks = dataSize / 16;
    for (size_t i = 0; i < fullBlocks; i++) {
        BYTE encryptedCounter[16];
        
        // Encrypt counter
        AES_EncryptBlock(counter, roundKeys, numRounds, encryptedCounter);
        
        // XOR with input
        for (int j = 0; j < 16; j++) {
            output[i * 16 + j] = input[i * 16 + j] ^ encryptedCounter[j];
        }
        
        // Increment counter (big-endian)
        for (int j = 15; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
    }
    
    // Process partial block if any
    size_t remainingBytes = dataSize % 16;
    if (remainingBytes > 0) {
        BYTE encryptedCounter[16];
        
        // Encrypt counter for partial block
        AES_EncryptBlock(counter, roundKeys, numRounds, encryptedCounter);
        
        // XOR only remaining bytes
        for (size_t j = 0; j < remainingBytes; j++) {
            output[fullBlocks * 16 + j] = input[fullBlocks * 16 + j] ^ encryptedCounter[j];
        }
        
        // Increment counter for next operation
        for (int j = 15; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
    }
    
    // Copy final counter for output
    memcpy(ivOut, counter, 16);
}



// TPM 2.0 AES Encryption (TPM 2.0 compliant)
static void CryptEncrypt(const BYTE *data, UINT16 dataSize, const BYTE *key, UINT16 keySize, BYTE *encrypted) {
    // Validate key size (AES-128, AES-192, AES-256)
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        qemu_log_mask(LOG_GUEST_ERROR, "CryptEncrypt: Invalid AES key size %u\n", keySize);
        return;
    }
    
    // Calculate number of rounds
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    
    // Expand key
    BYTE roundKeys[240]; // Max for AES-256 (15 rounds * 16 bytes)
    AES_KeyExpansion(key, keySize, roundKeys);
    
    // Pad data to 16-byte blocks
    BYTE paddedData[1024 + 16]; // Max buffer + padding
    UINT16 paddedSize = PKCS7_Pad(data, dataSize, paddedData);
    
    // Process blocks
    for (UINT16 i = 0; i < paddedSize; i += 16) {
        AES_EncryptBlock(&paddedData[i], roundKeys, numRounds, &encrypted[i]);
    }
}

// TPM 2.0 AES Decryption (TPM 2.0 compliant)
static void CryptDecrypt(const BYTE *encrypted, UINT16 dataSize, const BYTE *key, UINT16 keySize, BYTE *decrypted) {
    // Validate key size (AES-128, AES-192, AES-256)
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        qemu_log_mask(LOG_GUEST_ERROR, "CryptDecrypt: Invalid AES key size %u\n", keySize);
        return;
    }
    
    // Validate data size (must be multiple of 16)
    if (dataSize % 16 != 0) {
        qemu_log_mask(LOG_GUEST_ERROR, "CryptDecrypt: Invalid data size %u (must be multiple of 16)\n", dataSize);
        return;
    }
    
    // Calculate number of rounds
    UINT16 numRounds = (keySize == 16) ? 10 : (keySize == 24) ? 12 : 14;
    
    // Expand key
    BYTE roundKeys[240]; // Max for AES-256 (15 rounds * 16 bytes)
    AES_KeyExpansion(key, keySize, roundKeys);
    
    // Process blocks
    for (UINT16 i = 0; i < dataSize; i += 16) {
        AES_DecryptBlock(&encrypted[i], roundKeys, numRounds, &decrypted[i]);
    }
    
    // Remove PKCS#7 padding
    UINT16 unpaddedSize = PKCS7_Unpad(decrypted, dataSize, decrypted);
    if (unpaddedSize == 0) {
        qemu_log_mask(LOG_GUEST_ERROR, "CryptDecrypt: Invalid PKCS#7 padding\n");
        return;
    }
}

TPM_RC TPM2_Sign(Sign_In *in, Sign_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_Sign: Signing data with key\n");
    
    // Validate input
    if (in->keyHandle.keySize == 0 || in->data.dataSize == 0) {
        return TPM_RC_KEY;
    }
    
    // Generate signature
    CryptSignRSA_PSS_SHA256((const uint8_t *)in->data.data, (uint16_t)in->data.dataSize, (const uint8_t *)in->keyHandle.key, (uint16_t)in->keyHandle.keySize, (uint8_t *)out->signature.signature);
    out->signature.signatureSize = TPM_MAX_SIGNATURE_SIZE; // Fixed signature size
    
    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_VerifySignature(VerifySignature_In *in, VerifySignature_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_VerifySignature: Verifying signature\n");
    
    // Validate input
    if (in->keyHandle.keySize == 0 || in->data.dataSize == 0 || in->signature.signatureSize == 0) {
        return TPM_RC_SIGNATURE;
    }
    
    // Verify signature
    out->verification = CryptVerifySignatureRSA_PSS_SHA256((const uint8_t *)in->data.data, (uint16_t)in->data.dataSize, 
                                           (const uint8_t *)in->signature.signature, (uint16_t)in->signature.signatureSize,
                                           (const uint8_t *)in->keyHandle.key, (uint16_t)in->keyHandle.keySize);
    
    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_Hash(Hash_In *in, Hash_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_Hash: Computing hash of data\n");
    
    // Validate input
    if (in->data.dataSize == 0) {
        return TPM_RC_HASH;
    }
    
    // Run SHA-256 self-test on first call
    static int sha256_tested = 0;
    if (!sha256_tested) {
        test_sha256_implementation();
        sha256_tested = 1;
    }
    
    // Compute hash using full SHA-256 implementation
    SHA256_Calculate((const uint8_t *)in->data.data, (size_t)in->data.dataSize, (uint8_t *)out->digest.buffer);
    out->digest.size = SHA256_DIGEST_SIZE;
    
    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In *in, EncryptDecrypt2_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: %s, Algorithm=0x%04X, Mode=0x%04X\n", 
                  in->decrypt ? "Decrypt" : "Encrypt", in->symDef.algorithm, in->symDef.mode);
    
    // Validate input parameters
    if (in->keyHandle.keySize == 0) {
        return TPM_RC_KEY;
    }
    
    if (in->inData.bufferSize == 0) {
        return TPM_RC_VALUE;
    }
    
    // Validate algorithm support
    if (in->symDef.algorithm != TPM_ALG_AES) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Unsupported algorithm 0x%04X\n", in->symDef.algorithm);
        return TPM_RC_ALG;
    }
    
    // Validate mode support
    if (in->symDef.mode != TPM_ALG_ECB && in->symDef.mode != TPM_ALG_CBC && 
        in->symDef.mode != TPM_ALG_CFB && in->symDef.mode != TPM_ALG_OFB && 
        in->symDef.mode != TPM_ALG_CTR) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Unsupported mode 0x%04X\n", in->symDef.mode);
        return TPM_RC_MODE;
    }
    
    // Validate key size for AES
    if (in->keyHandle.keySize != 16 && in->keyHandle.keySize != 24 && in->keyHandle.keySize != 32) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Invalid AES key size %u\n", in->keyHandle.keySize);
        return TPM_RC_KEY;
    }
    
    // Validate data size (block-aligned only for ECB and CBC)
    if ((in->symDef.mode == TPM_ALG_ECB || in->symDef.mode == TPM_ALG_CBC) && 
        in->inData.bufferSize % 16 != 0) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Data size %u not block-aligned for mode 0x%04X\n", 
                      in->inData.bufferSize, in->symDef.mode);
        return TPM_RC_VALUE;
    }
    
    // Validate IV size for chaining modes
    if (in->symDef.mode != TPM_ALG_ECB && in->ivIn.ivSize != 16) {
        qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Invalid IV size %u for mode 0x%04X\n", 
                      in->ivIn.ivSize, in->symDef.mode);
        return TPM_RC_VALUE;
    }
    
    // Perform encryption/decryption based on mode and direction
    switch (in->symDef.mode) {
        case TPM_ALG_ECB:
            // Electronic Codebook mode (no IV needed)
            {
                // Expand key for ECB operations
                UINT16 numRounds = (in->keyHandle.keySize == 16) ? 10 : (in->keyHandle.keySize == 24) ? 12 : 14;
                BYTE roundKeys[240];
                AES_KeyExpansion(in->keyHandle.key, in->keyHandle.keySize, roundKeys);
                
                if (in->decrypt) {
                    // ECB Decryption
                    for (size_t i = 0; i < in->inData.bufferSize; i += 16) {
                        AES_DecryptBlock(&in->inData.buffer[i], roundKeys, numRounds, &out->outData.buffer[i]);
                    }
                } else {
                    // ECB Encryption
                    for (size_t i = 0; i < in->inData.bufferSize; i += 16) {
                        AES_EncryptBlock(&in->inData.buffer[i], roundKeys, numRounds, &out->outData.buffer[i]);
                    }
                }
                out->outData.bufferSize = in->inData.bufferSize;
                out->ivOut.ivSize = 0; // No IV for ECB
            }
            break;
            
        case TPM_ALG_CBC:
            if (in->decrypt) {
                // CBC Decryption
                AES_CBC_Decrypt(in->inData.buffer, in->inData.bufferSize, 
                              in->keyHandle.key, in->keyHandle.keySize,
                              in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            } else {
                // CBC Encryption
                AES_CBC_Encrypt(in->inData.buffer, in->inData.bufferSize, 
                              in->keyHandle.key, in->keyHandle.keySize,
                              in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            }
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_CFB:
            if (in->decrypt) {
                // CFB Decryption
                AES_CFB_Decrypt(in->inData.buffer, in->inData.bufferSize, 
                              in->keyHandle.key, in->keyHandle.keySize,
                              in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            } else {
                // CFB Encryption
                AES_CFB_Encrypt(in->inData.buffer, in->inData.bufferSize, 
                              in->keyHandle.key, in->keyHandle.keySize,
                              in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            }
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_OFB:
            // OFB is the same for encryption and decryption
            AES_OFB_Process(in->inData.buffer, in->inData.bufferSize, 
                          in->keyHandle.key, in->keyHandle.keySize,
                          in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_CTR:
            // CTR is the same for encryption and decryption
            AES_CTR_Process(in->inData.buffer, in->inData.bufferSize, 
                          in->keyHandle.key, in->keyHandle.keySize,
                          in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        default:
            return TPM_RC_VALUE;
    }
    
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_EncryptDecrypt2: Success, output size %u\n", out->outData.bufferSize);
    
    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In *in, RSA_Encrypt_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_RSA_Encrypt: RSA encryption\n");
    
    // Validate input
    if (in->keyHandle.keySize == 0 || in->data.dataSize == 0) {
        return TPM_RC_KEY;
    }
    
    // Simple RSA encryption simulation (XOR-based)
    CryptEncrypt((const uint8_t *)in->data.data, (uint16_t)in->data.dataSize, (const uint8_t *)in->keyHandle.key, (uint16_t)in->keyHandle.keySize, (uint8_t *)out->encrypted.data);
    out->encrypted.dataSize = in->data.dataSize;
    
    return TPM_RC_SUCCESS;
}

TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In *in, RSA_Decrypt_Out *out) {
    qemu_log_mask(LOG_GUEST_ERROR, "TPM2_RSA_Decrypt: RSA decryption\n");
    
    // Validate input
    if (in->keyHandle.keySize == 0 || in->encrypted.dataSize == 0) {
        return TPM_RC_KEY;
    }
    
    // Simple RSA decryption simulation (XOR-based)
    CryptDecrypt((const uint8_t *)in->encrypted.data, (uint16_t)in->encrypted.dataSize, (const uint8_t *)in->keyHandle.key, (uint16_t)in->keyHandle.keySize, (uint8_t *)out->decrypted.data);
    out->decrypted.dataSize = in->encrypted.dataSize;
    
    return TPM_RC_SUCCESS;
}

