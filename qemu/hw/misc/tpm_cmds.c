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
                if (in->decrypt) {
                    TPM_AES_ECB_Decrypt(in->inData.buffer, in->inData.bufferSize,
                                        in->keyHandle.key, in->keyHandle.keySize,
                                        out->outData.buffer);
                } else {
                    TPM_AES_ECB_Encrypt(in->inData.buffer, in->inData.bufferSize,
                                        in->keyHandle.key, in->keyHandle.keySize,
                                        out->outData.buffer);
                }
                out->outData.bufferSize = in->inData.bufferSize;
                out->ivOut.ivSize = 0; // No IV for ECB
            }
            break;
            
        case TPM_ALG_CBC:
            if (in->decrypt) {
                // CBC Decryption
                TPM_AES_CBC_Decrypt(in->inData.buffer, in->inData.bufferSize, 
                                    in->keyHandle.key, in->keyHandle.keySize,
                                    in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            } else {
                // CBC Encryption
                TPM_AES_CBC_Encrypt(in->inData.buffer, in->inData.bufferSize, 
                                    in->keyHandle.key, in->keyHandle.keySize,
                                    in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            }
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_CFB:
            if (in->decrypt) {
                // CFB Decryption
                TPM_AES_CFB_Decrypt(in->inData.buffer, in->inData.bufferSize, 
                                    in->keyHandle.key, in->keyHandle.keySize,
                                    in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            } else {
                // CFB Encryption
                TPM_AES_CFB_Encrypt(in->inData.buffer, in->inData.bufferSize, 
                                    in->keyHandle.key, in->keyHandle.keySize,
                                    in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            }
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_OFB:
            // OFB is the same for encryption and decryption
            TPM_AES_OFB_Process(in->inData.buffer, in->inData.bufferSize, 
                                in->keyHandle.key, in->keyHandle.keySize,
                                in->ivIn.iv, out->outData.buffer, out->ivOut.iv);
            out->outData.bufferSize = in->inData.bufferSize;
            out->ivOut.ivSize = 16;
            break;
            
        case TPM_ALG_CTR:
            // CTR is the same for encryption and decryption
            TPM_AES_CTR_Process(in->inData.buffer, in->inData.bufferSize, 
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

