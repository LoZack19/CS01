#include "include/hw/misc/s32k358_tpm.h"

UINT16 read_be16(Fifo8 *fifo) {
    return ((UINT16)fifo8_pop(fifo) << 8) | (UINT16)fifo8_pop(fifo);
}

UINT32 read_be32(Fifo8 *fifo) {
    return ((UINT32)fifo8_pop(fifo) << 24) |
           ((UINT32)fifo8_pop(fifo) << 16) |
           ((UINT32)fifo8_pop(fifo) << 8)  |
            (UINT32)fifo8_pop(fifo);
}

void write_be16(Fifo8 *fifo, UINT16 value) {
    fifo8_push(fifo, (value >> 8) & 0xFF);
    fifo8_push(fifo, value & 0xFF);
}

void write_be32(Fifo8 *fifo, UINT32 value) {
    fifo8_push(fifo, (value >> 24) & 0xFF);
    fifo8_push(fifo, (value >> 16) & 0xFF);
    fifo8_push(fifo, (value >> 8) & 0xFF);
    fifo8_push(fifo, value & 0xFF);
}

// Unmarshal a command header from the FIFO
void tpm_cmd_header_unmarshal(Fifo8 *fifo, tpm_cmd_header_t *header) {
    header->tag = read_be16(fifo);
    header->commandSize = read_be32(fifo);
    header->commandCode = read_be32(fifo);
}

// Marshal a response header to the FIFO
void tpm_rsp_header_marshal(Fifo8 *fifo, const tpm_rsp_header_t *header) {
    write_be16(fifo, header->tag);
    write_be32(fifo, header->responseSize);
    write_be32(fifo, header->responseCode);
}

// Unmarshal a GetRandom input structure from the FIFO
void get_random_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    GetRandom_In *get_random_in = (GetRandom_In *)in;
    get_random_in->bytesRequested = read_be16(fifo);
}

// Marshal a GetRandom output structure to the FIFO
void get_random_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const GetRandom_Out *get_random_out = (const GetRandom_Out *)out;
    write_be16(fifo, get_random_out->randomBytes.size);
    for (UINT16 i = 0; i < get_random_out->randomBytes.size; i++) {
        fifo8_push(fifo, get_random_out->randomBytes.buffer[i]);
    }
}

// Cryptographic operation marshaling functions

// Sign command marshaling
void sign_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    Sign_In *sign_in = (Sign_In *)in;
    
    // Unmarshal key handle
    sign_in->keyHandle.keySize = read_be16(fifo);
    for (UINT16 i = 0; i < sign_in->keyHandle.keySize && i < 256; i++) {
        sign_in->keyHandle.key[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal data
    sign_in->data.dataSize = read_be16(fifo);
    for (UINT16 i = 0; i < sign_in->data.dataSize && i < 256; i++) {
        sign_in->data.data[i] = fifo8_pop(fifo);
    }
}

void sign_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const Sign_Out *sign_out = (const Sign_Out *)out;
    
    // Marshal signature
    write_be16(fifo, sign_out->signature.signatureSize);
    for (UINT16 i = 0; i < sign_out->signature.signatureSize && i < 256; i++) {
        fifo8_push(fifo, sign_out->signature.signature[i]);
    }
}

// VerifySignature command marshaling
void verify_signature_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    VerifySignature_In *verify_in = (VerifySignature_In *)in;
    
    // Unmarshal key handle
    verify_in->keyHandle.keySize = read_be16(fifo);
    for (UINT16 i = 0; i < verify_in->keyHandle.keySize && i < 256; i++) {
        verify_in->keyHandle.key[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal data
    verify_in->data.dataSize = read_be16(fifo);
    for (UINT16 i = 0; i < verify_in->data.dataSize && i < 256; i++) {
        verify_in->data.data[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal signature
    verify_in->signature.signatureSize = read_be16(fifo);
    for (UINT16 i = 0; i < verify_in->signature.signatureSize && i < 256; i++) {
        verify_in->signature.signature[i] = fifo8_pop(fifo);
    }
}

void verify_signature_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const VerifySignature_Out *verify_out = (const VerifySignature_Out *)out;
    fifo8_push(fifo, verify_out->verification);
}

// Hash command marshaling
void hash_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    Hash_In *hash_in = (Hash_In *)in;
    
    // Unmarshal data
    hash_in->data.dataSize = read_be16(fifo);
    for (UINT16 i = 0; i < hash_in->data.dataSize && i < 256; i++) {
        hash_in->data.data[i] = fifo8_pop(fifo);
    }
}

void hash_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const Hash_Out *hash_out = (const Hash_Out *)out;
    
    // Marshal digest
    write_be16(fifo, hash_out->digest.size);
    for (UINT16 i = 0; i < hash_out->digest.size && i < SHA256_DIGEST_SIZE; i++) {
        fifo8_push(fifo, hash_out->digest.buffer[i]);
    }
}

// EncryptDecrypt2 command marshaling (TPM 2.0 compliant)
void encrypt_decrypt2_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    EncryptDecrypt2_In *encrypt_in = (EncryptDecrypt2_In *)in;
    
    // Unmarshal key handle
    encrypt_in->keyHandle.keySize = read_be16(fifo);
    for (UINT16 i = 0; i < encrypt_in->keyHandle.keySize && i < 256; i++) {
        encrypt_in->keyHandle.key[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal decrypt flag
    encrypt_in->decrypt = fifo8_pop(fifo);
    
    // Unmarshal symmetric definition
    encrypt_in->symDef.algorithm = read_be16(fifo);
    encrypt_in->symDef.mode = read_be16(fifo);
    encrypt_in->symDef.keyBits = read_be16(fifo);
    
    // Unmarshal input IV
    encrypt_in->ivIn.ivSize = read_be16(fifo);
    for (UINT16 i = 0; i < encrypt_in->ivIn.ivSize && i < 16; i++) {
        encrypt_in->ivIn.iv[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal input data
    encrypt_in->inData.bufferSize = read_be16(fifo);
    for (UINT16 i = 0; i < encrypt_in->inData.bufferSize && i < 1024; i++) {
        encrypt_in->inData.buffer[i] = fifo8_pop(fifo);
    }
}

void encrypt_decrypt2_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const EncryptDecrypt2_Out *encrypt_out = (const EncryptDecrypt2_Out *)out;
    
    // Marshal output data
    write_be16(fifo, encrypt_out->outData.bufferSize);
    for (UINT16 i = 0; i < encrypt_out->outData.bufferSize && i < 1024; i++) {
        fifo8_push(fifo, encrypt_out->outData.buffer[i]);
    }
    
    // Marshal output IV
    write_be16(fifo, encrypt_out->ivOut.ivSize);
    for (UINT16 i = 0; i < encrypt_out->ivOut.ivSize && i < 16; i++) {
        fifo8_push(fifo, encrypt_out->ivOut.iv[i]);
    }
}

// RSA Encrypt command marshaling
void rsa_encrypt_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    RSA_Encrypt_In *rsa_encrypt_in = (RSA_Encrypt_In *)in;
    
    // Unmarshal key handle
    rsa_encrypt_in->keyHandle.keySize = read_be16(fifo);
    for (UINT16 i = 0; i < rsa_encrypt_in->keyHandle.keySize && i < 256; i++) {
        rsa_encrypt_in->keyHandle.key[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal data
    rsa_encrypt_in->data.dataSize = read_be16(fifo);
    for (UINT16 i = 0; i < rsa_encrypt_in->data.dataSize && i < 256; i++) {
        rsa_encrypt_in->data.data[i] = fifo8_pop(fifo);
    }
}

void rsa_encrypt_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const RSA_Encrypt_Out *rsa_encrypt_out = (const RSA_Encrypt_Out *)out;
    
    // Marshal encrypted data
    write_be16(fifo, rsa_encrypt_out->encrypted.dataSize);
    for (UINT16 i = 0; i < rsa_encrypt_out->encrypted.dataSize && i < 256; i++) {
        fifo8_push(fifo, rsa_encrypt_out->encrypted.data[i]);
    }
}

// RSA Decrypt command marshaling
void rsa_decrypt_in_unmarshal(Fifo8 *fifo, uint8_t *in) {
    RSA_Decrypt_In *rsa_decrypt_in = (RSA_Decrypt_In *)in;
    
    // Unmarshal key handle
    rsa_decrypt_in->keyHandle.keySize = read_be16(fifo);
    for (UINT16 i = 0; i < rsa_decrypt_in->keyHandle.keySize && i < 256; i++) {
        rsa_decrypt_in->keyHandle.key[i] = fifo8_pop(fifo);
    }
    
    // Unmarshal encrypted data
    rsa_decrypt_in->encrypted.dataSize = read_be16(fifo);
    for (UINT16 i = 0; i < rsa_decrypt_in->encrypted.dataSize && i < 256; i++) {
        rsa_decrypt_in->encrypted.data[i] = fifo8_pop(fifo);
    }
}

void rsa_decrypt_out_marshal(Fifo8 *fifo, const uint8_t *out) {
    const RSA_Decrypt_Out *rsa_decrypt_out = (const RSA_Decrypt_Out *)out;
    
    // Marshal decrypted data
    write_be16(fifo, rsa_decrypt_out->decrypted.dataSize);
    for (UINT16 i = 0; i < rsa_decrypt_out->decrypted.dataSize && i < 256; i++) {
        fifo8_push(fifo, rsa_decrypt_out->decrypted.data[i]);
    }
}