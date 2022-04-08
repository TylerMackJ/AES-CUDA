#ifndef aes
#define aes

#include <stdint.h>
#include <cuda_runtime.h>

#include "shared.cuh"

__host__ void encrypt(uint8_t *data, int length, uint8_t *key, enum KeySize keySize, uint64_t nonce, uint8_t **encryptedData, int *paddedLength);

__global__ void gpu_encrypt(uint8_t *encryptedData, uint64_t nonce, uint32_t *expandedKey, int paddedLength, enum KeySize keySize);

__host__ void decrypt(uint8_t *data, int length, uint8_t *key, enum KeySize keySize, uint8_t **decryptedData, int *paddedLength);

__global__ void gpu_decrypt(uint8_t *decryptedData, uint64_t nonce, uint32_t *expandedKey, int paddedLength, enum KeySize keySize);

__host__ void ePadBytes(uint8_t *bytes, int length, uint8_t **paddedBytes, int *paddedLength);

__host__ void dPadBytes(uint8_t *bytes, int length, uint8_t **paddedBytes, int *paddedLength);

#endif