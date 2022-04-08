#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cuda_runtime.h>

#include "aes.cuh"
#include "shared.cuh"
#include "keyExpansion.cuh"
#include "encryption.cuh"

__host__ int main()
{
    uint8_t *data;

    FILE *fp;
    fp = fopen("./in.bin", "rb");
    if (fp == NULL)
    {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 0L, SEEK_END);
    long dataLength = ftell(fp);

    rewind(fp);

    data = (uint8_t*)malloc(sizeof(uint8_t) * dataLength);

    fread(data, sizeof(uint8_t), dataLength, fp);

    fclose(fp);

    // Key
    enum KeySize keySize = AES128;

    uint8_t key[16] = { 0xbf, 0x02, 0xc4, 0xa0, 0x53, 0xef, 0x1b, 0x0b, 0x11, 0x15, 0x62, 0x0e, 0x39, 0x36, 0x30, 0x75 };

    // Output
    uint8_t *encryptedData;
    int encryptedLength;
    uint8_t *decryptedData;
    int decryptedLength;

    // Print out key
    //printf("Key:\t\t");
    //printLength(key, keySize / 8);

    // Print out plaintext
    //printf("Plaintext:\t");
    //printLength(data, dataLength);

    // Encrypt Data
    encrypt(data, dataLength, key, keySize, rand_uint64(), &encryptedData, &encryptedLength);

    // Print out encrypted data
    //printf("\nEncrypted:\t");
    //printLength(encryptedData, encryptedLength);

    // Decrypt Data
    decrypt(encryptedData, encryptedLength, key, keySize, &decryptedData, &decryptedLength);

    // Print out decrypted data
    //printf("\nPlaintext:\t");
    //printLength(decryptedData, decryptedLength);

    return 0;
}

__host__ void encrypt(uint8_t *data, int length, uint8_t *key, enum KeySize keySize, uint64_t nonce, uint8_t **encryptedData, int *paddedLength)
{
    
    // Pad data (with 0) to a 16 byte divisble length
    ePadBytes(data, length, encryptedData, paddedLength);

    // Get nonce and prepend it to encrypted data
    for (int i = 0; i < 8; i++) 
    {
        (*encryptedData)[i] = ((uint8_t*)&nonce)[i];
    }

    // Expand key
    uint32_t *expandedKey;
    keyExpansion(keySize, key, &expandedKey);

    // Copy data to gpu
    uint8_t *d_encryptedData;
    cudaMalloc(&d_encryptedData, *paddedLength);
    cudaMemcpy(d_encryptedData, *encryptedData, *paddedLength, cudaMemcpyHostToDevice);

    // Copy expanded key to gpu
    int rounds;

    switch (keySize)
    {
    case AES128:
        rounds = 10;
        break;
    case AES192:
        rounds = 12;
        break;
    case AES256:
        rounds = 14;
        break;
    }
    uint32_t *d_expandedKey;
    cudaMalloc(&d_expandedKey, sizeof(uint32_t) * (rounds + 1) * 4);
    cudaMemcpy(d_expandedKey, expandedKey, sizeof(uint32_t) * (rounds + 1) * 4, cudaMemcpyHostToDevice);
    
    //for (int chunk = 0; chunk < ((paddedLength - 8) / 16); chunk++)
    int blocks = ((*paddedLength - 8) / 16) / 512 + 1;
    int threads = 512;

    gpu_encrypt<<<blocks, threads>>>(d_encryptedData, nonce, d_expandedKey, *paddedLength, keySize);

    // Copy data back to host
    cudaError_t cerror = cudaMemcpy(*encryptedData, d_encryptedData, *paddedLength, cudaMemcpyDeviceToHost);

    if (cerror != cudaSuccess) {
        printf("Cuda error: %d\n", cerror);
    }

    // Free
    cudaFree(d_encryptedData);
    cudaFree(d_expandedKey);
}

__global__ void gpu_encrypt(uint8_t *encryptedData, uint64_t nonce, uint32_t *expandedKey, int paddedLength, enum KeySize keySize)
{
    int chunk = blockIdx.x * blockDim.x + threadIdx.x;

    if (chunk < ((paddedLength - 8) / 16)) {

        // Build state array and get pointer to it
        StateArray sA;
        sA.nonce = nonce;
        sA.counter = chunk;
        uint8_t* stateArray = (uint8_t*)&sA;

        encryptState(stateArray, expandedKey, keySize);

        // Get a pointer to the current part of the plain text
        uint8_t *plaintext = (encryptedData) + (chunk * 16) + 8;

        // XOR with stateArray
        for (int i = 0; i < 16; i++)
        {
            plaintext[i] ^= stateArray[i];
        }

    }
}

__host__ void decrypt(uint8_t *data, int length, uint8_t *key, enum KeySize keySize, uint8_t **decryptedData, int *paddedLength)
{
    // Pad data (with 0) to a 16 byte divisble length
    dPadBytes(data, length, decryptedData, paddedLength);

    // Gather nonce
    uint64_t nonce;
    for (int i = 0; i < 8; i++)
    {
        ((uint8_t*)&nonce)[i] = data[i];
    }

    // Expand key
    uint32_t *expandedKey;
    keyExpansion(keySize, key, &expandedKey);

    // Copy data to gpu
    uint8_t *d_decryptedData;
    cudaMalloc((void**) &d_decryptedData, *paddedLength);
    cudaMemcpy((void*) d_decryptedData, *decryptedData, *paddedLength, cudaMemcpyHostToDevice);

    // Copy expanded key to gpu
    int rounds;

    switch (keySize)
    {
    case AES128:
        rounds = 10;
        break;
    case AES192:
        rounds = 12;
        break;
    case AES256:
        rounds = 14;
        break;
    }
    uint32_t *d_expandedKey;
    cudaMalloc((void**) &d_expandedKey, sizeof(uint32_t) * (rounds + 1) * 4);
    cudaMemcpy((void*) d_expandedKey, expandedKey, sizeof(uint32_t) * (rounds + 1) * 4, cudaMemcpyHostToDevice);
    
    // for (int chunk = 0; chunk < (paddedLength / 16); chunk++)
    int blocks = (*paddedLength / 16) / 512 + 1;
    int threads = 512;

    gpu_decrypt<<<blocks, threads>>>(d_decryptedData, nonce, d_expandedKey, *paddedLength, keySize);
    cudaDeviceSynchronize();
    // Copy data back to host
    cudaMemcpy((void**) *decryptedData, d_decryptedData, *paddedLength, cudaMemcpyDeviceToHost);

    // Free
    cudaFree(d_decryptedData);
    cudaFree(d_expandedKey);
}

__global__ void gpu_decrypt(uint8_t *decryptedData, uint64_t nonce, uint32_t *expandedKey, int paddedLength, enum KeySize keySize)
{
    int chunk = blockIdx.x * blockDim.x + threadIdx.x;

    if (chunk < (paddedLength / 16)) 
    {
        // Build state array and get pointer to it
        StateArray sA;
        sA.nonce = nonce;
        sA.counter = chunk;
        uint8_t* stateArray = (uint8_t*)&sA;

        encryptState(stateArray, expandedKey, keySize);

        // Get a pointer to the current part of the encrypted text
        uint8_t *encrypted = (decryptedData) + chunk * 16;

        if (DEBUG)  
        {
            printf("\n\tEncrypted:\t");
            printLength(encrypted, 16);
        }

        // XOR with stateArray
        for (int i = 0; i < 16; i++)
        {
            encrypted[i] ^= stateArray[i];
        }

        if (DEBUG)  
        {
            printf("\tEncrypted:\t");
            printLength(encrypted, 16);
            printf("\n");
        }
    }
}

__host__ void ePadBytes(uint8_t *bytes, int length, uint8_t **paddedBytes, int *paddedLength)
{
    *paddedLength = length;

    // Pad data out to 128 bit chunks
    if (*paddedLength % 16 != 0)
    {
        // If not already divisable by 16 then add an additional chunk
        *paddedLength = ((*paddedLength / 16) + 1) * 16;
    }

    // Add 64 bits for nonce at beginning
    *paddedLength += 8;

    // Move bytes into padded byte buffer
    *paddedBytes = (uint8_t *)malloc(sizeof(uint8_t) * *paddedLength);
    for (int i = 0; i < length; i++)
    {
        (*paddedBytes)[i + 8] = ((uint8_t *)bytes)[i];
    }

    // Assure 0's for padded data
    for (int i = length + 8; i < *paddedLength; i++)
    {
        (*paddedBytes)[i] = '\0';
    }
}

__host__ void dPadBytes(uint8_t *bytes, int length, uint8_t **paddedBytes, int *paddedLength)
{
    *paddedLength = length - 8;

    // Pad data out to 128 bit chunks
    if (*paddedLength % 16 != 0)
    {
        // If not already divisable by 16 then add an additional chunk
        *paddedLength = ((*paddedLength / 16) + 1) * 16;
    }

    // Move bytes into padded byte buffer
    *paddedBytes = (uint8_t *)malloc(sizeof(uint8_t) * *paddedLength);
    for (int i = 0; i < length; i++)
    {
        (*paddedBytes)[i] = ((uint8_t *)bytes)[i + 8];
    }

    // Assure 0's for padded data
    for (int i = length + 8; i < *paddedLength; i++)
    {
        (*paddedBytes)[i] = '\0';
    }
}

__device__ void encryptState(uint8_t* stateArray, uint32_t* expandedKey, enum KeySize keySize) {
    // XOR with first 4 words of key expansion
    addRoundKey(stateArray, 0, expandedKey);
    if (DEBUG)
    {
        printf("\nRound 0:\n\tAddRKey:\t");
        printLength(stateArray, 16);
    }

    // Loop through rounds
    int rounds;
    switch (keySize)
    {
    case AES128:
        rounds = 10;
        break;
    case AES192:
        rounds = 12;
        break;
    case AES256:
        rounds = 14;
        break;
    }

    for (int round = 1; round <= rounds; round++)
    {
        if (DEBUG)
        {
            printf("\nRound %d:\n", round);
        }

        // Substitute bytes
        subBytes(stateArray);
        if (DEBUG)
        {
            printf("\tSubBytes:\t");
            printLength(stateArray, 16);
        }

        // Shift rows
        shiftRows(stateArray);
        if (DEBUG)
        {
            printf("\tShiftRows:\t");
            printLength(stateArray, 16);
        }

        // Mix columns (not on last round)
        if (round != rounds)
        {
            for (int column = 0; column < 4; column++)
            {
                mixColumns(&(stateArray[index(column, 0)]));
            }
        }
        if (DEBUG)
        {
            printf("\tMixCols:\t");
            printLength(stateArray, 16);
        }

        // Add round key
        addRoundKey(stateArray, round, expandedKey);
        if (DEBUG)
        {
            printf("\tAddRKey:\t");
            printLength(stateArray, 16);
        }
    }
}

__device__ void mixColumns(uint8_t *r)
{
    int a[4];
    for (uint8_t c = 0; c < 4; c++)
    {
        a[c] = r[c];
    }
    r[0] = mb02[a[0]] ^ mb03[a[1]] ^      a[2]  ^       a[3] ;
    r[1] =      a[0]  ^ mb02[a[1]] ^ mb03[a[2]] ^       a[3] ;
    r[2] =      a[0]  ^      a[1]  ^ mb02[a[2]] ^  mb03[a[3]];
    r[3] = mb03[a[0]] ^      a[1]  ^      a[2]  ^  mb02[a[3]];
}

__device__ void shiftRows(uint8_t *stateArray)
{
    uint8_t t0;
    uint8_t t1;
    // Row 0 no change
    // Row 1 rotate 1 left
    t0 = stateArray[index(0, 1)];
    stateArray[index(0, 1)] = stateArray[index(1, 1)];
    stateArray[index(1, 1)] = stateArray[index(2, 1)];
    stateArray[index(2, 1)] = stateArray[index(3, 1)];
    stateArray[index(3, 1)] = t0;
    // Row 2 rotate 2
    t0 = stateArray[index(0, 2)];
    stateArray[index(0, 2)] = stateArray[index(2, 2)];
    t1 = stateArray[index(1, 2)];
    stateArray[index(1, 2)] = stateArray[index(3, 2)];
    stateArray[index(2, 2)] = t0;
    stateArray[index(3, 2)] = t1;
    // Row 3 rotate 1 right
    t0 = stateArray[index(3, 3)];
    stateArray[index(3, 3)] = stateArray[index(2, 3)];
    stateArray[index(2, 3)] = stateArray[index(1, 3)];
    stateArray[index(1, 3)] = stateArray[index(0, 3)];
    stateArray[index(0, 3)] = t0;
}

__device__ void subBytes(uint8_t *stateArray)
{
    for (int i = 0; i < 16; i++)
    {
        stateArray[i] = d_sbox[stateArray[i]];
    }
}

__device__ void addRoundKey(uint8_t *stateArray, int round, uint32_t *expandedKey)
{
    for (int column = 0; column < 4; column++)
    {
        for (int row = 0; row < 4; row++)
        {
            stateArray[index(column, row)] ^= (uint8_t)(expandedKey[column + (round * 4)] >> (24 - (8 * row)));
        }
    }
}

__host__ void keyExpansion(enum KeySize keySize, uint8_t *key, uint32_t **expansion)
{
    int rounds;

    switch (keySize)
    {
    case AES128:
        rounds = 10;
        break;
    case AES192:
        rounds = 12;
        break;
    case AES256:
        rounds = 14;
        break;
    }

    *expansion = (uint32_t *)malloc(sizeof(uint32_t) * (rounds + 1) * 4);

    uint32_t rcon[] = {0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                       0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};

    // Set beginning of expansion as the key
    for (int i = 0; i < (keySize / 32); i++)
    {
        (*expansion)[i] = ((key[(i * 4) + 0] << 24) & (0xFF << 24)) | ((key[(i * 4) + 1] << 16) & (0xFF << 16)) |
                          ((key[(i * 4) + 2] << 8) & (0xFF << 8)) | (key[(i * 4) + 3] & 0xFF);
    }

    // Get other round keys
    for (int i = (keySize / 32); i < ((rounds + 1) * 4); i++)
    {
        uint32_t temp = (*expansion)[i - 1];

        if (i % (keySize / 32) == 0)
        {
            // RotWord
            temp = ((temp << 8) & 0xFFFFFF00) | ((temp >> 24) & 0xFF);

            // SubWord
            uint8_t b0 = sbox[(temp >> 24) & 0xFF];
            uint8_t b1 = sbox[(temp >> 16) & 0xFF];
            uint8_t b2 = sbox[(temp >> 8) & 0xFF];
            uint8_t b3 = sbox[(temp >> 0) & 0xFF];

            temp = ((b0 << 24) & (0xFF << 24)) | ((b1 << 16) & (0xFF << 16)) | ((b2 << 8) & (0xFF << 8)) | (b3 & 0xFF);

            // Rcon
            temp = temp ^ rcon[i / (keySize / 32)];
        }

        (*expansion)[i] = temp ^ (*expansion)[i - (keySize / 32)];
    }
}

#define ROTL8(x, shift) ((uint8_t)((x) << (shift)) | ((x) >> (8 - (shift))))

__host__ __device__ void printLength(uint8_t *data, int length)
{
    printf("%02d Bytes: ", length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x ", (int)((uint8_t *)data)[i]);
    }
    printf("\n");
}

#if RAND_MAX/256 >= 0xFFFFFFFFFFFFFF
  #define LOOP_COUNT 1
#elif RAND_MAX/256 >= 0xFFFFFF
  #define LOOP_COUNT 2
#elif RAND_MAX/256 >= 0x3FFFF
  #define LOOP_COUNT 3
#elif RAND_MAX/256 >= 0x1FF
  #define LOOP_COUNT 4
#else
  #define LOOP_COUNT 5
#endif

__host__ uint64_t rand_uint64(void) {
    time_t t;
    srand((unsigned) time(&t));
    uint64_t r = 0;
    for (int i=LOOP_COUNT; i > 0; i--) {
        r = r*(RAND_MAX + (uint64_t)1) + rand();
    }
    return r;
}