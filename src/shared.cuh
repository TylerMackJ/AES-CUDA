#ifndef shared
#define shared

#define DEBUG 0

#include <stdint.h>
#include <cuda_runtime.h>

#define index(x, y) ((x * 4) + y)

typedef struct StateArray {
    uint64_t nonce;
    uint64_t counter;
} StateArray;


/* REQUIRES SBOX FOR 256 https://samiam.org/key-schedule.html */
enum KeySize
{
    AES128 = 128,
    AES192 = 192,
    AES256 = 256
};

__host__ __device__ void printLength(uint8_t *data, int length);

// https://stackoverflow.com/questions/33010010/how-to-generate-random-64-bit-unsigned-integer-in-c
__host__ uint64_t rand_uint64(void);

#endif