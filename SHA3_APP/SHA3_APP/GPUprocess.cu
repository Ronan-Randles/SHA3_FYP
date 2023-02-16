/*******************************************************
* Author R.Conway                                       *
*                                                       *
* Description: Use CUDA to convery a 2D array of RGB    *
*              pixels to a 2D array of grayscale pixels *
*                                                       *
********************************************************/
#include <cuda.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include <helper_cuda.h>

//#include "GPUProcess.h"


/**
  * Function to compute the Keccak[r, c] sponge function over a given input.
  * @param  rate            The value of the rate r.
  * @param  capacity        The value of the capacity c.
  * @param  input           Pointer to the input message.
  * @param  inputByteLen    The number of input bytes provided in the input message.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         These <i>n</i> bits must be in the least significant bit positions
  *                         and must be delimited with a bit 1 at position <i>n</i>
  *                         (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                         from position <i>n</i>+1 to position 7.
  *                         Some examples:
  *                             - If no bits are to be appended, then @a delimitedSuffix must be 0x01.
  *                             - If the 2-bit sequence 0,1 is to be appended (as for SHA3-*), @a delimitedSuffix must be 0x06.
  *                             - If the 4-bit sequence 1,1,1,1 is to be appended (as for SHAKE*), @a delimitedSuffix must be 0x1F.
  *                             - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedSuffix must be 0x8B.
  * @param  output          Pointer to the buffer where to store the output.
  * @param  outputByteLen   The number of output bytes desired.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  */
__global__ void Keccak_gpu(unsigned int rate, unsigned int capacity, uint64_t* input, int n_inputs);

typedef uint64_t tKeccakLane;

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))
#define Keccak_Rounds 24
#define uint_row_size 25*sizeof(uint64_t)
#define SHA3_CONST(x) x##L
enum last_permutation { Theta, Rho_PI, Chi, Iota };
char* perm_strings[4] = {(char *)"Theta", (char *)"Rho_PI", (char *)"Chi", (char *)"Iota" };
enum last_permutation last_perm;

// Works for Little Endian system, more needed to support Big Endian
#define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
#define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
#define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)



//void VerifyGPUOperation();

void GPUProcessing(uint64_t* input, int num_inputs)
{
    uint64_t* d_state_in;
    uint64_t* state_out;
    cudaEvent_t start, stop;
    float time;
    int state_size_bytes = 8 * num_inputs * uint_row_size;

    dim3 dimGrid(ceil(num_inputs / 16.0), 1, 1);
    dim3 dimBlock(16, 16, 1);

    /* Allocate device memory */
    checkCudaErrors(cudaMalloc((void**)&d_state_in, state_size_bytes));

    /* Allocate host memory for state_out */
    state_out = (uint64_t*)malloc(state_size_bytes);

    /* Initialise device memory */
    checkCudaErrors(cudaMemcpy(d_state_in, state_out, state_size_bytes, cudaMemcpyHostToDevice));

    /* Create timing events*/
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    cudaEventRecord(start, 0);

    /* Launch CUDA GPU kernels */
    Keccak_gpu <<<dimGrid, dimBlock >> > (256, 1344, d_state_in, num_inputs);
    printf("State out[0]: %.16llx", state_out[0]);

    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);

    cudaEventElapsedTime(&time, start, stop);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    printf("\nTime for kernel execution is %3.2f ms\n", time);

    /* Copy from device back to host */
    checkCudaErrors(cudaMemcpy(input, d_state_in, state_size_bytes, cudaMemcpyDeviceToHost));

    /* Verify correct operation */
    // Ommitted here ...

    /* Free allocated memory on both device and host */
    checkCudaErrors(cudaFree(d_state_in));
    printf(" Hashing complete \n");
}

__device__ static void print_state(uint64_t state[25], int round) {
    int x, y;
    printf("%s round %i\n", perm_strings[last_perm], round);
    //print in format of sha3 example pdf
    for (int p = 0; p < 5; p++) {
        for (int l = 0; l < 5; l++) {
            printf("[%i,%i]: %.16lx ", l, p, readLane(l, p));
            if (((p * 5 + l) % 2) == 1)
                printf("\n");
        }
    }
    printf("\n");
}


__device__ void KeccakF1600(void* state)
{
    unsigned int round, x, y, j, t;

    static const uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
    };

    // uint8_t LFSRstate = 0x01;
    //print_state(state,0);
    for (round = 0; round < 25; round++)
    {
        //print_state(state, round);
        //Theta step
        {
            tKeccakLane C[5], D;

            for (x = 0; x < 5; x++)
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            for (x = 0; x < 5; x++) {
                D = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
                for (y = 0; y < 5; y++)
                    XORLane(x, y, D);
            }
            //last_perm = Theta;
            //print_state(state, round);
        }
        //Rho and Pi step
        {
            tKeccakLane current, tmp;

            //Start at (x,y) = (1,0)
            x = 1;
            y = 0;
            current = readLane(x, y);

            for (t = 0; t < 24; t++) {
                unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
                unsigned int Y = (2 * x + 3 * y) % 5;
                x = y;
                y = Y;
                tmp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = tmp;
            }
            //last_perm = Rho_PI;
            //print_state(state, round);
        }
        //Chi step
        {
            tKeccakLane temp[5];
            for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++)
                    temp[x] = readLane(x, y);
                for (x = 0; x < 5; x++)
                    writeLane(x, y, temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]));
            }
            //last_perm = Chi;
            //print_state(state, round);
        }

        //Iota step
        {
            XORLane(0, 0, keccakf_rndc[round]);
            //last_perm = Iota;
            //print_state(state, round);
        }

    }

}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAXSTRLEN sizeof("0xa3a3a3a3a3a3a3a3")

__global__ void Keccak_gpu(unsigned int rate, unsigned int capacity, uint64_t* input, int n_inputs)
{
    int c = blockIdx.x * blockDim.x + threadIdx.x;

    //Ensure rate and capacity sum to 1600 for keccakF1600
    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;
    
    if (c < n_inputs) {     
        KeccakF1600(&input[c]);
    }
}
