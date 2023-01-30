/**
 * Written by Ronan Randles
 * Student number: 19242441
 * 
 * Reference material used:
 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
 */

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
void Keccak(unsigned int rate, unsigned int capacity, unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint64_t tKeccakLane;

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))
#define Keccak_Rounds 24
#define SHA3_CONST(x) x##L
enum last_permutation {Theta, Rho_PI, Chi, Iota};
char * perm_strings [4] = {"Theta", "Rho_PI", "Chi", "Iota"};
enum last_permutation last_perm;

// Works for Little Endian system, more needed to support Big Endian
#define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
#define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
#define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)


//Sample input essentially skips data absorbtion phase. TODO: Replace with propper implimentation
uint64_t sample_input[25] =     {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3,
                                 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3,
                                 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3,
                                 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0, 0x0, 0x0,
                                 0x0, 0x0, 0x0, 0x0, 0x0};

unsigned char *sample_input_2 = "0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0xa3a3a3a3a3a3a3a3,0x0000000000000000,0x0,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000";

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

static void print_state(uint64_t state[25], int round){
    int x, y;
    printf("%s round %i\n", perm_strings[last_perm], round);
    //print in format of sha3 example pdf
    for (int p = 0; p < 5; p++) {
        for (int l = 0; l < 5; l++) {
            printf("[%i,%i]: %.16lx ", l, p, readLane(l,p));
            if (((p * 5 + l) % 2) == 1)
                printf("\n");
        }
    }
    printf("\n");
}

void KeccakF1600(void *state)
{
    unsigned int round, x, y, j, t;
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
                D = C[(x + 4) % 5] ^ ROL64(C[(x+1) % 5], 1);
                for (y = 0; y < 5; y++)
                    XORLane(x, y, D);
            } 
            last_perm = Theta;
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
            last_perm = Rho_PI;
            //print_state(state, round);
        }
        //Chi step
        {
            tKeccakLane temp[5];
            for (y = 0; y < 5; y++){
                for(x = 0; x < 5; x++)
                    temp[x] = readLane(x, y);
                for(x = 0; x < 5; x++)
                    writeLane(x, y, temp[x] ^ ((~ temp[(x + 1) % 5]) & temp[(x + 2) % 5]));
            }
            last_perm = Chi;
            //print_state(state, round);
        }
        
        //Iota step
        {
            // for (j = 0; j < 7; j++) {
            //     unsigned int bitPosition = (1 << j) - 1; /* (2^j)-1 */   
                   
            //     if (LFSR86540(&LFSRstate)) {
            //         XORLane(0, 0, (tKeccakLane)1 << bitPosition);
            //     }
            // }
            XORLane(0,0,keccakf_rndc[round]);
            last_perm = Iota;
            //print_state(state, round);
        }
        
    }
    
}

#include <string.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAXSTRLEN sizeof("0xa3a3a3a3a3a3a3a3")

void Keccak(unsigned int rate, unsigned int capacity, unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
{
    uint64_t state[25];
    unsigned int rateInBytes = rate/8;
    unsigned int blockSize = 0;
    unsigned int i;
    unsigned char *ptr;
    char *new_ptr;
    char *remaining;
    unsigned char *prev_ptr;
    int individual_length;
    char *temp = malloc(MAXSTRLEN);
    //printf("INPUT: [%s]\n", input);
    memset(state, 0, sizeof(state));
    // //Absorb input blocks from sting using parsing
    ptr = strchr(input,',');
    individual_length = (unsigned char *)ptr - input;
    memcpy(temp, input, individual_length);
    for (int i = 0; i < sizeof(state)/8; i++){
        state[i] = strtoul(temp,&remaining,16);

        if (!ptr)
            break;
        memset(temp, 0, MAXSTRLEN);
        memcpy(temp, ++ptr, individual_length);

        //Save pointer for future length calculations
        prev_ptr = ptr;
        
        //Set new ponter, Incrementation operator skips delimiting comma
        ptr = strchr(ptr,',');

        //Allow "0x0" to be used instead of "0x000...0"
        individual_length = ptr - prev_ptr;
    }

    //Ensure rate and capacity sum to 1600 for keccakF1600
    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
    return;
    // print_state(state, -1);
    KeccakF1600(state);

    //print_state(state, 99);

    // while(inputByteLen > 0) {
    //     blockSize = MIN(inputByteLen, rateInBytes);
       
    //     // for (i = 0; i < blockSize; i++){
    //     //     state[i] ^= input[i];
    //     //     printf("Input: %x\n", input[i]);
    //     // }
    //     char *input_copy = strtok_r(input,",", &token);
    //     printf("Token: %s\n", token);
    //     state[count] = atoi(token);
    //     //print_state(&state, count++);
    //     input += blockSize;
    //     inputByteLen -= blockSize;

    //     if (inputByteLen == blockSize) {
    //         //print_state(state, 999);
    //         //KeccakF1600(state);
    //         blockSize = 0;
    //     }
    // }
    
    // printf("SQEEZING\n");
    // /* === Do the padding and switch to the squeezing phase === */
    // /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    // state[blockSize] ^= delimitedSuffix;
    // /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    // if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes-1)))
    //     KeccakF1600(state);
    // /* Add the second bit of padding */
    // state[rateInBytes-1] ^= 0x80;
    // /* Switch to the squeezing phase */
    // KeccakF1600(state);

    // /* === Squeeze out all the output blocks === */
    // while(outputByteLen > 0) {
    //     blockSize = MIN(outputByteLen, rateInBytes);
    //     memcpy(output, state, blockSize);
    //     output += blockSize;
    //     outputByteLen -= blockSize;

    //     if (outputByteLen > 0)
    //         KeccakF1600(state);
    // }

    
}

// int main() {
//     Keccak(256, 1344, sample_input_2, 1024, ',', "TODO", 512);
//     //KeccakF1600(&sample_input);
// }