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
void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen);

#include <stdint.h>
#include <stdio.h>
typedef uint64_t tKeccakLane;

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

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

int LFSR86540(uint8_t *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

static void print_state(uint8_t state[25]){
    int x, y;


    //print in format of sha3 example pdf
    for (int p = 0; p < 5; p++) {
        for (int l = 0; l < 5; l++) {
            printf("%.16lx ", readLane(l,p));
            if (((p * 5 + l) % 2) == 1)
                printf("\n");
        }
    }
    printf("\n");
}

void KeccakF1600(void *state)
{
    unsigned int round, x, y, j, t;
    uint8_t LFSRstate = 0x01;
    // for (int p = 0; p < 5; p++) {
    //     for (int l = 0; l < 5; l++)
    //         printf("Sample [%i,%i] %lx\n",l, p, readLane(l,p));
    // }
    printf("\n\n\n");
    print_state(state);
    printf("\n\n\n");
    //FOR LOOP
    {
        //Theta step
        tKeccakLane C[5], D;

        for (x = 0; x < 5; x++)
            C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
        for (x = 0; x < 5; x++) {
            D = C[(x + 4) % 5] ^ ROL64(C[(x+1) % 5], 1);
            for (y = 0; y < 5; y++)
                XORLane(x, y, D);
        }    
    }

    print_state(state);
}

#include <string.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix, unsigned char *output, unsigned long long int outputByteLen)
{
    uint8_t state[200];
    unsigned int rateInBytes = rate/8;
    unsigned int blockSize = 0;
    unsigned int i;

    //Ensure rate and capacity sum to 1600 for keccakF1600
    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
    return;

    memset(state, 0, sizeof(state));

    //Absorb input blocks
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for (i = 0; i < blockSize; i++)
            state[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            KeccakF1600(state);
            blockSize = 0;
        }
    }

    /* === Do the padding and switch to the squeezing phase === */
    /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    state[blockSize] ^= delimitedSuffix;
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if (((delimitedSuffix & 0x80) != 0) && (blockSize == (rateInBytes-1)))
        KeccakF1600(state);
    /* Add the second bit of padding */
    state[rateInBytes-1] ^= 0x80;
    /* Switch to the squeezing phase */
    KeccakF1600(state);

    /* === Squeeze out all the output blocks === */
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600(state);
    }

    
}

int main() {

    
    KeccakF1600(&sample_input);
}