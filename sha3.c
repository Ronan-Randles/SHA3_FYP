/** 
 * This Keccak version was built according to the specification outlined in the "FEDERAL INFORMATION
 * PROCESSING STANDARDS PUBLICATION": SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions.
 * Available here:https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 * 
 * 
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>


static void print_state(uint64_t state[5][5]);

//Uint 64 ~= Lane since lane = w = 64 bits for b=1600 for now
#define b 1600
#define w b/25
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))

static int sha3(uint64_t state[5][5]){
    //TODO add malloc,NULL check
    uint64_t c[5], d[5];
    int x, y;
    
    //theta
    for (x = 0; x < 5; x++)
       c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
    
    for (x = 0; x < 5; x++) {
        d[x] = c[(x + 4) % 5] ^ ROL64(c[(x + 1) % 5], 1);
        
        for (y = 0; y < 5; y++)
            state[x][y] ^= d[y];
    }
    print_state(state);
}

static void print_state(uint64_t state[5][5]){
    int x, y;
    //print in format of sha3 example pdf
    for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
            printf("[%i,%i] = %lx \n", y, x, state[y][x]);
        }
        //printf("\n");
    }
}

int main() {
    uint64_t state[5][5] = {
                                {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0000000000000000},
                                {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0000000000000000},
                                {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0000000000000000, 0x0000000000000000},
                                {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0000000000000000, 0x0000000000000000},
                                {0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0xa3a3a3a3a3a3a3a3, 0x0000000000000000, 0x0000000000000000}
                            };
    
    //print_state(state);
    sha3(state);
    

    return 0;
}