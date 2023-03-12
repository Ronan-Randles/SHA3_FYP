/**
 * Written by Ronan Randles
 * Student number: 19242441
 * 
 * Reference material used:
 * https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "keccak.h"

typedef uint64_t tKeccakLane;

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))
#define Keccak_Rounds 24
#define SHA3_CONST(x) x##L
#define inputs_per_row 25
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



static void print_state(uint64_t state[25], int round){
    int x, y;
    //printf("%s round %i\n", perm_strings[last_perm], round);
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

/**
    @brief Applies the KeccakF1600 permutation to the input state.
    @param state A pointer to the state to be permuted.
    @details This function applies the KeccakF1600 permutation to the input state
    and modifies it in-place. The permutation consists of 24 rounds, each of which
    applies the Theta, Rho and Pi, Chi, and Iota steps to the state in sequence.
    The permutation constants used in the Iota step are defined in the keccakf_rndc
    array.
    @note This function does not return a value, it modifies the input state in-place.
*/
void KeccakF1600(void *state)
{
    // printf("INPUT\n");
    // print_state(state, 99);
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
    
    //print_state(state,0);
    for (round = 0; round < 24; round++)
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
            XORLane(0,0,keccakf_rndc[round]);
            last_perm = Iota;
            //print_state(state, round);
        }
        
    }
}
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, uint64_t *input, int num_inputs)
{
    //Ensure rate and capacity sum to 1600 for keccakF1600
    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;
    // print_state(state, -1);
        for (int i = 0; i < num_inputs; i++) { 
            // printf("before\n");
            // print_state(&input[i * inputs_per_row], i);
            KeccakF1600(&input[i * inputs_per_row]);
            
            // printf("after\n");
            // print_state(&input[i * inputs_per_row], i);
    }
    

    
}

// int main() {
//     printf("Test\n");
// }