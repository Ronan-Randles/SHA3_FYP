#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>

#include "GPUProcess.h"

#define n_inputs 16
#define buffer_max 512
#define inputs_per_row 25
#define row_mem_size inputs_per_row*sizeof(uint64_t)
#define MAXSTRLEN sizeof("0xa3a3a3a3a3a3a3a3")

using namespace std;

int write_output(uint64_t* state, int n) {
    char* filename = (char *)"output_gpu.txt";

    FILE* f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening the file %s", filename);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < inputs_per_row; j++) {
            fprintf(f, "0x%.16llx", state[i * inputs_per_row + j]);

            if (j == inputs_per_row - 1) {
                if (i != n - 1)
                    fprintf(f, "\n");
            }
            else
                fprintf(f, ",");

        }
    }
    return EXIT_SUCCESS;
}

int preprocess_loadInputs(uint64_t* state, char* FILENAME) {
    //TODO: SHOULD BE UNSIGNED?
    //Change to be allocated on heap
    char **inputs = (char **)malloc(n_inputs * 512 * sizeof(char));
    if (inputs == NULL) {
        printf("Failed to allocate memory on input\n");
        return EXIT_FAILURE;
    }
    size_t line_buf_size = 0;
    int line_count = 0;
    size_t line_size;

    //Take in lines from input.txt and save as individual state inputs
    fstream fp;
    fp.open(FILENAME, ios::in);
    if (!fp.is_open())
    {
        std::cerr << "Cannot open the File : " << FILENAME << std::endl;
        return EXIT_FAILURE;
    }

    string tp = "";
    /* Loop through until we are done with the file. */
    do
    {   
        getline(fp, tp);

        //Allocate enough memory to store actual string pointed to by line_buf
        inputs[line_count] = (char *)malloc(512 * sizeof(char));
        if (inputs[line_count] == NULL) {
            printf("Failed to allocate memory on input\n");
            return EXIT_FAILURE;
        }
        strcpy(inputs[line_count], tp.c_str());
        //std::cout << line_count << "\n" << inputs[line_count] << "\n\n";
        line_count++;

    } while (line_count < n_inputs);

    /* Close the file now that we are done with it */
    fp.close();

    
    char *ptr;
    char *new_ptr;
    char *remaining;
    char *prev_ptr;
    int individual_length;
    char *temp = (char *)malloc(MAXSTRLEN);
    int state_mem_size = 0;

    //memset(state, 0, sizeof(state));
    for (int j = 0; j < n_inputs; j++){
        //Absorb input blocks from sting using parsing
        ptr = strchr(inputs[j],',');
        individual_length = ptr - inputs[j];
        memcpy(temp, inputs[j], individual_length);
        for (int i = 0; i < inputs_per_row; i++){
            state[j* inputs_per_row + i] = strtoull(temp,&remaining,16);

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
    }
    //State inputs are now saved to state, an n_inputs*25 array.
    //Now safe to free malloc'ed memory
    free(temp);
    for (int i = 0; i < n_inputs; i++)
        free(inputs[i]);

    return EXIT_SUCCESS;
}

int main()
{
    uint64_t* state_input = (uint64_t*)malloc(n_inputs * row_mem_size);
    uint64_t* gpu_state_out = (uint64_t*)malloc(n_inputs * row_mem_size);
    uint64_t* cpu_out = (uint64_t*)malloc(n_inputs * row_mem_size);

    /*Load cpu generated inputs*/
    printf("\nLoading inputs from inputs.txt\n");
    preprocess_loadInputs(state_input, (char*)"../../input.txt");

    /* Load cpu outputs for comparrison */
    printf("\nLoading cpu outputs for comparison\n");
    preprocess_loadInputs(cpu_out, (char*)"../../output.txt");

    printf("Starting Keccak Hashing\n");
    GPUProcessing(state_input, gpu_state_out, cpu_out, n_inputs);

    printf("Writing outputs to outputs_gpu.txt\n"); 
    write_output(gpu_state_out, n_inputs);
   
    
    return(EXIT_SUCCESS);
}
