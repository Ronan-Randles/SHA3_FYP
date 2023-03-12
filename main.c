#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include "keccak.h"
#include "random.h"

#define n_inputs 1000000
#define buffer_max 512
#define inputs_per_row 25
#define row_mem_size inputs_per_row*sizeof(uint64_t)
#define MAXSTRLEN sizeof("0xa3a3a3a3a3a3a3a3")

/**
    @brief Generates input data for a program and saves it to a file.

    @param n The number of data points to generate.

    @details This function generates input data for a program by using the genrand64_int64() 
    function to generate a series of 64-bit integers. The function then saves this data to a file
    named "input.txt". Each data point is written as a string in the format "0x%.16llx", and the 
    data points are separated by commas. The function can generate up to 25 data points per line,
    and it adds a newline character after every 25th data point. If the file cannot be opened,
    the function prints an error message to the console.
*/
void generate_input(int n){
    char *filename = "input.txt";

    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening the file %s", filename);
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < 25; j++){
            fprintf(f, "0x%.16llx", genrand64_int64());
                
                    if (j == 24){
                        if (i != n-1)
                            fprintf(f,"\n");
                    }
                    else
                        fprintf(f,",");
        }
    }
    fclose(f);
}

static void print_state(uint64_t state[25], int round){
    int x, y;
    //printf("%s round %i\n", perm_strings[last_perm], round);
    //print in format of sha3 example pdf
    for (int p = 0; p < 5; p++) {
        for (int l = 0; l < 5; l++) {
            printf("[%i,%i]: %.16lx ", l, p, state[p * 5 + l]);
            if (((p * 5 + l) % 2) == 1)
                printf("\n");
        }
    }
    printf("\n");
}

/**

    @brief Writes the output of the program to a file named "output.txt".

    @param state A pointer to an array of 64-bit unsigned integers representing the state.

    @param n An integer representing the number of output rows to be written to the file.

    @return An integer representing the status of the function execution. Returns EXIT_SUCCESS
    (0) if successful, and EXIT_FAILURE (1) otherwise.
*/
int write_output(uint64_t *state, int n){
    char *filename = "output.txt";

    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening the file %s", filename);
        return EXIT_FAILURE;
    }
    for (int i = 0; i < n; i++) {
        // Prints for testing
        // printf("Output #%i\n", i);
        // print_state(&state[i*inputs_per_row], i);
        for (int j = 0; j < inputs_per_row; j++){
            fprintf(f, "0x%.16lx", state[i * inputs_per_row + j]);
                
                    if (j == inputs_per_row - 1){
                        if (i != n-1)
                            fprintf(f,"\n");
                    }
                    else
                        fprintf(f,",");

        }
    }
    return EXIT_SUCCESS;
}

/**

    @brief Loads input data from a file and preprocesses it for use in a program.

    @param state A pointer to the memory location where the preprocessed input data will be stored.

    @param num_inputs The number of input data points to load from the file.

    @return Returns EXIT_SUCCESS upon successful completion of the function, or EXIT_FAILURE if an error occurs.

    @details This function reads in a file named "input.txt" and preprocesses its contents for use in a program.
    The function first allocates memory for an array of strings, each of which will hold a single line from the file.
    It then reads in each line from the file and saves it as a string in the array. The function then parses each
    string in the array to extract the individual data points and save them to the memory location pointed to by the
    "state" parameter. The function uses the strtoull() function to convert each data point from its hexadecimal string
    representation to an integer. If the function encounters an error, it prints an error message to the console and
    returns EXIT_FAILURE. The function frees any dynamically allocated memory before returning.

    @note The "state" parameter must point to a memory location that is large enough to hold the preprocessed input data.
    The "num_inputs" parameter specifies the number of data points to load from the file, and this value should not exceed
    the size of the memory allocated for the "state" parameter.

*/
int preprocess_loadInputs(uint64_t *state, int num_inputs){
    
    char **inputs = malloc(n_inputs * 512 * sizeof(char));
    if(inputs == NULL){
        printf("Failed to allocate memory on input\n");
        return EXIT_FAILURE;
    }

    char *FILENAME = "input.txt";
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0;
    int line_size;

    //Take in lines from input.txt and save as individual state inputs
    FILE *fp = fopen(FILENAME, "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening file '%s'\n", FILENAME);
        return EXIT_FAILURE;
    }
    
    /* Loop through until we are done with the file. */
    do
    {
        line_size = getline(&line_buf, &line_buf_size, fp);
        if (line_size < 0)
            break; 

        //Allocate enough memory to store actual string pointed to by line_buf
        inputs[line_count] = malloc(512 * sizeof(char));
        if(inputs[line_count] == NULL){
            printf("Failed to allocate memory on input\n");
            return EXIT_FAILURE;
        }
        strcpy(inputs[line_count],line_buf);
        // print for testing
        // printf("Line #%i: {%s}\n", line_count, inputs[line_count]);
        line_count++;

    } while (line_size >= 0);
    /* Free the allocated line buffer */
    free(line_buf);
    
    /* Close the file now that we are done with it */
    fclose(fp);

    //
    char *ptr;
    char *remaining;
    char *prev_ptr;
    int individual_length;
    char *temp = malloc(MAXSTRLEN);
    int state_mem_size = 0;

    for (int j = 0; j < n_inputs; j++){
        //Absorb input blocks from sting using parsing
        ptr = strchr(inputs[j],',');
        individual_length = ptr - inputs[j];
        // Prints for testing
        // printf("\nInput #%i\n", j);
        // printf("{");
        memcpy(temp, inputs[j], individual_length);
        for (int i = 0; i < inputs_per_row; i++){
            state[j* inputs_per_row + i] = strtoull(temp,&remaining,16);
            //printf("%.16lx,", state[j* inputs_per_row + i]);

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
        // printf("}");
    }

    //State inputs are now saved to state, an n_inputs*25 array.
    //Now safe to free malloc'ed memory
    free(temp);
    for (int i = 0; i < n_inputs; i++)
        free(inputs[i]);

    return EXIT_SUCCESS;
}

int main(){
    //Allows for loop to control iteration of inputs
    int mult = 1;

    printf("\nGenerating inputs...\n");
    generate_input(n_inputs * mult);

    //Memory to load inputs into
    uint64_t *state_input = malloc(n_inputs * mult * row_mem_size);
    printf("\nLoading inputs...\n");
    preprocess_loadInputs(state_input, n_inputs * mult);

    printf("\nStarting Keccak hashing...\n");
    if (mult > 1)
        printf(" #Inputs  Time (s)");
    for (int j = 1; j <= mult; j++){
        clock_t start, end = 0;

        start = clock();
        Keccak(256, 1344, state_input, n_inputs * j);
        end = clock();

        /* Get the time taken by program to execute in seconds */
        double duration = ((double)end - start)/CLOCKS_PER_SEC;
    
        if (mult == 1)
            printf("Time taken to hash %i inputs: %f s\n", n_inputs, duration);
        else
            printf("\n %i  %f \n", n_inputs * j, duration);
    }

    write_output(state_input, n_inputs);
    printf("Output written to output.txt\n");
}