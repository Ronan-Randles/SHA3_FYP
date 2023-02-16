#include <stdio.h>
#include <stdlib.h>
#include "keccak.c"
#include "random.c"
#include <time.h>
#include <string.h>

#define n_inputs 256*64
#define buffer_max 512
#define inputs_per_row 25
#define row_mem_size inputs_per_row*sizeof(uint64_t)

void generate_input(int n){
    //TODO: Could save to array rather than file
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

void write_output(uint64_t *state, int n){
    char *filename = "output.txt";

    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening the file %s", filename);
    }
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < inputs_per_row; j++){
            fprintf(f, "0x%.16llx", state[i * inputs_per_row + j]);
                
                    if (j == inputs_per_row - 1){
                        if (i != n-1)
                            fprintf(f,"\n");
                    }
                    else
                        fprintf(f,",");

        }
    }
}

int preprocess_loadInputs(uint64_t *state, int num_inputs){
    unsigned char *inputs[num_inputs];
    char *FILENAME = "input.txt";
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0;
    ssize_t line_size;

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
        inputs[line_count] = malloc(2 * 512 * sizeof(char));
        if(inputs[line_count] == NULL){
            printf("Failed to allocate memory on input\n");
            return EXIT_FAILURE;
        }
        strcpy(inputs[line_count],line_buf);
        line_count++;

    } while (line_size >= 0);
    /* Free the allocated line buffer */
    free(line_buf);
    
    /* Close the file now that we are done with it */
    fclose(fp);

    //
    unsigned char *ptr;
    char *new_ptr;
    char *remaining;
    unsigned char *prev_ptr;
    int individual_length;
    char *temp = malloc(MAXSTRLEN);
    int state_mem_size = 0;

    //memset(state, 0, sizeof(state));
    for (int j = 0; j < num_inputs; j++){
        //Absorb input blocks from sting using parsing
        ptr = strchr(inputs[j],',');
        individual_length = (unsigned char *)ptr - inputs[j];
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

int main(){
    uint64_t *state_input = malloc(n_inputs * row_mem_size);
    clock_t start, end = 0;

    printf("\nGenerating inputs...\n");
    generate_input(n_inputs);

    printf("\nLoading inputs...\n");
    preprocess_loadInputs(state_input, n_inputs);

    printf("\nStarting Keccak hashing...\n");
    start = clock();
    Keccak(256, 1344, state_input, n_inputs);
    end = clock();


    /* Get the time taken by program to execute in seconds */
    double duration = ((double)end - start)/CLOCKS_PER_SEC;

    printf("\nTime taken to hash %i inputs: %f seconds\n", n_inputs, duration);

    write_output(state_input, n_inputs);
    printf("Output written to output.txt\n");
    //free(state_input);
}