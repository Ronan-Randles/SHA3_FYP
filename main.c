#include <stdio.h>
#include <stdlib.h>
#include "keccak.c"
#include "random.c"
#include <time.h>
#include <string.h>

#define n_inputs 250000
#define buffer_max 512

int generate_input(int n){
    //TODO: Could save to array rather than file
    char *filename = "input.txt";

    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening the file %s", filename);
        return -1;
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

    return 0;
}

int load_inputs(){
    //TODO move input loading here
}

int main(){
    unsigned char *inputs[n_inputs];
    char *FILENAME = "input.txt";
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0;
    ssize_t line_size;

    printf("\nGenerating inputs...\n");
    generate_input(n_inputs);

    clock_t start, end;
    FILE *fp = fopen(FILENAME, "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening file '%s'\n", FILENAME);
        return EXIT_FAILURE;
    }

    printf("\nLoading inputs...\n");
    
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
        }

        strcpy(inputs[line_count],line_buf);

        line_count++;

    } while (line_size >= 0);

    // for (int i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++){
    //     printf("Inputs[%i]: %s\n", i, inputs[i]);
    // }

    printf("\nStarting Keccak hashing...\n");
    start = clock();
    for (int i = 0; i < n_inputs; i++) { 
        Keccak(256, 1344, inputs[i], 1024, ',', "TODO", 512);
    }

    end = clock();
    /* Get the time taken by program to execute in seconds */
    double duration = ((double)end - start)/CLOCKS_PER_SEC;

    /* Free the allocated line buffer */
    free(line_buf);
    line_buf = NULL;

    /* Close the file now that we are done with it */
    fclose(fp);
    printf("\nTime taken to hash %i inputs: %f seconds\n", n_inputs, duration);
}