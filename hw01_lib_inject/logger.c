#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <argp.h>


#define DEFAULT_SOPATH "./logger.so"

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n", program_name);
}

int main(const int argc, char *argv[]) {
    char *sopath = DEFAULT_SOPATH;
    char *output_file = NULL;
    int opt;

    // Parse command line arguments
    if (argc < 2) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "config.txt") != 0) {
        fprintf(stderr, "config file should be named with config.txt\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // ------------------- Prepare argv_before_command start ---------------------
    // ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 ...]
    //                                           ^ argv_before_command_end_index
    // argv_before_command: ./logger config.txt [-o file] [-p sopath]
    // ---------------------------------------------------------------------------
    
    int argv_before_command_end_index = 2;
    if (argv[2][0] == '-') {
        argv_before_command_end_index = 4;
        if (argv[4][0] == '-') {
            argv_before_command_end_index = 6;
        }
    }
    char *argv_before_command[argv_before_command_end_index];
    int i = 0;
    for (; i < argv_before_command_end_index; i++) {
        argv_before_command[i] = argv[i];
    }
    argv_before_command[i+1] = '\0';
    // printf("argv_before_command_end_index: %d\n", argv_before_command_end_index);
    
    // ------------------- Prepare argv_before_command end -----------------------


    optind = 2; // parsing after config.txt
    while ((opt = getopt(argv_before_command_end_index, argv_before_command, "o:p:")) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            case 'p':
                sopath = optarg;
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind != argv_before_command_end_index) {
        // printf("optind: %d\n", optind);
        // printf("argv_before_command_end_index: %d\n", argv_before_command_end_index);
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // The command to execute and its arguments
    char *command = argv[argv_before_command_end_index];
    char **args = &argv[argv_before_command_end_index];

    // set LD_PRELOAD env
    setenv("LD_PRELOAD", sopath, 1);

    // Redirect output to specified file or stderr
    if (output_file != NULL) {
        freopen(output_file, "w", stderr);
    } else {
        dup2(fileno(stderr), fileno(stdout));
    }

    // Execute the command with modified environment
    execvp(command, args);

    // If execvp fails, print error and exit
    perror("execvp");
    exit(EXIT_FAILURE);
}