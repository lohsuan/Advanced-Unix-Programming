#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#define DEFAULT_SOPATH "./logger.so"

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n", program_name);
}

int main(int argc, char *argv[]) {

    char *sopath = DEFAULT_SOPATH;
    char *output_file = NULL;
    int opt;

    // Parse command line arguments
    if (argc < 2) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    char *config_file = argv[1];
    if (strcmp(config_file, "config.txt") != 0) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    

    optind = 2; // Start parsing after config_file argument

    // don't show invalid option
    opterr = 0;
    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            case 'p':
                sopath = optarg;
                break;
            default:
                continue;
        }
    }

    // Check if command is provided
    if (optind >= argc) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // // The command to execute and its arguments
    char *command = argv[optind];
    char **args = &argv[optind];

    // set LD_PRELOAD env with setenv
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