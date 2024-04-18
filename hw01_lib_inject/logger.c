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

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <argp.h>

// #define DEFAULT_SOPATH "./logger.so"

// const char *argp_program_version = "logger 1.0";
// const char *argp_program_bug_address = "<your_email@example.com>";

// // Struct to hold parsed arguments
// struct arguments {
//     char *config_file;
//     char *output_file;
//     char *sopath;
//     char *command;
//     char **command_args;
// };

// // Option parser function
// static error_t parse_opt(int key, char *arg, struct argp_state *state) {
//     struct arguments *arguments = state->input;

//     switch (key) {
//         case 'o':
//             arguments->output_file = arg;
//             break;
//         case 'p':
//             arguments->sopath = arg;
//             break;
//         case ARGP_KEY_ARG:
//             switch (state->arg_num) {
//                 case 0:
//                     arguments->config_file = arg;
//                     break;
//                 case 1:
//                     arguments->command = arg;
//                     break;
//                 default:
//                     arguments->command_args[state->arg_num - 2] = arg;
//                     break;
//             }
//             break;
//         case ARGP_KEY_END:
//             if (state->arg_num < 2) {
//                 argp_usage(state);
//             }
//             break;
//         default:
//             return ARGP_ERR_UNKNOWN;
//     }
//     return 0;
// }

// // Argp parser options
// static struct argp_option options[] = {
//     {"output", 'o', "FILE", 0, "Redirect output to FILE"},
//     {"sopath", 'p', "SOPATH", 0, "Specify shared object path for LD_PRELOAD"},
//     {0}
// };

// // Argp parser
// static struct argp argp = {
//     .options = options,
//     .parser = parse_opt,
//     .args_doc = "config.txt command [arg1 arg2 ...]",
//     .doc = "A program to execute commands specified in a configuration file."
// };

// int main(int argc, char *argv[]) {
//     struct arguments arguments;

//     // Set default values
//     arguments.config_file = NULL;
//     arguments.output_file = NULL;
//     arguments.sopath = DEFAULT_SOPATH;
//     arguments.command = NULL;
//     arguments.command_args = malloc((argc - 1) * sizeof(char *));

//     // Parse arguments using argp
//     argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &arguments);

//     // Validate config file name
//     if (strcmp(arguments.config_file, "config.txt") != 0) {
//         fprintf(stderr, "config file should be named config.txt\n");
//         argp_usage(NULL);
//     }

//     // Set LD_PRELOAD environment variable
//     setenv("LD_PRELOAD", arguments.sopath, 1);

//     // Redirect output to specified file or stderr
//     if (arguments.output_file != NULL) {
//         freopen(arguments.output_file, "w", stderr);
//     } else {
//         dup2(fileno(stderr), fileno(stdout));
//     }

//     // Execute the command with modified environment
//     execvp(arguments.command, arguments.command_args);

//     // If execvp fails, print error and exit
//     perror("execvp");
//     exit(EXIT_FAILURE);
// }