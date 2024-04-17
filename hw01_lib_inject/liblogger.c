// Shared object
// This shared object will be injected into the monitored binary using LD_PRELOAD. It will intercept file access related
// library calls and log them along with their parameters and return values.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <pcre.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


// Function Prototypes
void parse_config_file(const char *config_file);
int isBlacklisted(const char *check_content, const char *blacklist);
void log_content(const void *ptr, size_t len, FILE *stream, const char *api);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
int system(const char *command);

// Function pointer types for the original functions
typedef FILE *(*orig_fopen_func)(const char *path, const char *mode);
typedef size_t (*orig_fread_func)(void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef size_t (*orig_fwrite_func)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
typedef int (*orig_connect_func)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*orig_getaddrinfo_func)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
typedef int (*orig_system_func)(const char *command);

// Blacklist entry structure
typedef struct {
    const char *api;  // open, read, write, connect, getaddrinfo
    const char *rule;
} BlacklistEntry;

#define MAX_BLACKLIST_SIZE 20
BlacklistEntry blacklist[MAX_BLACKLIST_SIZE];
int num_entries = 0;

char * parse_log_filename = NULL;
char * parse_base_filename = NULL;

// Runs when a shared library is loaded: __attribute__((constructor))
void __attribute__((constructor)) before_main() {
    parse_config_file("config.txt");
}

void parse_config_file(const char *config_file) {
    orig_fopen_func orig_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!orig_fopen) {
        fprintf(stderr, "Error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    FILE *file = orig_fopen(config_file, "r");
    if (file == NULL) {
        perror("Error opening config file");
        return;
    }

    char line[256];
    int index = 0;
    int begin = 0;
    
    char tag[20], api[50], rule[100];

    while (fgets(line, sizeof(line), file) != NULL) {
        
        if (sscanf(line, "%s %s", tag, api) == 2) {
            sscanf(api, "%[^-]", api);  
            if (strcmp(tag, "BEGIN") == 0) begin = 1;
            else if (strcmp(tag, "END") == 0) begin = 0;

        } else if (begin) {
            sscanf(line, "%s", rule);
            
            blacklist[index].api = strdup(api);
            blacklist[index].rule = strdup(rule);

            index++;
        }
    }

    num_entries = index;
    
    // for (int i = 0; i < num_entries; i++) {
    //     printf("blacklist[%d].api = %s\n", i, blacklist[i].api);
    //     printf("blacklist[%d].rule = %s\n", i, blacklist[i].rule);
    // }
    
    // printf("num_entries = %d\n", num_entries);
    
    fclose(file);
}

int isBlacklisted(const char *check_content, const char *blacklist) {
    const char *error;
    int error_offset;
    pcre *re;
    int ovector[30]; // Array to hold the result of the search

    // Compile the regular expression pattern
    re = pcre_compile(blacklist, 0, &error, &error_offset, NULL);
    if (re == NULL) {
        fprintf(stderr, "PCRE compilation failed at offset %d: %s\n", error_offset, error);
        return -1; // Error compiling regex
    }

    // Execute the regular expression match against the path
    if (pcre_exec(re, NULL, check_content, strlen(check_content), 0, 0, ovector, sizeof(ovector)) >= 0) {
        // Match found
        pcre_free(re);
        return 1;
    }

    pcre_free(re);
    return 0; // No match found in the blacklist
}

// Wrapper for fopen function
FILE *fopen(const char *path, const char *mode) {
    // parse the path to get the filename and remove file extension
    // and store the filename in a global variable for log file naming
    parse_base_filename = basename(path); // with extension

    char *filename = strdup(basename(path));
    char *dot = strrchr(filename, '.');
    if (dot) *dot = '\0'; 
    parse_log_filename = filename; // without extension

    // Check if the path matches any blacklist pattern
    for (int i = 0; i < num_entries; i++) {
        if (strcmp(blacklist[i].api, "open") != 0) continue;

        if (isBlacklisted(path, blacklist[i].rule) == 1) {
            errno = EACCES;
            fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", path, mode);
            return NULL;
        }
    }

    orig_fopen_func orig_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!orig_fopen) {
        fprintf(stderr, "Error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    FILE *fp = orig_fopen(path, mode);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, fp);
    return fp;
}

// log content into {pid}-{filename}-{api}.log 
// If filename is used before, keep logging the content into the same log file.   
void log_content(const void *ptr, size_t len, FILE *stream, const char *api) {
    char log_filename[256];

    snprintf(log_filename, sizeof(log_filename), "%d-%s-%s.log", getpid(), parse_log_filename, api);

    orig_fopen_func orig_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *log_file = orig_fopen(log_filename, "a"); // Append to the log file

    for (size_t i = 0; i < len; i++) {
        fprintf(log_file, "%c", ((char *)ptr)[i]);
    }

    fclose(log_file);
}

// Wrapper for fread function
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    orig_fread_func orig_fread = dlsym(RTLD_NEXT, "fread");
    size_t result = orig_fread(ptr, size, nmemb, stream);
    // printf("ptr = %s\n", (char *)ptr);
    
    // count length of the content and log to .log file
    int len = 0;
    while (((char *)ptr)[len] != '\0') len++;
    log_content(ptr, len, stream, "read");

    // toeknize the content to word to match the blacklist keywords
    char *str = strdup((char *)ptr);
    const char *delim = " ";
    char *token = strtok(str, delim);
    while (token != NULL) {
        // printf("token = %s\n", token);
        token = strtok(NULL, delim);

        // Check if the content contains any blacklisted keywords
        for (int i = 0; i < num_entries; i++) {
            if (strcmp(blacklist[i].api, "read") != 0) continue;

            if (isBlacklisted(ptr, blacklist[i].rule) == 1) {
                errno = EACCES;
                fprintf(stderr, "[logger] fread(%p, %zu, %zu, %p) = 0\n", ptr, size, nmemb, stream);
                return 0;
            }
        }
    }
    
    fprintf(stderr, "[logger] fread(%p, %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, result);
    free(str);
    return result;
}


char * handleLineEscape(const void *ptr, size_t originLen, FILE *stream) {
    char *resString = malloc(originLen * 2);
    int returndLen = originLen;
    for (size_t i = 0, j = 0; i < originLen; i++, j++) {
        if (((char *)ptr)[i] == '\n') {
            resString[j] = '\\';
            resString[++j] = 'n';
            returndLen++;
        } else {
            resString[j] = ((char *)ptr)[i];
        }
    }
    resString[returndLen] = '\0';
    return resString;
}

// Wrapper for fwrite function
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    
    int len = 0;
    while (((char *)ptr)[len] != '\0') len++;
    log_content(ptr, len, stream, "write");

    // filename blacklist check
    for (int i = 0; i < num_entries; i++) {
        if (strcmp(blacklist[i].api, "write") != 0) continue;
        // printf("blacklist[%d].rule = %s\n", i, blacklist[i].rule);
        // printf("parse_base_filename = %s\n", parse_base_filename);
        if (isBlacklisted(parse_base_filename, blacklist[i].rule) == 1) {
            char* resString = handleLineEscape(ptr, len, stream);
            fprintf(stderr, "[logger] blacklist fwrite(\"%s\", %zu, %zu, %p) = 0\n", resString, size, nmemb, stream);
            errno = EACCES;
            return 0;
        }
    }
    
    // original fwrite function to write the content to the stream
    orig_fwrite_func orig_fwrite = dlsym(RTLD_NEXT, "fwrite");
    size_t result = orig_fwrite(ptr, size, nmemb, stream);

    char* resString = handleLineEscape(ptr, len, stream);
    fprintf(stderr, "[logger] fwrite(\"%s\", %zu, %zu, %p) = %zu\n", resString, size, nmemb, stream, result);
    free(resString);

    return result;
}

// Wrapper for connect function
// Allow a user to block connection setup to specific IP addresses. 
// If the IP is blocked, return -1 and set errno to ECONNREFUSED.
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    char * ip = malloc(100);
    struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, ip, 100);
    // printf("ip = %s\n", ip);

    // Check if the path matches any blacklist pattern
    for (int i = 0; i < num_entries; i++) {
        if (strcmp(blacklist[i].api, "connect") != 0) continue;

        if (isBlacklisted(ip, blacklist[i].rule) == 1) {
            errno = ECONNREFUSED;
            fprintf(stderr, "[logger] connect(%d, %s, %d) = -1\n", sockfd, ip, addrlen);
            return -1;
        }
    }

    orig_connect_func orig_connect = dlsym(RTLD_NEXT, "connect");
    int result = orig_connect(sockfd, addr, addrlen);
    fprintf(stderr, "[logger] connect(%d, %s, %d) = %d\n", sockfd, ip, addrlen, result);
    free(ip);
    return result;
}

// Wrapper for getaddrinfo function
// Allow a user to block specific host name resolution requests. If a host is blocked, return EAI_NONAME.
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // Check if the path matches any blacklist pattern
    for (int i = 0; i < num_entries; i++) {
        if (strcmp(blacklist[i].api, "getaddrinfo") != 0) continue;

        if (isBlacklisted(node, blacklist[i].rule) == 1) {
            errno = EAI_NONAME;
            fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = -1\n", node, service, hints, res);
            return -2;
        }
    }

    orig_getaddrinfo_func orig_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    int result = orig_getaddrinfo(node, service, hints, res);
    fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n", node, service, hints, res, result);
    return result;
}

// Wrapper for system function
// Commands invoked by system function should also be hijacked and monitored by your program.
int system(const char *command) {
    orig_system_func orig_system = dlsym(RTLD_NEXT, "system");
    int result = orig_system(command);
    fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, result);
    return result;
}