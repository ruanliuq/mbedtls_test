#pragma once

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//------------------------------------------------------------------------------
//  define debug printf infomation
//------------------------------------------------------------------------------
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

#ifdef DONTPRINTANYTHING
#define ERROR_FAIL2(MESSAGE, ...) do { exit(EXIT_FAILURE); } while (0)
#define ERROR_FAIL(MESSAGE, ...) do { exit(EXIT_FAILURE); } while (0)
#define ERROR(MESSAGE, ...)      do { ; } while (0)
#define WARNING(MESSAGE, ...)    do { ; } while (0)
#define DEBUG_MPK(MESSAGE, ...)  do { ; } while (0)
#define DEBUG_PRINTF(MESSAGE, ...)  do { printf(MESSAGE "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#else
#define ERROR_FAIL2(MESSAGE, ...) do { fprintf(stderr, COLOR_RED    "0x%lx %d: %s:%d: " MESSAGE COLOR_RESET "\n", pthread_self(), getpid(), __FILE__, __LINE__, ##__VA_ARGS__); if(errno){perror(NULL);} exit(EXIT_FAILURE); } while (0)
#define ERROR_FAIL(MESSAGE, ...) do { fprintf(stderr, COLOR_RED    "0x%lx %d: %s: " MESSAGE COLOR_RESET "\n", pthread_self(), getpid(), __func__, ##__VA_ARGS__); if(errno){perror(NULL);} exit(EXIT_FAILURE); } while (0)
#define ERROR(MESSAGE, ...) do { if (MESSAGE) { fprintf(stderr, COLOR_RED "0x%lx %d: %s: " MESSAGE COLOR_RESET "\n", pthread_self(), getpid(), __func__, ##__VA_ARGS__); } } while (0)
#define WARNING(MESSAGE, ...)    do { fprintf(stderr, COLOR_YELLOW "0x%lx %d: %s: " MESSAGE COLOR_RESET "\n", pthread_self(), getpid(), __func__, ##__VA_ARGS__); } while (0)
#define DEBUG_MPK(MESSAGE, ...)  do { fprintf(stderr, COLOR_BLUE   "0x%lx %d: %s: " MESSAGE COLOR_RESET "\n", pthread_self(), getpid(), __func__, ##__VA_ARGS__); } while (0)
#define DEBUG_PRINTF(MESSAGE, ...)  do { printf(MESSAGE "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#endif
//------------------------------------------------------------------------------
// only linux tee os 
static inline void print_mem_maps() {
    #ifndef RELEASE
    char line[2048];
    FILE * fp;
    DEBUG_MPK("print_mem_maps()");

    // 删掉
    #ifndef PROXYKERNEL
    // print maps, including protection keys
    DEBUG_MPK("print_mem_maps() smaps");
    fp = fopen("/proc/self/smaps", "r");
    if(fp == NULL){
        ERROR_FAIL("Failed to fopen /proc/self/smaps");
    }
    while (fgets(line, 2048, fp) != NULL) {
        if (strstr(line, "-") != NULL
         || (strstr(line, "ProtectionKey") != NULL && strstr(line, "ProtectionKey:         0") == NULL)
         //|| strstr(line, "Size") == line
        ) {
            fprintf(stderr, "%s", line);
        }
    }
    fclose(fp);
    #endif // !PROXYKERNEL

    #endif // !RELEASE
}

//------------------------------------------------------------------------------
#define assert_warn(expression) do { \
    if(!(expression)) WARNING("assertion failed: %s", #expression); \
} while (0)

#endif // __ASSEMBLY__