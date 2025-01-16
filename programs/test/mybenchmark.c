/*
 *  Benchmark demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
#include "encryptiondata.h"
#if !defined(MBEDTLS_HAVE_TIME)
int main(void)
{
    mbedtls_printf("MBEDTLS_HAVE_TIME not defined.\n");
    mbedtls_exit(0);
}
#else

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>

#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha3.h"

#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/aria.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cmac.h"
#include "mbedtls/poly1305.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"

#include "mbedtls/rsa.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"

#include "mbedtls/error.h"

/* *INDENT-OFF* */
#ifndef asm
#define asm __asm
#endif
/* *INDENT-ON* */

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#include <windows.h>
#include <process.h>

struct _hr_time {
    LARGE_INTEGER start;
};

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>

struct _hr_time {
    struct timeval start;
};

#endif /* _WIN32 && !EFIX64 && !EFI32 */

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#ifdef MBEDTLS_TIMING_ALT
void mbedtls_set_alarm(int seconds);
unsigned long mbedtls_timing_hardclock(void);
extern volatile int mbedtls_timing_alarmed;
#else
static void mbedtls_set_alarm(int seconds);
static unsigned long mbedtls_timing_hardclock(void);
#endif

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  (2 * sizeof(size_t))

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 16)  /* 64k */


#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define OPTIONS                                                              \
    "md5, ripemd160, sha1, sha256, sha512,\n"                                \
    "sha3_224, sha3_256, sha3_384, sha3_512,\n"                              \
    "des3, des, camellia, chacha20,\n"                                       \
    "aes_cbc, aes_cfb128, aes_cfb8, aes_gcm, aes_ccm, aes_xts, chachapoly\n" \
    "aes_cmac, des3_cmac, poly1305\n"                                        \
    "ctr_drbg, hmac_drbg\n"                                                  \
    "rsa, dhm, ecdsa, ecdh.\n"

#if defined(MBEDTLS_ERROR_C)
#define PRINT_ERROR                                                     \
    mbedtls_strerror(ret, (char *) tmptest, sizeof(tmptest));          \
    mbedtls_printf("FAILED: %s\n", tmptest);
#else
#define PRINT_ERROR                                                     \
    mbedtls_printf("FAILED: -0x%04x\n", (unsigned int) -ret);
#endif

#define TIME_AND_TSC(TITLE, CODE) \
    do { \
        unsigned long ii, jj; \
        unsigned long long start_cycle=0, end_cycle=0, elapsed_cycles=0; \
        unsigned long long start_cycle2=0, end_cycle2=0, elapsed_cycles2=0,elapsed_cycles2_us=0;\
        int ret = 0; \
        unsigned long long i = 0;\
        \
        mbedtls_printf(HEADER_FORMAT"\n", TITLE); \
        fflush(stdout); \
        mbedtls_timing_alarmed = 0; \
        asm volatile("rdcycle %0" : "=r"(start_cycle)); \
        mbedtls_printf("start time: %llu\n", start_cycle); \
        fflush(stdout); \
        set_array();\
        for (ii = 1; ret == 0 && !mbedtls_timing_alarmed; ii++) \
        { \
            ret = CODE; \
            asm volatile("rdcycle %0" : "=r"(end_cycle));\
            elapsed_cycles = end_cycle - start_cycle;\
            if (elapsed_cycles > 1000000) { /* Assuming hardclock returns time in microseconds */ \
                mbedtls_timing_alarmed = 1; \
            } \
        } \
        mbedtls_printf("end time: %llu\n", end_cycle); \
        fflush(stdout); \
        mbedtls_printf("value of elapsed_cycles: %llu\n", elapsed_cycles); \
        fflush(stdout); \
        if (mbedtls_timing_alarmed) { \
            mbedtls_printf("mbedtls_timing_alarmed triggered after iteration: %lu\n", ii); \
            fflush(stdout); \
        } \
        asm volatile("rdcycle %0" : "=r"(start_cycle2)); \
        mbedtls_printf("start_cycle2 time: %llu\n", start_cycle2); \
        fflush(stdout); \
        if (ret != 0) { \
            PRINT_ERROR; \
        } else { \
            mbedtls_printf("%9lu KiB/s\n", \
                           ii * BUFSIZE / 1024\
                           ); \
        } \
    } while (0)
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C) && defined(MBEDTLS_MEMORY_DEBUG)

/* How much space to reserve for the title when printing heap usage results.
 * Updated manually as the output of the following command:
 *
 *  sed -n 's/.*[T]IME_PUBLIC.*"\(.*\)",/\1/p' programs/test/benchmark.c |
 *      awk '{print length+3}' | sort -rn | head -n1
 *
 * This computes the maximum length of a title +3, because we appends "/s" and
 * want at least one space. (If the value is too small, the only consequence
 * is poor alignment.) */
#define TITLE_SPACE 17

#define MEMORY_MEASURE_INIT                                             \
    size_t max_used, max_blocks, max_bytes;                             \
    size_t prv_used, prv_blocks;                                        \
    size_t alloc_cnt, free_cnt, prv_alloc, prv_free;                    \
    mbedtls_memory_buffer_alloc_cur_get(&prv_used, &prv_blocks);      \
    mbedtls_memory_buffer_alloc_max_reset();

#define MEMORY_MEASURE_RESET                                            \
    mbedtls_memory_buffer_alloc_count_get(&prv_alloc, &prv_free);

#define MEMORY_MEASURE_PRINT(title_len)                               \
    mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);      \
    mbedtls_memory_buffer_alloc_count_get(&alloc_cnt, &free_cnt);     \
    ii = TITLE_SPACE > (title_len) ? TITLE_SPACE - (title_len) : 1;     \
    while (ii--) mbedtls_printf(" ");                                \
    max_used -= prv_used;                                               \
    max_blocks -= prv_blocks;                                           \
    max_bytes = max_used + MEM_BLOCK_OVERHEAD * max_blocks;             \
    mbedtls_printf("%6u heap bytes, %6u allocs",                       \
                   (unsigned) max_bytes,                               \
                   (unsigned) (alloc_cnt - prv_alloc));

#else
#define MEMORY_MEASURE_INIT
#define MEMORY_MEASURE_RESET
#define MEMORY_MEASURE_PRINT(title_len)
#endif

#define TIME_PUBLIC(TITLE, TYPE, CODE)                                \
    do {                                                                    \
        unsigned long ii;                                                   \
        unsigned long long start_cycle=0, end_cycle=0, elapsed_cycles=0; \
        unsigned long long start_cycle2=0, end_cycle2=0, elapsed_cycles2=0,elapsed_cycles2_us=0;\
        int ret;                                                            \
        MEMORY_MEASURE_INIT;                                                \
                                                                        \
        mbedtls_printf(HEADER_FORMAT, TITLE);                             \
        fflush(stdout);                                                   \
                                                                        \
        ret = 0;                                                            \
        mbedtls_timing_alarmed = 0; \
        asm volatile("rdcycle %0" : "=r"(start_cycle)); \
        mbedtls_printf("start time: %llu\n", start_cycle); \
        fflush(stdout); \
        for (ii = 1; !mbedtls_timing_alarmed && !ret; ii++)             \
        {                                                                   \
            MEMORY_MEASURE_RESET;                                           \
            CODE;                                                           \
            asm volatile("rdcycle %0" : "=r"(end_cycle));\
            elapsed_cycles = end_cycle - start_cycle;\
            if (elapsed_cycles > 10000000) { /* Assuming hardclock returns time in microseconds */ \
                mbedtls_timing_alarmed = 1; \
            } \
        }                                                                   \
        mbedtls_printf("end time: %llu\n", end_cycle); \
        fflush(stdout); \
        mbedtls_printf("value of elapsed_cycles: %llu\n", elapsed_cycles); \
        fflush(stdout); \
        if (mbedtls_timing_alarmed) { \
            mbedtls_printf("mbedtls_timing_alarmed triggered after iteration: %lu\n", ii); \
            fflush(stdout); \
        } \
        asm volatile("rdcycle %0" : "=r"(start_cycle2)); \
        mbedtls_printf("start_cycle2 time: %llu\n", start_cycle2); \
        fflush(stdout); \
                                                                        \
        if (ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED)               \
        {                                                                   \
            mbedtls_printf("Feature Not Supported. Skipping.\n");         \
            ret = 0;                                                        \
        }                                                                   \
        else if (ret != 0)                                                 \
        {                                                                   \
            PRINT_ERROR;                                                    \
        }                                                                   \
        else                                                                \
        {                                                                   \
            mbedtls_printf("%6lu " TYPE "/s", ii / 3);                    \
            MEMORY_MEASURE_PRINT(sizeof(TYPE) + 1);                     \
            mbedtls_printf("\n");                                         \
        }                                                                   \
    } while (0)

#if !defined(MBEDTLS_TIMING_ALT)
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    (defined(_MSC_VER) && defined(_M_IX86)) || defined(__WATCOMC__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tsc;
    __asm   rdtsc
    __asm   mov[tsc], eax
    return tsc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          ( _MSC_VER && _M_IX86 ) || __WATCOMC__ */

/* some versions of mingw-64 have 32-bit longs even on x84_64 */
#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__i386__) || (                       \
    (defined(__amd64__) || defined(__x86_64__)) && __SIZEOF_LONG__ == 4))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __i386__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__amd64__) || defined(__x86_64__))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return lo | (hi << 32);
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __amd64__ || __x86_64__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && (defined(__powerpc__) || defined(__ppc__))

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tbl, tbu0, tbu1;

    do {
        asm volatile ("mftbu %0" : "=r" (tbu0));
        asm volatile ("mftb  %0" : "=r" (tbl));
        asm volatile ("mftbu %0" : "=r" (tbu1));
    } while (tbu0 != tbu1);

    return tbl;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && ( __powerpc__ || __ppc__ ) */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc64__)

#if defined(__OpenBSD__)
#warning OpenBSD does not allow access to tick register using software version instead
#else
#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile ("rdpr %%tick, %0;" : "=&r" (tick));
    return tick;
}
#endif /* __OpenBSD__ */
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&  \
    defined(__GNUC__) && defined(__sparc__) && !defined(__sparc64__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long tick;
    asm volatile (".byte 0x83, 0x41, 0x00, 0x00");
    asm volatile ("mov   %%g1, %0" : "=r" (tick));
    return tick;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __sparc__ && !__sparc64__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__alpha__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long cc;
    asm volatile ("rpcc %0" : "=r" (cc));
    return cc & 0xFFFFFFFF;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __alpha__ */

#if !defined(HAVE_HARDCLOCK) && defined(MBEDTLS_HAVE_ASM) &&      \
    defined(__GNUC__) && defined(__ia64__)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    unsigned long itc;
    asm volatile ("mov %0 = ar.itc" : "=r" (itc));
    return itc;
}
#endif /* !HAVE_HARDCLOCK && MBEDTLS_HAVE_ASM &&
          __GNUC__ && __ia64__ */

#if !defined(HAVE_HARDCLOCK) && defined(_WIN32) && \
    !defined(EFIX64) && !defined(EFI32)

#define HAVE_HARDCLOCK

static unsigned long mbedtls_timing_hardclock(void)
{
    LARGE_INTEGER offset;

    QueryPerformanceCounter(&offset);

    return (unsigned long) (offset.QuadPart);
}
#endif /* !HAVE_HARDCLOCK && _WIN32 && !EFIX64 && !EFI32 */

#if !defined(HAVE_HARDCLOCK)

#define HAVE_HARDCLOCK

static int hardclock_init = 0;
static struct timeval tv_init;

static unsigned long mbedtls_timing_hardclock(void)
{
    struct timeval tv_cur;

    if (hardclock_init == 0) {
        gettimeofday(&tv_init, NULL);
        hardclock_init = 1;
    }

    gettimeofday(&tv_cur, NULL);
    return (tv_cur.tv_sec  - tv_init.tv_sec) * 1000000U
           + (tv_cur.tv_usec - tv_init.tv_usec);
}
#endif /* !HAVE_HARDCLOCK */

volatile int mbedtls_timing_alarmed = 0;

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

/* It's OK to use a global because alarm() is supposed to be global anyway */
static DWORD alarmMs;

static void TimerProc(void *TimerContext)
{
    (void) TimerContext;
    Sleep(alarmMs);
    mbedtls_timing_alarmed = 1;
    /* _endthread will be called implicitly on return
     * That ensures execution of thread function's epilogue */
}

static void mbedtls_set_alarm(int seconds)
{
    if (seconds == 0) {
        /* No need to create a thread for this simple case.
         * Also, this shorcut is more reliable at least on MinGW32 */
        mbedtls_timing_alarmed = 1;
        return;
    }

    mbedtls_timing_alarmed = 0;
    alarmMs = seconds * 1000;
    (void) _beginthread(TimerProc, 0, NULL);
}

#else /* _WIN32 && !EFIX64 && !EFI32 */

static void sighandler(int signum)
{
    mbedtls_timing_alarmed = 1;
    signal(signum, sighandler);
}

static void mbedtls_set_alarm(int seconds)
{
    mbedtls_timing_alarmed = 0;
    signal(SIGALRM, sighandler);
    alarm(seconds);
    if (seconds == 0) {
        /* alarm(0) cancelled any previous pending alarm, but the
           handler won't fire, so raise the flag straight away. */
        mbedtls_timing_alarmed = 1;
    }
}

#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !MBEDTLS_TIMING_ALT */

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL) {
        rng_state  = NULL;
    }

    while (len > 0) {
        use_len = len;
        if (use_len > sizeof(int)) {
            use_len = sizeof(int);
        }

        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

#define CHECK_AND_CONTINUE(R)                                         \
    {                                                                   \
        int CHECK_AND_CONTINUE_ret = (R);                             \
        if (CHECK_AND_CONTINUE_ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED) { \
            mbedtls_printf("Feature not supported. Skipping.\n");     \
            continue;                                                   \
        }                                                               \
        else if (CHECK_AND_CONTINUE_ret != 0) {                        \
            mbedtls_exit(1);                                          \
        }                                                               \
    }

#if defined(MBEDTLS_ECP_C)
static int set_ecp_curve(const char *string, mbedtls_ecp_curve_info *curve)
{
    const mbedtls_ecp_curve_info *found =
        mbedtls_ecp_curve_info_from_name(string);
    if (found != NULL) {
        *curve = *found;
        return 1;
    } else {
        return 0;
    }
}
#endif



typedef struct {
    char md5, ripemd160, sha1, sha256, sha512,
         sha3_224, sha3_256, sha3_384, sha3_512,
         des3, des,
         aes_cbc, aes_cfb128, aes_cfb8, aes_ctr, aes_gcm, aes_ccm, aes_xts, chachapoly,
         aes_cmac, des3_cmac,
         aria, camellia, chacha20,
         poly1305,
         ctr_drbg, hmac_drbg,
         rsa, dhm, ecdsa, ecdh;
} todo_list;




int test_bench(void)
{
    int i;
    size_t j;
    char title[TITLE_LEN];
    todo_list todo;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[HEAP_SIZE] = { 0 };
#endif
#if defined(MBEDTLS_ECP_C)
    mbedtls_ecp_curve_info single_curve[2] = {
        { MBEDTLS_ECP_DP_NONE, 0, 0, NULL },
        { MBEDTLS_ECP_DP_NONE, 0, 0, NULL },
    };
    const mbedtls_ecp_curve_info *curve_list = mbedtls_ecp_curve_list();
#endif

#if defined(MBEDTLS_ECP_C)
    (void) curve_list; /* Unused in some configurations where no benchmark uses ECC */
#endif
    
    memset(&todo, 0, sizeof(todo));
    //todo.sha512 = 1;
    //todo.des = 1;
    //todo.chacha20 = 1;
    //todo.aes_cbc = 1;
    //todo.poly1305 = 1;
    //todo.sha256 = 1;
    //todo.sha3_256 = 1;
    //todo.sha3_512 = 1;
    //todo.camellia = 1;
    todo.hmac_drbg = 1;
    //todo.rsa = 1;
    //todo.aria = 1;
    //todo.ripemd160 = 1;
    //todo.chachapoly = 1;

    mbedtls_printf("\n");

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif
    
    

    /* Avoid "unused static function" warning in configurations without
     * symmetric crypto. */




#if defined(MBEDTLS_SHA256_C)
    if (todo.sha256) {
    TIME_AND_TSC("SHA-256", mbedtls_sha256(buftest, BUFSIZE, tmptest, 0));
    }
#endif

#if defined(MBEDTLS_SHA512_C)
    if (todo.sha512) {
        TIME_AND_TSC("SHA-512", mbedtls_sha512(buftest, BUFSIZE, tmptest, 0));
    }
#endif

#if defined(MBEDTLS_SHA3_C)
    if (todo.sha3_224) {
        TIME_AND_TSC("SHA3-224", mbedtls_sha3(MBEDTLS_SHA3_224, buftest, BUFSIZE, tmptest, 28));
    }
    if (todo.sha3_256) {
        TIME_AND_TSC("SHA3-256", mbedtls_sha3(MBEDTLS_SHA3_256, buftest, BUFSIZE, tmptest, 32));
    }
    if (todo.sha3_384) {
        TIME_AND_TSC("SHA3-384", mbedtls_sha3(MBEDTLS_SHA3_384, buftest, BUFSIZE, tmptest, 48));
    }
    if (todo.sha3_512) {
        TIME_AND_TSC("SHA3-512", mbedtls_sha3(MBEDTLS_SHA3_512, buftest, BUFSIZE, tmptest, 64));
    }
#endif

#if defined(MBEDTLS_RIPEMD160_C)
    if (todo.ripemd160) {
        TIME_AND_TSC("RIPEMD160", mbedtls_ripemd160(buftest, BUFSIZE, tmptest));
    }
#endif


#if defined(MBEDTLS_DES_C)
#if defined(MBEDTLS_CIPHER_MODE_CBC)

    if (todo.des) {
        mbedtls_des_context des;

        mbedtls_des_init(&des);
        if (mbedtls_des_setkey_enc(&des, tmptest) != 0) {
            mbedtls_exit(1);
        }
        TIME_AND_TSC("DES",
                     mbedtls_des_crypt_cbc(&des, MBEDTLS_DES_ENCRYPT, BUFSIZE, tmptest, buftest, buftest));
        mbedtls_des_free(&des);
    }

#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_DES_C */



#if defined(MBEDTLS_CHACHA20_C)
    if (todo.chacha20) {
        TIME_AND_TSC("ChaCha20", mbedtls_chacha20_crypt(buftest, buftest, 0U, BUFSIZE, buftest, buftest));
    }
#endif

#if defined(MBEDTLS_POLY1305_C)
    if (todo.poly1305) {
        TIME_AND_TSC("Poly1305", mbedtls_poly1305_mac(buftest, buftest, BUFSIZE, buftest));
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.aes_cbc) {
        int keysize;
        mbedtls_aes_context aes;

        mbedtls_aes_init(&aes);
        for (keysize = 128; keysize <= 128; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "AES-CBC-%d", keysize);

            memset(buftest, 0, sizeof(buftest));
            memset(tmptest, 0, sizeof(tmptest));
            CHECK_AND_CONTINUE(mbedtls_aes_setkey_enc(&aes, tmptest, keysize));

            TIME_AND_TSC(title,
                         mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, BUFSIZE, tmptest, buftest, buftest));
        }
        mbedtls_aes_free(&aes);
    }
#endif

#if defined(MBEDTLS_CAMELLIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.camellia) {
        int keysize;
        mbedtls_camellia_context camellia;

        mbedtls_camellia_init(&camellia);
        for (keysize = 256; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "CAMELLIA-CBC-%d", keysize);

            memset(buftest, 0, sizeof(buftest));
            memset(tmptest, 0, sizeof(tmptest));
            mbedtls_camellia_setkey_enc(&camellia, tmptest, keysize);

            TIME_AND_TSC(title,
                         mbedtls_camellia_crypt_cbc(&camellia, MBEDTLS_CAMELLIA_ENCRYPT,
                                                    BUFSIZE, tmptest, buftest, buftest));
        }
        mbedtls_camellia_free(&camellia);
    }
#endif


#if defined(MBEDTLS_HMAC_DRBG_C) && \
    (defined(MBEDTLS_SHA1_C) || defined(MBEDTLS_SHA256_C))
    if (todo.hmac_drbg) {
        mbedtls_hmac_drbg_context hmac_drbg;
        const mbedtls_md_info_t *md_info;

        mbedtls_hmac_drbg_init(&hmac_drbg);

#if defined(MBEDTLS_SHA1_C)
        if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1)) == NULL) {
            mbedtls_exit(1);
        }

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }
        TIME_AND_TSC("HMAC_DRBG SHA-1 (NOPR)",
                     mbedtls_hmac_drbg_random(&hmac_drbg, buftest, BUFSIZE));

        if (mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0) != 0) {
            mbedtls_exit(1);
        }

#endif
        mbedtls_hmac_drbg_free(&hmac_drbg);
    }
#endif /* MBEDTLS_HMAC_DRBG_C && ( MBEDTLS_SHA1_C || MBEDTLS_SHA256_C ) */

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if (todo.rsa) {
        int keysize;
        mbedtls_rsa_context rsa;

        for (keysize = 2048; keysize <= 2048; keysize += 1024) {
            mbedtls_snprintf(title, sizeof(title), "RSA-%d", keysize);

            mbedtls_rsa_init(&rsa);
            mbedtls_rsa_gen_key(&rsa, myrand, NULL, keysize, 65537);

            TIME_PUBLIC(title, " public",
                        buftest[0] = 0;
                        ret = mbedtls_rsa_public(&rsa, buftest, buftest));

            TIME_PUBLIC(title, "private",
                        buftest[0] = 0;
                        ret = mbedtls_rsa_private(&rsa, myrand, NULL, buftest, buftest));

            mbedtls_rsa_free(&rsa);
        }
    }
#endif

#if defined(MBEDTLS_ARIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (todo.aria) {
        int keysize;
        mbedtls_aria_context aria;

        mbedtls_aria_init(&aria);
        for (keysize = 256; keysize <= 256; keysize += 64) {
            mbedtls_snprintf(title, sizeof(title), "ARIA-CBC-%d", keysize);

            memset(buftest, 0, sizeof(buftest));
            memset(tmptest, 0, sizeof(tmptest));
            mbedtls_aria_setkey_enc(&aria, tmptest, keysize);

            TIME_AND_TSC(title,
                         mbedtls_aria_crypt_cbc(&aria, MBEDTLS_ARIA_ENCRYPT,
                                                BUFSIZE, tmptest, buftest, buftest));
        }
        mbedtls_aria_free(&aria);
    }
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    if (todo.chachapoly) {
        mbedtls_chachapoly_context chachapoly;

        mbedtls_chachapoly_init(&chachapoly);
        memset(buftest, 0, sizeof(buftest));
        memset(tmptest, 0, sizeof(tmptest));

        mbedtls_snprintf(title, sizeof(title), "ChaCha20-Poly1305");

        mbedtls_chachapoly_setkey(&chachapoly, tmptest);

        TIME_AND_TSC(title,
                     mbedtls_chachapoly_encrypt_and_tag(&chachapoly,
                                                        BUFSIZE, tmptest, NULL, 0, buftest, buftest, tmptest));

        mbedtls_chachapoly_free(&chachapoly);
    }
#endif



    mbedtls_printf("\n");

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif


}

#endif /* MBEDTLS_HAVE_TIME */
