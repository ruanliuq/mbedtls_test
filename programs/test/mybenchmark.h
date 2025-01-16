#ifndef MYBENCHMARK_H
#define MYBENCHMARK_H
#include "/home/rlq/mbedtls/include/mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include <string.h>
#include <stdlib.h>

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


#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>

#include "mbedtls/memory_buffer_alloc.h"


#include <stddef.h>  // 用于 size_t
#include <stdint.h>  // 用于 uint8_t
#include <sys/time.h>
#include <signal.h>




// 声明全局变量
extern volatile int mbedtls_timing_alarmed2;

int test_bench(void);


#endif // BENCHMARK_H

