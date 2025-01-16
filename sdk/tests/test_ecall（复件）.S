#define __ASSEMBLY__
#include "domain_key.h"
#include "test_ecall.h"

GEN_ALL_SIMPLE test3                         ECALL_TEST3
GEN_ALL_SIMPLE test3_nested                  ECALL_TEST3_NESTED
GEN_ALL_SIMPLE test3_time                    ECALL_TEST3_TIME   
GEN_ALL_SIMPLE test2_nested                  ECALL_TEST2_NESTED
GEN_ALL_SIMPLE test_api_calls                ECALL_TEST_API_ID
GEN_ALL_SIMPLE test_args                     ECALL_TEST_ARGS_ID