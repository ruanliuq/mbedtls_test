#pragma once

#include "test_ecall.h"

#ifndef __ASSEMBLY__

#include <stdint.h>
#include <domain_key.h>

extern void ecall_test3(void);
extern int  ecall_register_test3(int did);

extern int  ecall_test3_nested(int arg);
extern int  ecall_register_test3_nested(int did);

extern uint64_t ecall_test3_time();
extern int      ecall_register_test3_time(int did);

extern int  ecall_register_test2_nested(int arg);
extern int      ecall_test2_nested(int);

extern void ecall_register_test_api_calls(int did);
extern void     ecall_test_api_calls(void);

extern void ecall_register_test_args(int did);
extern uint64_t ecall_test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f);

void       test_simple_api2(void);
#endif // __ASSEMBLY__