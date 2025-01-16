#pragma once

#include "domain_key.h"

// TODO ： 这些编号是如何定义的？
// RISC-V ISA规范本身并未定义具体的ecall服务编号。这些编号是由运行在RISC-V上的操作系统或运行时环境定义的。
// 例如，如果你在使用RISC-V架构的Linux系统，那么系统调用编号将由Linux内核为RISC-V架构定义。
#define ECALL_TEST3                              9
#define ECALL_TEST3_NESTED                       8
#define ECALL_TEST3_TIME                         7

#define ECALL_TEST_ARGS_ID                      10
#define ECALL_TEST_API_ID                       11
#define ECALL_TEST_KILL_ALL_REGS_ID             12
#define ECALL_TEST2_NESTED                      13

#define ECALL_PKEY_ISOLATION_CHILD_ALLOC        20
#define ECALL_PKEY_ISOLATION_CHILD_STACK        21
#define ECALL_PKEY_ISOLATION_CHILD_SUCCESS      22
#define ECALL_PKEY_ISOLATION_CHILD_FAIL         23

#define ECALL_TEST0_CHILD                       24



