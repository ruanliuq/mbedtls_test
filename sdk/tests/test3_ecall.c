#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "test3_ecall.h"
#include "domain_key.h"
#include "dm_debug.h"
#include "test_ecall.h"


int test2_nested(int arg){
    DEBUG_MPK("test2_nested(%d)\n", arg);
    //pk_print_current_reg();
    arg--;
    if(arg > 0){
        DEBUG_MPK("test2_nested: Calling test3_nested(%d)\n", arg);
        int ret = ecall_test3_nested(arg);
        DEBUG_MPK("test2_nested: Successfully called ecall_test3_nested(%d). return value was %d\n", arg, ret);
        assert(ret == arg - 1);
    }else{
      #ifdef DEBUG
        dm_print_debug_info();
      #endif
    }
    return arg;
}

void test3() {
    //Reading private data (should fail if not called via ecall_test3)
    uint64_t * x = (uint64_t*)&test3;
    printf("test3: %lx\n", *x);

    dm_print_current_reg();

    printf("test3: Calling test2 ecall function:\n");
    uint64_t ret = ecall_test_args(0x10, 0x11, 0x12, 0x13, 0x14, 0x15);
    printf("ecall_test_args returned %lx\n", ret);
    assert(ret == 0xAABBCCDD00112233ULL);

    printf("test3: Calling test2 ecall function which then calls api functions:\n");
    ecall_test_api_calls();
}

int test3_nested(int arg){
    DEBUG_MPK("test3_nested(%d)", arg);
    //pk_print_current_reg();
    arg--;
    if(arg > 0){
        DEBUG_MPK("test3_nested: Calling ecall_test2_nested(%d)\n", arg);
        int ret = ecall_test2_nested(arg);
        DEBUG_MPK("test3_nested: Successfully called ecall_test2_nested(%d). return value was %d\n", arg, ret);
        assert(ret == arg - 1);
    }else{
      #ifdef DEBUG
        dm_print_debug_info();
      #endif
    }
    return arg;
}

uint64_t test3_time(){
    return RDTSC();
}

void  test_simple_api2(){

}

// 自己写的参数值
uint64_t test_args(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    printf("%lx %lx %lx %lx %lx %lx\n", a, b, c, d, e, f);
    assert(a == 0x10);
    assert(b == 0x11);
    assert(c == 0x12);
    assert(d == 0x13);
    assert(e == 0x14);
    assert(f == 0x15);
    return 0xAABBCCDD00112233ULL;
}

void __attribute__((naked)) test_api_calls() {
    asm volatile (
    "addi     sp,sp,-8;"
    "sd       ra,0(sp);"
    "call     dm_print_debug_info;"
    "call     dm_print_current_reg;"
    "call     test_simple_api2;"
    "ld       ra,0(sp);"
    "addi     sp,sp,8;"
    "ret;"
    );
}
