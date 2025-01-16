
#include "domain_key.h"
#include "syscall.h"
#include "test_ecall.h"
#include "test1_api.h"
#include "test3_ecall.h"
#include "/home/rlq/mbedtls/programs/test/mybenchmark.h"
int test3_domain = 0;
int test2_domain = 0;
#define P_LINE() do { printf("===========================================\n"); } while (0)



//------------------------------------------------------------------------------
// Addresses of sections to be isolated
// 怎么处理？
extern uintptr_t _test2_start[];
extern uintptr_t _test2_end[];

extern uintptr_t _test3t_start[];
extern uintptr_t _test3t_end[];
extern uintptr_t _test3d_start[];
extern uintptr_t _test3d_end[];
extern uintptr_t _test3_start[];
extern uintptr_t _test3_end[];

#define SYM_SIZE(sym) (size_t)((uintptr_t)_##sym##_end - (uintptr_t)_##sym##_start)

//------------------------------------------------------------------------------

void TESTS() {
    P_LINE();
    printf("Testing simple API call\n");
    // test_simple_api 返回给hello?
    int res = test_simple_api(3,4,5);
    assert(res == (3+4+5));

    P_LINE();
    printf("START of test1 API\n");
    test1_api(); // This test must be before any other test allocating keys
    printf("END of test1 API\n");

    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY; //This is necessary because bench() calls some test2 function directly without an ecall. otherwise this would lead to a key mismatch fault and we'd die.
    
    printf("test2_domain = dm_domain_create(domain_flags)\n");
    test2_domain = dm_domain_create(domain_flags);
#ifndef SHARED
    bool ret = dm_pkey_mprotect(test2_domain, _test2_start, SYM_SIZE(test2), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
#endif
    // ecall_register_test2(test2_domain);

    printf("test3_domain = dm_domain_create(domain_flags)\n");
    test3_domain = dm_domain_create(domain_flags);
    #ifndef SHARED
    #ifdef PROXYKERNEL
        // Proxy kernel has some mmap issues, so let's just use a single mapping for code+data which allows r+w+x
        ret = dm_pkey_mprotect2(test3_domain, _test3_start, SYM_SIZE(test3), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
        assert(ret == 0);
    #else /* PROXYKERNEL */
        printf("dm_pkey_mprotect\n");
        ret = dm_pkey_mprotect(test3_domain, _test3t_start, SYM_SIZE(test3t), PROT_EXEC | PROT_READ, GET_DEFAULT_VKEY);
        assert(ret == 0);
        printf("dm_pkey_mprotect\n");
        ret = dm_pkey_mprotect(test3_domain, _test3d_start, SYM_SIZE(test3d), PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
        assert(ret == 0);
    #endif /* PROXYKERNEL */
    #endif /* SHARED */

    //currently not necessary because root domain is allowed to do any ecall?
    //dm_domain_allow_caller2(test3_domain, dm_current_did(), 0);
    //dm_domain_allow_caller2(test2_domain, dm_current_did(), 0);

    printf("ecall_register_test3(test3_domain)\n");
    // 向manager注册一个可调用到test3_domain的门
    ecall_register_test3(test3_domain);
    printf("ecall_register_test3_time(test3_domain)\n");
    ecall_register_test3_time(test3_domain);

    printf("ecall_register_test2_nested(test2_domain)\n");
    ecall_register_test2_nested(test2_domain);
    printf("ecall_register_test3_nested(test3_domain)\n");
    ecall_register_test3_nested(test3_domain);

    //test2 and test3 need to be able to call each other
    printf("dm_domain_allow_caller2(test3_domain, test2_domain, 0)\n");
    // 允许后者调用前者
    dm_domain_allow_caller2(test3_domain, test2_domain, 0);
    printf("dm_domain_allow_caller2(test2_domain, test3_domain, 0)\n");
    dm_domain_allow_caller2(test2_domain, test3_domain, 0);

    P_LINE();

    #ifdef DEBUG
    //Print debug info after setting up domains
    dm_print_debug_info();
    #endif


    P_LINE();
    printf("Testing nested calls\n");
    ecall_test3_nested(10);
    P_LINE();
}

void run_pre_init_tests() {
  // Before initialization, all calls shall work as usual
  int ret;
  int pkey = pkey_alloc(0, 0);
  assert(pkey >= 0);
  char* mem = mmap(NULL, 2 * PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  assert(MAP_FAILED != mem);
  mem[1] = mem[0]+1;
  ret = mprotect(mem, PAGESIZE, PROT_READ | PROT_WRITE);
  assert(0 == ret);
  ret = pkey_mprotect(mem + PAGESIZE, PAGESIZE, PROT_READ | PROT_WRITE, pkey);
  assert(0 == ret);
  ret = munmap(mem, 2 * PAGESIZE);
  assert(0 == ret);
  ret = pkey_free(pkey);
  assert(0 == ret);
}

int main()
{

    dm_print_reg_arch(_read_pkru_reg());
#ifdef TIMING   //yes
    bench_preinit();
#else
    // 这个注释掉，不要
    // run_pre_init_tests();
#endif
    printf("main : domain manager init start\n");
    fflush(stdout);
    // Initialize PK
    if(domain_manager_init() != 0){
        ERROR_FAIL("main: domain_manager_init failed");
    }

    DEBUG_PRINTF("domain manager init success\n");

    dm_print_current_reg();
    
    //TESTS();
    test_bench();
    test_bench();
    test_bench();
    // Deinitialize PK

    if(domain_manager_deinit() != 0){
        ERROR_FAIL("main: domain_manager_deinit failed");
    }
    DEBUG_PRINTF("all success ,end");

    return 0;

}
