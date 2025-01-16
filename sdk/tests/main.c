
#include "domain_key.h"
#include "syscall.h"
#include "test_ecall.h"
#include "test1_api.h"
#include "test3_ecall.h"
#include "/home/rlq/mbedtls/programs/test/mybenchmark.h"
#include "/home/rlq/mbedtls/programs/test/encryptiondata.h"
//#include "/home/rlq/mbedtls/programs/test/benchmark.h"
int poly1305_domain = 0;
int sha256_domain = 0;
int sha512_domain = 0;
int data_domain = 0;
int des_domain = 0;
int chacha20_domain = 0;
#define P_LINE() do { printf("===========================================\n"); } while (0)



//------------------------------------------------------------------------------
// Addresses of sections to be isolated
// 怎么处理？
extern uintptr_t _data_start[];
extern uintptr_t _data_end[];



extern uintptr_t _poly1305t_start[];
extern uintptr_t _poly1305t_end[];
extern uintptr_t _poly1305d_start[];
extern uintptr_t _poly1305d_end[];
extern uintptr_t _poly1305_start[];
extern uintptr_t _poly1305_end[];

extern uintptr_t _sha256t_start[];
extern uintptr_t _sha256t_end[];
extern uintptr_t _sha256d_start[];
extern uintptr_t _sha256d_end[];
extern uintptr_t _sha256_start[];
extern uintptr_t _sha256_end[];

extern uintptr_t _sha512t_start[];
extern uintptr_t _sha512t_end[];
extern uintptr_t _sha512d_start[];
extern uintptr_t _sha512d_end[];
extern uintptr_t _sha512_start[];
extern uintptr_t _sha512_end[];

extern uintptr_t _dest_start[];
extern uintptr_t _dest_end[];
extern uintptr_t _desd_start[];
extern uintptr_t _desd_end[];
extern uintptr_t _des_start[];
extern uintptr_t _des_end[];

extern uintptr_t _chacha20t_start[];
extern uintptr_t _chacha20t_end[];
extern uintptr_t _chacha20d_start[];
extern uintptr_t _chacha20d_end[];
extern uintptr_t _chacha20_start[];
extern uintptr_t _chacha20_end[];

#define SYM_SIZE(sym) (size_t)((uintptr_t)_##sym##_end - (uintptr_t)_##sym##_start)

//------------------------------------------------------------------------------

//void create_domain(){
//    P_LINE();
//    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
//    printf("data_domain = dm_domain_create(domain_flags)\n");
//    benchmark_domain = dm_domain_create(domain_flags);
//    bool ret = dm_pkey_mprotect(benchmark_domain, _benchmark_start, SYM_SIZE(benchmark), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
//    assert(ret == 0);
//   
//}


void create_data_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("data_domain = dm_domain_create(domain_flags)\n");
    data_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(data_domain, _data_start, SYM_SIZE(data), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_sha256_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("sha256_domain = dm_domain_create(domain_flags)\n");
    sha256_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(sha256_domain, _sha256_start, SYM_SIZE(sha256), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_sha512_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("sha512_domain = dm_domain_create(domain_flags)\n");
    sha512_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(sha512_domain, _sha512_start, SYM_SIZE(sha512), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_des_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("des_domain = dm_domain_create(domain_flags)\n");
    des_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(des_domain, _des_start, SYM_SIZE(des), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_chacha20_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("chacha20_domain = dm_domain_create(domain_flags)\n");
    chacha20_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(chacha20_domain, _chacha20_start, SYM_SIZE(chacha20), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_poly1305_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("poly1305_domain = dm_domain_create(domain_flags)\n");
    poly1305_domain = dm_domain_create(domain_flags);
    bool ret = dm_pkey_mprotect(poly1305_domain, _poly1305_start, SYM_SIZE(poly1305), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
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
    printf("main : local test start\n");
    fflush(stdout);
    test_bench();
    // return 0;
    printf("main : domain manager init start\n");
    fflush(stdout);

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
    printf("main : tee test start\n");
    fflush(stdout);
    create_data_domain();
    create_sha256_domain();
    create_sha512_domain();
    create_des_domain();
    create_chacha20_domain();
    create_poly1305_domain();
    test_bench();
    // Deinitialize PK

    if(domain_manager_deinit() != 0){
        ERROR_FAIL("main: domain_manager_deinit failed");
    }
    DEBUG_PRINTF("all success ,end");

    return 0;

}
