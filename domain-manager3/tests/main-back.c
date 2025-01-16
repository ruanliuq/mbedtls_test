
#include "domain_key.h"
#include "syscall.h"
#include "test_ecall.h"
#include "test1_api.h"
#include "test3_ecall.h"
#include "/home/rlq/mbedtls/programs/test/mybenchmark.h"
#include "/home/rlq/mbedtls/programs/test/encryptiondata.h"
#include <time.h>

int poly1305_domain = 0;
int sha256_domain = 0;
int sha512_domain = 0;
int data_domain = 0;
int des_domain = 0;
int chacha20_domain = 0;
#define P_LINE() do { DEBUG_PRINTF("===========================================\n"); } while (0)


UpdateBitmapParams* params[8] = {0};

void create_diff_domain(int did){
        // 定义寄存器和指令名称
    const char* csr_cycle_name = "CSR_CYCLE";
    const char* csr_instret_name = "CSR_INSTRET";
    const char* csr_pkru_name = "CSR_PKRU";
    const char* sfence_vma_name = "Sfence_vma";
    const char* mirdbu_name = "Mirdbu";

    // 权限值设置示例
    int allow = 1;  // 允许权限
    int deny = 0;   // 禁止权限

    // 初始化UpdateBitmapParams对象
    for (int i = 0; i < 8; i++) {
        params[i]->domainId = did++;  // 每个对象具有不同的域ID

        // 设置指令权限
        params[i]->instNames = (const char**)malloc(params[i]->instCount * sizeof(const char*)); // 存储指令名称
        params[i]->instValues = (int*)malloc(params[i]->instCount * sizeof(int));        // 存储对应的权限值
        params[i]->instCount = 2;

        if (i % 2 == 0) {
            params[i]->instNames[0] = sfence_vma_name;
            params[i]->instValues[0] = allow;
            params[i]->instNames[1] = mirdbu_name;
            params[i]->instValues[1] = deny;
        } else {
            params[i]->instNames[0] = mirdbu_name;
            params[i]->instValues[0] = allow;
            params[i]->instNames[1] = sfence_vma_name;
            params[i]->instValues[1] = deny;
        }

        // 设置寄存器读权限
        params[i]->regReadNames = (const char**)malloc(params[i]->regWriteCount * sizeof(const char*)); // 存储寄存器读名称
        params[i]->regReadValues = (int*)malloc(params[i]->regWriteCount * sizeof(int));        // 存储对应的权限值
        params[i]->regReadCount = 3;

        params[i]->regReadNames[0] = csr_cycle_name;
        params[i]->regReadNames[1] = csr_instret_name;
        params[i]->regReadNames[2] = csr_pkru_name;

        params[i]->regReadValues[0] = (i < 4) ? allow : deny;
        params[i]->regReadValues[1] = (i >= 4) ? allow : deny;
        params[i]->regReadValues[2] = (i % 2 == 0) ? allow : deny;

        // 设置寄存器写权限
        params[i]->regWriteNames = (const char**)malloc(params[i]->regWriteCount * sizeof(const char*)); // 存储寄存器写名称
        params[i]->regWriteValues = (int*)malloc(params[i]->regWriteCount * sizeof(int));        // 存储对应的权限值
        params[i]->regWriteCount = 3;

        params[i]->regWriteNames[0] = csr_cycle_name;
        params[i]->regWriteNames[1] = csr_instret_name;
        params[i]->regWriteNames[2] = csr_pkru_name;

        params[i]->regWriteValues[0] = (i % 2 == 0) ? allow : deny;
        params[i]->regWriteValues[1] = (i >= 4) ? allow : deny;
        params[i]->regWriteValues[2] = (i < 4) ? allow : deny;
    }

}

//------------------------------------------------------------------------------
// Addresses of sections to be isolated
// 怎么处理？


extern uintptr_t _datat_start[];
extern uintptr_t _datat_end[];
extern uintptr_t _datad_start[];
extern uintptr_t _datad_end[];
extern uintptr_t _data_start[];
extern uintptr_t _data_end[];

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

extern uintptr_t _poly1305t_start[];
extern uintptr_t _poly1305t_end[];
extern uintptr_t _poly1305d_start[];
extern uintptr_t _poly1305d_end[];
extern uintptr_t _poly1305_start[];
extern uintptr_t _poly1305_end[];

#define SYM_SIZE(sym) (size_t)((uintptr_t)_##sym##_end - (uintptr_t)_##sym##_start)

//------------------------------------------------------------------------------
    #define BILLION 1000000000L


/*

*/


void create_data_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("data_domain = dm_domain_create(domain_flags, 0)\n");
    data_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(data_domain, _data_start, SYM_SIZE(data), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_sha256_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("sha256_domain = dm_domain_create(domain_flags, 0)\n");
    sha256_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(sha256_domain, _sha256_start, SYM_SIZE(sha256), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_sha512_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("sha512_domain = dm_domain_create(domain_flags, 0)\n");
    sha512_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(sha512_domain, _sha512_start, SYM_SIZE(sha512), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_des_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("des_domain = dm_domain_create(domain_flags, 0)\n");
    des_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(des_domain, _des_start, SYM_SIZE(des), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_chacha20_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("chacha20_domain = dm_domain_create(domain_flags, 0)\n");
    chacha20_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(chacha20_domain, _chacha20_start, SYM_SIZE(chacha20), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}

void create_poly1305_domain(){
    P_LINE();
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    printf("poly1305_domain = dm_domain_create(domain_flags, 0)\n");
    poly1305_domain = dm_domain_create(domain_flags, 0);
    bool ret = dm_pkey_mprotect(poly1305_domain, _poly1305_start, SYM_SIZE(poly1305), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY);
    assert(ret == 0);
}




void test_isa(){
    struct timespec start, end;
    double elapsed, total_create = 0, total_free = 0, total_update = 0;

    P_LINE();
    DEBUG_PRINTF("Test for ISA domain, create 128 domains\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    int start_domain_id = dm_domain_create(0, 0);
    for(int i = 1; i < 128; ++i){
        int did = dm_domain_create(0, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    total_create = elapsed;
    DEBUG_PRINTF("Total time to create 128 domains: %f seconds\n", elapsed);
    DEBUG_PRINTF("Average time per domain create: %f seconds\n", elapsed / 128);

    P_LINE();
    DEBUG_PRINTF("Test for ISA domain, delete 128 domains\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < 128; ++i){
        dm_domain_free(start_domain_id++);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    total_free = elapsed;
    DEBUG_PRINTF("Total time to delete 128 domains: %f seconds\n", elapsed);
    DEBUG_PRINTF("Average time per domain delete: %f seconds\n", elapsed / 128);

    P_LINE();
    DEBUG_PRINTF("Test for ISA domain, switch domain\n");
    int new_domain_id = dm_domain_create(0, 0);
    create_diff_domain(new_domain_id);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < 8; ++i){
        int did = dm_domain_create(0, 0);
        dm_update_isaBuffer(params[i]);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    total_update = elapsed;
    DEBUG_PRINTF("Total time to update 8 ISA buffers: %f seconds\n", elapsed);
    DEBUG_PRINTF("Average time per ISA buffer update: %f seconds\n", elapsed / 8);
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
    int i=0;
    isa_open();
    //printf("main : local test start\n");
    //fflush(stdout);
    //test_bench();
    //isa_close();
    
    printf("main : domain manager init start\n");
    fflush(stdout);


    // Initialize PK


    struct timespec start, end;
    double elapsed;
    DEBUG_PRINTF("all start\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    if(domain_manager_init() != 0){
        ERROR_FAIL("main: domain_manager_init failed");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    DEBUG_PRINTF("init time: %f seconds\n", elapsed);
    
    DEBUG_PRINTF("domain manager init success\n");

    dm_print_current_reg();
    
    //TESTS();
    printf("main : tee test start\n");
    fflush(stdout);
    
    
    create_data_domain();
    //create_sha256_domain();
    
    //create_sha512_domain();
    create_des_domain();
    //create_chacha20_domain();
    //create_poly1305_domain();
    test_bench();
    // Deinitialize PK
    if(domain_manager_deinit() != 0){
        ERROR_FAIL("main: domain_manager_deinit failed");
    }
    DEBUG_PRINTF("all success ,end");
    isa_close();
    return 0;

}
