#include "dm/domain_key.h"
#include "dm/syscall.h"
#include <time.h>
#include <stdio.h>
#include <stdint.h>

// #include "aes.h"                     // test1
// #include "bigint.h"               // test2
// #include "dhrystone.h"      // test3
// #include "miniz.h"               // test4
// #include "norx.h"                 // test5
// #include "primes.h"            // test6
// #include "qsort.h"               // test7
// #include "sha512.h"           // test8

//------------------------------------------------------------------------------
// Addresses of sections to be isolated
extern uintptr_t _test1_start[];
extern uintptr_t _test1_end[];
extern uintptr_t _test2_start[];
extern uintptr_t _test2_end[];

// extern uintptr_t _test3t_start[];
// extern uintptr_t _test3t_end[];
// extern uintptr_t _test3d_start[];
// extern uintptr_t _test3d_end[];
extern uintptr_t _test3_start[];
extern uintptr_t _test3_end[];

extern uintptr_t _test4_start[];
extern uintptr_t _test4_end[];
extern uintptr_t _test5_start[];
extern uintptr_t _test5_end[];
extern uintptr_t _test6_start[];
extern uintptr_t _test6_end[];
extern uintptr_t _test7_start[];
extern uintptr_t _test7_end[];
extern uintptr_t _test8_start[];
extern uintptr_t _test8_end[];
//------------------------------------------------------------------------------

#define LINE() do { printf("===========================================\n"); } while (0)

#define SYM_SIZE(sym) (size_t)((uintptr_t)_##sym##_end - (uintptr_t)_##sym##_start)

//------------------------------------------------------------------------------


//------------------------------------------------------------------------------

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

void test_isa(){
    #define BILLION 1000000000L
    struct timespec start, end;
    double elapsed, total_create = 0, total_free = 0, total_update = 0;

    LINE();
    printf("Test for ISA domain, create 256 domains\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    int start_domain_id = dm_domain_create(0, 0);
    for(int i = 1; i < 256; ++i){
        int did = dm_domain_create(0, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    total_create = elapsed;
    printf("Total time to create 256 domains: %f seconds\n", elapsed);
    printf("Average time per domain create: %f seconds\n", elapsed / 256);

    LINE();
    printf("Test for ISA domain, delete 256 domains\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < 256; ++i){
        dm_domain_free(start_domain_id++);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / (double)BILLION;
    total_free = elapsed;
    printf("Total time to delete 256 domains: %f seconds\n", elapsed);
    printf("Average time per domain delete: %f seconds\n", elapsed / 256);

    LINE();
    printf("Test for ISA domain, switch domain\n");
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
    printf("Total time to update 8 ISA buffers: %f seconds\n", elapsed);
    printf("Average time per ISA buffer update: %f seconds\n", elapsed / 8);
}  

//------------------------------------------------------------------------------
#include "test_list.h"
#include <string.h>

int test2_bigint(){
    return 0;
}

// 定义测试函数数组
typedef int (*test_func)(void);
test_func tests[] = {test1_aes, test2_bigint, test3_dhrystone, test4_miniz, test5_norx, test6_primes, test7_qsort, test8_sha512};

#define RUN_TEST1(testNum) do { \
    time0 = RDTSC(); \
    int test##testNum##_domain = dm_domain_create(domain_flags, 0); \
    time1 = RDTSC(); \
    bool ret##testNum = dm_pkey_mprotect(test##testNum##_domain, _test##testNum##_start, SYM_SIZE(test##testNum), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY); \
    time2 = RDTSC(); \
    assert(ret##testNum == 0); \
    tests[0](); \
    time3 = RDTSC(); \
    DEBUG_PRINTF("test 1 end"); \
    fp = fopen(filename, "w"); \
    if (fp == NULL) { \
        perror("Failed to open file"); \
        return 1; \
    } \
    fprintf(fp, "%lu\n%lu\n%lu\n%lu\n", time0, time1, time2, time3); \
    fprintf(fp, "\n"); \
    fclose(fp); \
} while (0)

#define RUN_TEST(testNum) do { \
    DEBUG_PRINTF("test start"); \
    time0 = RDTSC(); \
    int test##testNum##_domain = dm_domain_create(domain_flags, 0); \
    time1 = RDTSC(); \
    bool ret##testNum = dm_pkey_mprotect(test##testNum##_domain, _test##testNum##_start, SYM_SIZE(test##testNum), PROT_EXEC | PROT_READ | PROT_WRITE, GET_DEFAULT_VKEY); \
    time2 = RDTSC(); \
    assert(ret##testNum == 0); \
    tests[testNum-1](); \
    time3 = RDTSC(); \
    DEBUG_PRINTF("test end"); \
    fp = fopen(filename, "a"); \
    if (fp == NULL) { \
        perror("Failed to open file"); \
        return 1; \
    } \
    fprintf(fp, "Write Count: %d\n", ++count); \
    fprintf(fp, "%lu\n%lu\n%lu\n%lu\n", time0, time1, time2, time3); \
    fprintf(fp, "\n"); \
    fclose(fp); \
} while (0)

void test_rv8(){
    int domain_flags = PK_INHERIT_KEY | PK_COPY_KEY;
    LINE();
    DEBUG_PRINTF("Testing simple API call\n");
    int res = test_simple_api(1,2,3,4,5,6);
    assert(res == (1+2+3+4+5+6));
    LINE();

    uint64_t time0;    // before create
    uint64_t time1;    // after create before mprotect
    uint64_t time2;    //  after mprotect before call
    uint64_t time3;    //  after call
    int count = 0;

    FILE *fp;
    const char *filename = "output.txt";

    RUN_TEST1(1);
    // RUN_TEST(2);
    RUN_TEST(3);
    RUN_TEST(4);
    // RUN_TEST(5);
    RUN_TEST(6);
    // RUN_TEST(7);
    RUN_TEST(8);

    return;
}

void local_test_rv8(){
    int count = 0;
    const char *filename = "local_output.txt";

    uint64_t time0, time1;
    FILE *fp;
    // 依次运行测试函数
    for (int i = 0; i < 8; i++) {
        if(i+1 == 2 || i+1 == 5 || i+1 == 7)
            continue;
        DEBUG_PRINTF("Test %d start", i + 1);
        time0 = RDTSC();
        tests[i]();
        time1 = RDTSC();
        DEBUG_PRINTF("Test %d end", i + 1);

        // 打开文件并追加写入时间戳
        fp = fopen(filename, "a");
        if (fp == NULL) {
            perror("Failed to open file");
            return;
        }
        // 记录写入次数和时间戳
        fprintf(fp, "Write Count: %d\n", ++count);
        fprintf(fp, "%lu\n%lu\n", time0, time1);
        fprintf(fp, "\n");
        // 关闭文件
        fclose(fp);
    }
}

//------------------------------------------------------------------------------

int main(){

    isa_close();
    printf("main : local test start\n");
    fflush(stdout);
    local_test_rv8();

    printf("main : domain manager init start\n");
    fflush(stdout);
    
    isa_open();
    // Initialize PK
    if(domain_manager_init() != 0){
        ERROR_FAIL("main: domain_manager_init failed");
    }

    DEBUG_PRINTF("domain manager init success\n");

    dm_print_current_reg();
    
    // setup_domains();
    test_rv8();

    // Deinitialize PK
    if(domain_manager_deinit() != 0){
        ERROR_FAIL("main: domain_manager_deinit failed");
    }
    DEBUG_PRINTF("all success ,end");

}
