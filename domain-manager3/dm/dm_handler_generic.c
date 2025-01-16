
#define _GNU_SOURCE 1 //Needed for pthread_getattr_np and for link.h
#include <pthread.h>
#include <link.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h> // getrlimit
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
//#include "sysfilter.h"	// hooking 过滤系统调用

#include "syscall.h"
#include "dm_internal.h"
#include "domain_key.h"
// TODO   include other



//------------------------------------------------------------------------------
// Internal globals
//------------------------------------------------------------------------------



// dm_trusted_tls 保存有关当前线程保护域信息
#ifdef SHARED
__thread D_API  _dm_tls dm_trusted_tls __attribute__((aligned(PAGESIZE))) = {0,};
#else
__thread  _dm_tls dm_trusted_tls __attribute__((tls_model ("local-exec"))) __attribute__((aligned(PAGESIZE))) = {0,};
#endif
uint64_t D_DATA _dm_ttls_offset = 0;


//TODO int DM_DATA did_root;
int D_DATA did_root = -1;                          // 全局的root 域的 id ，初始化为 1
int D_DATA did_for_exception_handler = -1;
vkey_t D_DATA _vkey_counter = 1;                       // 全局的虚拟密钥数量，抵御重放攻击
_dm_data D_DATA dm_data = {0,};                    // root 域管理的全局数据结构
int D_DATA  dm_shared_pkeys[MAX_NUM_KEYS] = {0,};   // 共享密钥 List
//  TODO  pk_registered_ecalls
_dm_ecall D_DATA  domain_registered_ecalls[NUM_REGISTERED_ECALLS];

#ifdef FAKE_PKRU
D_DATA unsigned long long fake_pkru;
#endif

//------------------------------------------------------------------------------

// #include "limits.h"
// #include <sys/resource.h> // getrlimit
//  获得当前线程栈大小限制（最高为 1MB）
size_t static inline D_CODE _get_default_stack_size() {
    struct rlimit rlim;
    size_t stack_size = 0;
    if(getrlimit(RLIMIT_STACK, &rlim) != 0){
        WARNING("getrlimit failed");
        stack_size = 1024*dm_data.pagesize; // 1MB
    }else{
        stack_size = rlim.rlim_cur;
    }
    DEBUG_MPK("stack size = %zu KB", stack_size/1024);
    return stack_size;
}
//------------------------------------------------------------------------------




//------------------------------------------------------------------------------
bool static inline D_CODE check_domain_exists(int did){
	return (did > -1 && did < NUM_DOMAINS && dm_data.domains[did].used);
}
//------------------------------------------------------------------------------
bool static inline D_CODE _is_allowed_source_nocurrdid(int source_did, int target_did){
    //  TODO     assert_ifdebug
    assert(check_domain_exists(source_did));
    assert(check_domain_exists(target_did));

    // TODO    从 _find_in_array 函数直接提取的逻辑
    // allowed_source_domains ： 可以调用到我们域的数组
    int* array = dm_data.domains[target_did].allowed_source_domains;
    size_t array_count = dm_data.domains[target_did].allowed_source_domains_count;
    for (size_t i = 0; i < array_count; i++){
        if(array[i] == source_did){
            return true; // 找到了 source_did，返回 true
        }
    }
    return false; // 没有找到 source_did，返回 false
}

//------------------------------------------------------------------------------
int static inline D_CODE _get_domain_keyid_of_vkey(int did, vkey_t vkey){
    if (!check_domain_exists(did)) {
      return -1;
    }

    for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN && dm_data.domains[did].keys[KeyID].used; KeyID++){
        if (dm_data.domains[did].keys[KeyID].vkey == vkey) {
            return KeyID;
        }
    }
    return -1;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
bool static inline D_CODE _domain_owns_vkey_nocurrdid(int did, vkey_t vkey){
    assert(check_domain_exists(did));

    for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN && dm_data.domains[did].keys[KeyID].used; KeyID++){
        if (dm_data.domains[did].keys[KeyID].vkey == vkey &&
            dm_data.domains[did].keys[KeyID].owner) {
            return true;
        }
    }
    return false;
}
//------------------------------------------------------------------------------
pkey_t static inline D_CODE _get_domain_pkey(int did, vkey_t vkey){
    DEBUG_MPK("_get_domain_pkey(%d, %d)", did, vkey);
    if (!check_domain_exists(did) || VKEY_INVALID == vkey) {
      return (pkey_t)-1;
    }

    for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN && dm_data.domains[did].keys[KeyID].used; KeyID++){
        if (dm_data.domains[did].keys[KeyID].vkey == vkey) {
            return dm_data.domains[did].keys[KeyID].pkey;
        }
    }
    return (pkey_t)-1;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
vkey_t static inline D_CODE _get_default_vkey(int did){
    if (!check_domain_exists(did)) {
        ERROR("The did is invalid");
        return VKEY_INVALID;
    }

    // first slot holds default key
    if (!dm_data.domains[did].keys[0].used) {
        ERROR("Default key[0] is unused");
        return VKEY_INVALID;
    }

    if (!dm_data.domains[did].keys[0].owner) {
        ERROR("Default key[0] has no owner permission");
        return VKEY_INVALID;
    }

    assert(dm_data.domains[did].keys[0].pkey != 0);
    return dm_data.domains[did].keys[0].vkey;
}
//------------------------------------------------------------------------------


// 使用内存映射和保护来分配给定大小的栈。它还在栈的底部和顶部添加了两个保护页，以防止栈溢出和下溢。
void* D_CODE _allocate_stack(size_t stack_size) {
    DEBUG_MPK("Allocating stack with size %zu", stack_size);

    // mmap 变成了一个系统调用，但是可以使用 DLU_HOOKING/DL_HOOKING 宏定义把他变成自己定义的函数
    // 分配大小为`stack_size + 2*PAGESIZE`字节的内存区域
    // `NULL`参数意味着内核将选择内存区域的地址。`PROT_READ | PROT_WRITE`参数表示内存区域是可读和可写的。
    // `MAP_ANON | MAP_PRIVATE`参数意味着该内存区域将不受任何文件支持，并且对进程是私有的。在这种情况下，最后两个参数会被忽略。
    // 返回值是分配的堆栈的基地址
    void * stack_base = mmap(NULL, stack_size + 2*PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if(stack_base == MAP_FAILED){
        ERROR("_allocate_stack: mmap failed");
        // errno is set by mmap
        return NULL;
    }

    // stack_addr due to guard page
    // 计算堆栈的地址 （由于第一个 page 被用作保护页）
    // stack_addr 是实际上用到的 stack 的基地址
    void * stack_addr = (void*)((uintptr_t)stack_base + PAGESIZE);
    DEBUG_MPK("Allocated stack @ %p size 0x%zx", stack_addr, stack_size);

    // first guard page
    // mprotect 变成了一个系统调用，但是可以使用 DLU_HOOKING/DL_HOOKING 宏定义把他变成自己定义的函数
    // 将内存区域的第一个页面的保护更改为`PROT_NONE`，这意味着任何操作都无法访问该页面。这将创建一个保护页，
    // 如果栈指针 低于 栈地址 stack_base，则该保护页将触发分段错误。

    // 成功返回0;失败返回-1
    if(mprotect(stack_base, PAGESIZE, PROT_NONE) == -1){
        WARNING("_allocate_stack: mprotect on first guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected bottom stack guard page @ %p", stack_base);

    // second guard page
    // 再次调用`mprotect`宏，但这次将内存区域的最后一页的保护更改为`PROT_NONE`
    // 分配的内存(堆栈)的大小：stack_size + 2 * PAGESIZE
    void * stack_base2 =  (char*)stack_addr + stack_size;
    if(mprotect(stack_base2, PAGESIZE, PROT_NONE) == -1){
        WARNING("_allocate_stack: mprotect on last guard page failed");
        // we continue here
    }
    DEBUG_MPK("Protected top stack guard page @ %p", (char*)stack_addr + stack_size);

    return stack_addr;
}

//------------------------------------------------------------------------------
static inline D_CODE int _protect_user_stack(int did, _dm_thread_domain * data) {
    assert(data->user_stack_size);
    assert(data->user_stack_base);

    // Protect user stack
    DEBUG_MPK("Protect user stack for domain %d\n", did);
    int prot = PROT_WRITE | PROT_READ;
    //#ifndef PROXYKERNEL
    //prot |= PROT_GROWSDOWN;
    //#endif
    int ret = _dm_pkey_mprotect_underlocked(did, data->user_stack_base, data->user_stack_size, prot, GET_DEFAULT_VKEY);
    if(ret != 0){
        ERROR("_protect_user_stack: failed to protect user stack");
    }
    return ret;
}
//------------------------------------------------------------------------------
// wwwwwwwwwwwwwww
static inline D_CODE int dm_pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize) {
    if(dm_data.initialized){
        // 系统调用
        return pthread_attr_getstack(attr, stackaddr, stacksize);
    }

    char line[2048];
    // 这个文件包含了当前进程的内存映射信息
    FILE * fp = fopen("/proc/self/maps", "r");
    if(fp == NULL){
        ERROR_FAIL("Failed to fopen /proc/self/maps");
    }
    while (fgets(line, 2048, fp) != NULL) {
        // strstr 函数，判断每一行是否包含 "[stack]" 字符串
        // 这个字符串表示这一行是栈的内存映射, 没有就跳过
        if (strstr(line, "[stack]") == NULL)
            continue;

        DEBUG_MPK("line = %s", line);
        // strstr 函数，找到这一行中第一个 "-" 字符和第一个 " " 字符的位置，
        // 分别存储在 end1 和 end2 中，没有就报错并退出
        char * end1 = strstr(line, "-");
        char * end2 = strstr(line, " ");
        if(end1 == NULL || end2 == NULL){
            ERROR_FAIL("strstr failed.");
        }
        // 字符替换，一行就被分割为三个字符串，分别是栈的起始地址、栈的结束地址和栈的权限等信息
        *end1 = '\0';
        *end2 = '\0';

        // strtol 函数，将栈的起始地址和结束地址从十六进制字符串转换为长整数，
        // 分别存储在 number1 和 number2 中
        long int number1 = strtol(line,     NULL, 16);
        long int number2 = strtol(end1 + 1, NULL, 16);
        if(number1 == LONG_MIN || number1 == LONG_MAX){
            ERROR_FAIL("Could not parse number1.");
        }
        if(number2 == LONG_MIN || number2 == LONG_MAX){
            ERROR_FAIL("Could not parse number2.");
        }

        // 将 stackaddr 指向的位置设为 number1，表示栈的起始地址。
        // 将 stacksize 指向的位置设为 number2 - number1，表示栈的大小。栈大小 > 0
        *stackaddr = (void*)number1;
        *stacksize = (uintptr_t)number2 - (uintptr_t)number1;
        assert(*stacksize > 0);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return EINVAL;
}
//------------------------------------------------------------------------------
static inline D_CODE int _prepare_user_stack_pthread(int did, _dm_thread_domain * data) {

    size_t stacksize = 0;
    unsigned char * stackaddr = 0;

    // wwwwwwwwwwww 
    // 在我们的实际场景中，应该不是代理内核场景
    #ifdef PROXYKERNEL
        syscall(1337, &stackaddr, &stacksize);
        WARNING("stacksize = %zu", stacksize);
        assert(stackaddr >= (unsigned char *)0x70000000ULL);
        assert(stacksize >= 4096*100);
    #elif defined(FAKE_THREAD)
	    stacksize = (size_t) USER_THREAD_SIZE;
        stackaddr = (unsigned char *) USER_THREAD_STACK;
        WARNING("user stack size = %zu", stacksize);
    #else
        // 存储`线程属性`   <pthread.h>
        pthread_attr_t attr;
        // 需要: #define _GNU_SOURCE   <pthread.h>
        // pthread_getattr_np() 获取指定线程的属性，并将其存储在一个`线程属性`对象中。
        // pthread_self() 函数用于返回调用线程的线程 ID
        int s = pthread_getattr_np(pthread_self(), &attr);
        assert(s == 0);

        // 从 attr 中获取栈地址和栈大小，存储在 stackaddr 和 stacksize 中
        s = dm_pthread_attr_getstack(&attr, (void*)&stackaddr, &stacksize);
        assert(s == 0);
        DEBUG_MPK("pthread whole stack (incl. red zone): %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);

        // clip off red zone (one page)
        // http://rachid.koucha.free.fr/tech_corner/problem_of_thread_creation.html
        // 红色区域是栈的最低部分，用于检测栈溢出。
        stackaddr += PAGESIZE;
        stacksize -= PAGESIZE;

        DEBUG_MPK("pthread stack: %p-%p (len = %zu = 0x%zx)", stackaddr, stackaddr + stacksize, stacksize, stacksize);
    #endif

    data->user_stack_size = stacksize;
    data->user_stack_base = (void*)stackaddr;
    assert(data->user_stack_size);
    assert(data->user_stack_base);
    DEBUG_MPK("retrieved pthread user_stack_base %p, size %zu", data->user_stack_base, data->user_stack_size);

    // Protect user stack
    int ret = _protect_user_stack(did, data);
    assert(ret == 0);
    DEBUG_MPK("_prepare_user_stack_pthread end");
    return 0;
}
//------------------------------------------------------------------------------


// This function init-protects the currently running thread (TLS, etc)
// It must not use CURRENT_DID but only @p did
// wwwwwwwwww
int D_CODE  _dm_initialize_thread(int did, void* exception_stack){
    DEBUG_MPK("_dm_initialize_thread");
    // 如果没有定义 RELEASE 并且定义了 __riscv, 则打印当前寄存器的值
#ifndef RELEASE
#ifdef __riscv
    dm_print_current_reg();
    DEBUG_MPK("uie      = %zx", CSRR(CSR_UIE));
    DEBUG_MPK("ustatus  = %zx", CSRR(CSR_USTATUS));
    DEBUG_MPK("uepc     = %zx", CSRR(CSR_UEPC));
    DEBUG_MPK("ucause   = %zx", CSRR(CSR_UCAUSE));
    DEBUG_MPK("utval    = %zx", CSRR(CSR_UTVAL));
    DEBUG_MPK("uip      = %zx", CSRR(CSR_UIP));
    DEBUG_MPK("uscratch = %zx", CSRR(CSR_USCRATCH));
#endif
#endif

    // 初始化线程，先将线程的 current_did 设置为 无效
    dm_trusted_tls.current_did = INVALID_DID;

    // search for free tid slot
    size_t tid = 0;
    for (size_t tid = 0; tid < NUM_THREADS; tid++) {
      if (!dm_data.threads[tid]) {
        break;
      }
    }
    if (tid == NUM_THREADS) {
        return cleanup_and_exit(ENOMEM, "_dm_initialize_thread: No more threads available", 0);
    }

    // protect user stack

    // Since the new TLS  is not yet protected, we need a local copy of the thread-domain-data
    // 因为新的 TLS 还没有被保护，所以需要一个线程域数据的本地副本
    _dm_thread_domain data = {0};

    // we need to mprotect user stack before trusted TLS, since trusted TLS
    // can reside within the stack range, but has more strict permission
    // 需要先保护用户栈，再保护信任的 TLS，因为信任的 TTLS 可能在栈的范围内，但是有更严格的权限。
    int ret = _prepare_user_stack_pthread(did, &data);
    // 这里的 data->user_stack_base(0x7efdf000) 和下面的 TLS 不在一块
    if(ret != 0){
        return cleanup_and_exit(EACCES, "_dm_initialize_thread: _prepare_user_stack_pthread failed", 0);
    }

    // 向上取整，向下取整
    #define PAGEMASK (PAGESIZE-1)
    #define ROUNDUP(x) (((uintptr_t)(x) + PAGESIZE-1) & ~(uintptr_t)PAGEMASK)
    #define ROUNDDOWN(x) (((uintptr_t)(x)) & ~(uintptr_t)PAGEMASK)
    #define TCB_SIZE (0x700) // TODO: determine

    // 注意区分：TLS起始地址：GET_TLS_POINTER; TTLS起始地址：dm_trusted_tls (实际上也是 backup_user_stack)
    /* wwwwwwwwwwwwww 栈空间说明
    0x1000 = 4KB
    0x200000 = 2MB
                 ______
    0xfff       |      | ebp 栈底
                |      |   <-- static_tls_end(0x4fc000)
                |      |
                |      |   <-- ttls_end(0x4f5000),指向_dm_tls结构体的末尾
                |      |                                                 ____
                |      |   <-- ttls_start \ backup_user_stack(0x4f3000) |    
                |      |                                                |     红色页，防止栈溢出
                |      |   <-- ttls \ &dm_trusted_tls(0x4f2000)         |____
                |      |
                |      |   <-- GET_TLS_POINTER \ static_tls_start(0x4e9000) 
    0x000       |      | esp 栈顶   
    */
    DEBUG_MPK("tls:   %p", (void*)GET_TLS_POINTER);
    DEBUG_MPK("ttls:  %p", &dm_trusted_tls);
    DEBUG_MPK("TLS offset = 0x%lx (%ld)", _dm_ttls_offset, _dm_ttls_offset);
    // _dm_ttls_offset 是全局变量
    assert(_dm_ttls_offset == (uint64_t)&dm_trusted_tls.backup_user_stack - GET_TLS_POINTER);

// wwwwwwwww 增加的
#ifdef FAKE_TLS_SWAP
#ifndef SHARED
    // Determine size of static TLS and TCB
#ifdef __x86_64
    uintptr_t static_tls_size = ROUNDUP(__tls_static_end) - ROUNDDOWN(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN(GET_TLS_POINTER - static_tls_size);
    uintptr_t static_tls_end = ROUNDUP(GET_TLS_POINTER + TCB_SIZE); // TLS pointer is inbetween TLS and TCB
#else // RISC-V
    uintptr_t static_tls_size = ROUNDUP(__tls_static_end) - ROUNDDOWN(__tls_static_start);  // multiples of a page
    uintptr_t static_tls_start = ROUNDDOWN(GET_TLS_POINTER);
    uintptr_t static_tls_end = ROUNDUP(GET_TLS_POINTER + static_tls_size + TCB_SIZE);
#endif /* __x86_64 / RISC-V */
    DEBUG_MPK("static tls size:  0x%lx\n", static_tls_size);
    DEBUG_MPK("static tls start: 0x%lx", static_tls_start);
    DEBUG_MPK("       tls end:   0x%lx", static_tls_end);
    // TTLS的地址需要被包含在静态TLS地址里
    assert((uintptr_t)&dm_trusted_tls >= static_tls_start && (uintptr_t)&dm_trusted_tls <= (uintptr_t)static_tls_end);

    // Unprotect TLS such that one thread can access it in all domains
    // 取消对TLS的保护，这样一个线程可以在所有域中访问它，页面权限可读可写，页面密钥：0(所有域都有权)
    //Note: PKEY_MPROTECT doesn't track memory. (nobody can claim it)
    ret = pkey_mprotect((void*)static_tls_start, static_tls_end - static_tls_start, PROT_WRITE | PROT_READ, KEY_FOR_UNPROTECTED);
    if(ret != 0){
        ERROR_FAIL("_dm_initialize_thread: pkey_mprotect failed");
        return ret;
    }

#else // SHARED
    // If shared, TLS is not located in user stack which we just protected
    // So there is no need to unprotect it
    // 如果是共享的，TLS不位于我们刚刚保护的用户栈中,不需要取消保护
#endif // !SHARED
#else // FAKE_TLS_SWAP
    ERROR_FAIL("Implement me");
    // TODO: implement TLS swap (fs for x86, tp for RISC-V)
    // TODO: protect user TLS
#endif // FAKE_TLS_SWAP

    // protect trusted TLS
    uintptr_t ttls_start = (uintptr_t)&dm_trusted_tls.backup_user_stack;
    uintptr_t ttls_end  = (uintptr_t)(&dm_trusted_tls+1);   // dm_trusted_tls 是一个结构体，ttls_end指向结构体的末尾
// TODO 
//#ifdef TLS_MISALIGNMENT_BUG
    DEBUG_MPK("Misaligned TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
    ttls_start = ROUNDUP(ttls_start);
    // -2 : 按照 RISC-V 规范，堆栈需要 128 位对齐
    ttls_end = ROUNDDOWN(ttls_end-2);  // We need to misalign it from a page boundary, otherwise compiler will optimize ROUNDDOWN away
//#endif
    DEBUG_MPK("protecting TTLS from %p to %p", (void*)ttls_start, (void*)ttls_end);
    // TTLS 只有异常处理程序才能访问
    // TODO  KEY_FOR_EXCEPTION_HANDLER   ==>   KEY_FOR_ROOT_DOMAIN
    ret = _dm_pkey_mprotect_underlocked(DID_FOR_EXCEPTION_HANDLER, (void*)ttls_start, ttls_end - ttls_start, PROT_WRITE | PROT_READ, KEY_FOR_EXCEPTION_HANDLER);
    if(ret != 0) {
        ERROR("_dm_initialize_thread: _dm_pkey_mprotect_underlocked failed");
        return ret; // Similarly, return the error code from _dm_pkey_mprotect_underlocked.
    }

    // initialize trusted TLS
    DEBUG_MPK("_dm_initialize_thread : initialize trusted TLS");
    dm_data.threads[tid] = &dm_trusted_tls;
    dm_trusted_tls.tid = tid;
    dm_trusted_tls.thread_domain_data[did] = data; // pthread_self() 栈信息,初始化时,did为root
    dm_trusted_tls.current_did = did; // Now we can use CURRENT_DID ?????????????????????
    dm_trusted_tls.init = true;
    DEBUG_MPK("_dm_initialize_thread : assert did, init must be zero");
    assert(did == CURRENT_DID);

    // architecture-specific per-thread code
    _dm_setup_exception_stack_arch(exception_stack);
    _dm_setup_exception_handler_arch();
    DEBUG_MPK("_dm_initialize_thread end\n");

    return 0;
}


//------------------------------------------------------------------------------
// wwwwwwww
bool static inline D_CODE  _memory_overlaps(void* addr1, size_t len1, void* addr2, size_t len2) {
    return ((uintptr_t)addr1 < (uintptr_t)addr2 + len2) &&
          ((uintptr_t)addr2 < (uintptr_t)addr1 + len1);
}
//------------------------------------------------------------------------------
// wwwwwwww
// addr1 在 [addr2,addr2+len2)之间
bool static inline D_CODE _address_overlaps(void* addr1, void* addr2, size_t len2) {
    return (char*)addr1 >= (char*)addr2 && 
          (char*)addr1 < (char*)addr2 + len2;
}
//-------------------------------------------------------------------------------
/**
 * Unassigned memory can be owned by anyone. 
 * TODO: root domain needs to mprotect all shared libs to get their memory
 * tracked and assigned a key (0). Thus, only root domain can own it.
 */
bool static inline D_CODE _domain_owns_memory(int did, void * addr, size_t len) {
    DEBUG_MPK("_domain_owns_memory(%d, %p, %zu)", did, addr, len);
    if (did == DID_FOR_EXCEPTION_HANDLER) {
        return true;
    }
    if (!check_domain_exists(did)) {
        return false;
    }
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        // 实际上就是要满足 ranges[rid].used
        if (!dm_data.ranges[rid].used) {
          continue;
        }
        if (!_domain_owns_vkey_nocurrdid(did, dm_data.ranges[rid].vkey)) {
            // 如果域不拥有该内存区域的 owner 权限，则检查是否有重叠，如果有重叠，则出错，
            // 因为 域不拥有 这一块内存(dm_data.ranges[rid].addr , dm_data.ranges[rid].len)的 vkey，而(addr,len)和这一块内存区域有重叠
            // 那么 域对(addr,len)也没有 owner 权限
            // Domain does not own vkey of this memory range
            // Check that it does not overlap
            // DEBUG_MPK("Found foreign vkey on range: %p-%p, %zu", dm_data.ranges[rid].addr, (char*)dm_data.ranges[rid].addr+dm_data.ranges[rid].len, dm_data.ranges[rid].len);
            if (_memory_overlaps(addr, len, dm_data.ranges[rid].addr, dm_data.ranges[rid].len)) {
                DEBUG_MPK("overlap");
                return false;
            }
            DEBUG_MPK("no overlap");
        }
    }
    return true;
}

//------------------------------------------------------------------------------
bool static inline D_CODE _domain_has_vkey_nocurrdid(int did, vkey_t vkey){
    // assert_ifdebug(check_domain_exists(did));
    assert(check_domain_exists(did));
    for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN; KeyID++){
        if (dm_data.domains[did].keys[KeyID].used &&
            dm_data.domains[did].keys[KeyID].vkey == vkey) {
            return true;
        }
    }
    return false;
}
//-------------------------------------------------------------------------------

// returns -1 on error
vkey_t static inline D_CODE _vkey_for_address_nocurrdid(int did, void * addr) {
    DEBUG_MPK("_vkey_for_address (%d, %p)", did, addr);
    //  TODO   assert_ifdebug
    assert(check_domain_exists(did));
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!dm_data.ranges[rid].used) {
          continue;
        }
        vkey_t vkey = dm_data.ranges[rid].vkey;
        //  TODO   assert_ifdebug
        assert(VKEY_INVALID != vkey);
        if (_domain_has_vkey_nocurrdid(did, vkey)) {
            // Domain has key of this memory range
            // Check that it overlaps
            DEBUG_MPK("Testing vkey on range: %p-%p, %zu", dm_data.ranges[rid].addr, (char*)dm_data.ranges[rid].addr+dm_data.ranges[rid].len, dm_data.ranges[rid].len);
            if (_address_overlaps(addr, dm_data.ranges[rid].addr, dm_data.ranges[rid].len)) {
                DEBUG_MPK("Found vkey for requested range: %d", vkey);
                return vkey;
            }
            DEBUG_MPK("no overlap");
        }
    }
    return VKEY_INVALID;
}
//------------------------------------------------------------------------------




//------------------------------------------------------------------------------
void* D_CODE  _dm_setup_thread_exception_stack(){
    DEBUG_MPK("_dm_setup_thread_exception_stack");

    // protect exception handler stack for this thread
    DEBUG_MPK("Allocating exception stack");
    void * exception_stack = _allocate_stack(EXCEPTION_STACK_WORDS * WORDSIZE);
    if (!exception_stack) {
      DEBUG_MPK("_dm_setup_thread_exception_stack failed to allocate stack");
      return NULL;
    }
    DEBUG_MPK("Protecting exception stack");
    int ret = _dm_pkey_mprotect_underlocked(DID_FOR_EXCEPTION_HANDLER, exception_stack, EXCEPTION_STACK_WORDS * WORDSIZE, PROT_WRITE | PROT_READ, GET_DEFAULT_VKEY);
    assert(ret == 0);
    return exception_stack;
}
//------------------------------------------------------------------------------




//------------------------------------------------------------------------------
// init  _dm_data._dm_domain
int D_CODE _dm_domain_create_underlocked(unsigned int flags, unsigned int isa_set){

	DEBUG_MPK("_dm_domain_create start");

	if (flags & ~(PK_SHARED_KEY | PK_INHERIT_KEY | PK_COPY_KEY | PK_OWNER_KEY)){
        return cleanup_and_exit(EINVAL, "_dm_domain_create: Invalid flags", 0);
	}
	if (flags & (PK_COPY_KEY | PK_OWNER_KEY) &&
		!(flags & PK_INHERIT_KEY)){
        return cleanup_and_exit(EINVAL, "_dm_domain_create: PK_COPY_KEY | PK_OWNER_KEY \
        are only allowed in combination with PK_INHERIT_KEY", 0);
	}

	// allocate domain (did)
	int did = -1;
	for (int d = 0; d < NUM_DOMAINS; d++) {
		if(!dm_data.domains[d].used) {
			did = d;
			break;
		}
	}
	if (did == -1) {
        return cleanup_and_exit(ENOMEM, "_dm_domain_create could not allocate domain", 0);
	}

	_dm_domain * new_domain = &(dm_data.domains[did]);
	new_domain->used = true;
    
    int parent_did = -1;
	// remember who created the domain
	if ( dm_trusted_tls.init ) {
		if(parent_did >= 0){
            int child_num_ = dm_data.domains[parent_did].child_num;
            dm_data.domains[parent_did].child[child_num_] = did;
            dm_data.domains[parent_did].child_num = dm_data.domains[parent_did].child_num + 1;
        }
	} else {
		parent_did = INVALID_DID;
	}
    new_domain->parent_did = parent_did;

	// Allocate domain's default key
	vkey_t vkey = _dm_pkey_alloc_underlocked(did, flags & PK_SHARED_KEY, 0);
    // assert_ifdebug(vkey == KEY_FOR_EXCEPTION_HANDLER || did != DID_FOR_EXCEPTION_HANDLER);
    pkey_t pkey = _get_domain_pkey(did, vkey);
	if(pkey < 0){
		ERROR("_dm_domain_create could not allocate vkey");
		new_domain->used = false;
	    memset(new_domain, 0, sizeof(*new_domain));
	    return -1;
	}

    // 如果新建的m域是root或异常处理域，则将isa_did设置为0, 否则需要申请创建新ISA_did
    if(did == DID_FOR_ROOT_DOMAIN){
        new_domain->isa_did = 0;
        new_domain->can_update_isa = true;
    }
    else if(did == DID_FOR_EXCEPTION_HANDLER){
        new_domain->isa_did = 0;
        new_domain->can_update_isa = true;
    }
    else{
        new_domain->can_update_isa = false;
        if(isa_set & ISA_CANNOT_UPDATE){
            new_domain->can_update_isa = false;
        }
        
        if(isa_set & ISA_INHERIT && parent_did >= 0){
            new_domain->isa_did = dm_data.domains[parent_did].isa_did;
            //new_domain->can_update_isa = true;
            new_domain->is_inherit = true;
        }
        else{
            int isa_did_ = isa_create_new_did();
            if(isa_did_ <=0 || isa_did_ >= NUM_ISA){
                ERROR("can not create more isa domain");
                assert(false);
            }
            new_domain->isa_did = isa_did_;
            new_domain->is_inherit = false;
        }
    }
    // debug printf
    DEBUG_PRINTF("Create ISA %d and bind to memory domain %d", new_domain->isa_did, did);

	// Do arch-specific domain setup
    // set "_dm_domain.pkru_config_t default_config"
	_dm_setup_domain_arch(did, pkey);

#ifdef SHARED   // TODO 修改或者删除
    // Give read-only access to certain pk data needed for, e.g.:
    // dl_iterate_phdr (c++ exception handling, libc destructors, etc.
    // This needs to access .plt and likewise
    if (rokey_for_exception_handler != VKEY_INVALID) {
        ret = _pk_domain_assign_pkey_unlocked(DID_FOR_EXCEPTION_HANDLER, did, rokey_for_exception_handler, PK_KEY_COPY, PKEY_DISABLE_WRITE);
        if (0 != ret) {
            ERROR("_dm_create_domain_simple could not assign read-only key");
            // errno is set by _pk_domain_assign_pkey_unlocked
            assert(pkey >= 0 && pkey < MAX_NUM_KEYS);
            if (0 != pkey_free(pkey)) {
                WARNING("Unable to free protection key! Ignoring.");
            }
            memset(new_domain, 0, sizeof(*new_domain));
            return -1;
        }
    }
#endif

    // Inherit default key if requested
    if (flags & PK_INHERIT_KEY) {
        int ret = _dm_domain_assign_pkey_underlocked(did, CURRENT_DID, vkey, flags & (PK_COPY_KEY | PK_OWNER_KEY), 0);
        if (0 != ret) {
            assert(pkey >= 0 && pkey < MAX_NUM_KEYS);
            if (0 != pkey_free(pkey)) {
                WARNING("Unable to free protection key! Ignoring.");
            }
            memset(new_domain, 0, sizeof(*new_domain));
            return -1;
        }
    }
	DEBUG_MPK("_dm_domain_create end");
    // debug printf

	return did;
}
//------------------------------------------------------------------------------
// 处理一块内存区域的取消跟踪（untracking），
// 考虑到与其他已跟踪的内存区域可能存在的重叠情况。
// 如果新给定的内存区域与已跟踪的内存区域重叠，
// 函数将对已存在的内存跟踪信息进行相应的调整，这包括完全删除、截断或分割已跟踪的内存区域。
bool D_CODE _untrack_memory(void *addr, size_t len) {
    
    DEBUG_MPK("_untrack_memory(%p, %zu)", addr, len);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);
    // 用于存储可能被分割的旧的内存区域的尾部信息，初始值为未使用
    mprotect_t splittail = { .used = false };
    // 用于存储分割后的尾部信息的 rid
    size_t split_rid = SIZE_MAX;

    // truncate/split potential overlapping ranges
    // 遍历 pk_data.ranges 数组，寻找与新的内存区域[addr,len]重叠的旧的内存区域 ranges 里面的
    // 分为四种情况：示意图如下（O 和 N 表示旧区域和新区域）; 
    // 注意：新内存区域代表[addr,len]，旧内存区域代表 ranges[] 里面存储的原始值，存储内存区域 代表 ranges[] 里面存储的新值
    // 1. 如果 ranges[rid] 的起始地址和终止地址都在新区域里面，则把 旧区域删除
    // 2. 如果 ranges[rid] 的起始地址在新区域里面,终止地址不在新区域里面，则把 新内存区域的终止地址设为存储内存区域的起始地址（截断旧内存区域）
    // 3. 如果 ranges[rid] 的起始地址不在新区域里面,终止地址在新区域里面，则把 新内存区域的起始地址设为存储内存区域的结束地址
    // 4. 如果 ranges[rid] 的起始地址和终止地址都不在新区域里面(即 ranges[rid] 包含了 新区域 )
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (_memory_overlaps(addr, len, dm_data.ranges[rid].addr, dm_data.ranges[rid].len)) {
            DEBUG_MPK("memory overlaps with %p (0x%lx)", dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
            // Distinguish cases of old range (O) and new range (N)
            if (_address_overlaps(dm_data.ranges[rid].addr, addr, len)) {
                // old range-start is within delete range
                if (_address_overlaps((char*)dm_data.ranges[rid].addr+dm_data.ranges[rid].len-1, addr, len)) {
                    DEBUG_MPK("_untrack_memory: case 1: overlapping range fully covered. Deleting it");
                    // old range-end is within delete range
                    // NNNNNNNNNN
                    //     OOOO
                    // discard old range completely
                    dm_data.ranges[rid].used = 0;
                } else {
                    DEBUG_MPK("_untrack_memory: case 2: overlapping range right-overlap. Truncating it");
                    DEBUG_MPK("Original: %p (0x%zu)", dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
                    // old range-end is outside delete range
                    // NNNNNNNNNN
                    //     OOOOOOOOO
                    // truncate old range
                    //     [addr]OOO[end]  ----旧区域保留部分
                    //     OOOOOO
                    char* end = (char*)dm_data.ranges[rid].addr + dm_data.ranges[rid].len;
                    dm_data.ranges[rid].addr = (char*)addr + len;
                    assert((char*)end >= (char*)dm_data.ranges[rid].addr);
                    dm_data.ranges[rid].len = (size_t)((char*)end - (char*)dm_data.ranges[rid].addr);
                    assert((dm_data.ranges[rid].len % PAGESIZE) == 0);
                    assert(dm_data.ranges[rid].len > 0);
                    DEBUG_MPK("Truncated: %p (0x%zu)", dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
                }
            } else {    // if(_address_overlaps)
                // old range-start is outside delete range
                if (_address_overlaps((char*)dm_data.ranges[rid].addr+dm_data.ranges[rid].len-1, addr, len)) {
                    DEBUG_MPK("_untrack_memory: case 3: overlapping range left-overlap. Truncating it");
                    DEBUG_MPK("Original: %p (0x%zu)", dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
                    // old range-end is within delete range
                    //     NNNNNNNN
                    // OOOOOOOO
                    // truncate old range
                    // OOOO          ------旧区域保留部分
                    //     OOOO
                    assert((char*)addr >= (char*)dm_data.ranges[rid].addr);
                    dm_data.ranges[rid].len = (size_t)((char*)addr - (char*)dm_data.ranges[rid].addr);
                    assert((dm_data.ranges[rid].len % PAGESIZE) == 0);
                    assert(dm_data.ranges[rid].len > 0);
                    DEBUG_MPK("Truncated: %p (0x%zu)", dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
                } else {
                    DEBUG_MPK("_untrack_memory: case 4: overlapping range covers new. Splitting it");
                    // old range-end is outside delete range
                    //     NNNNNNNN
                    // OOOOOOOOOOOOOOO
                    // we have to split original range into two
                    // OOOO        OOO
                    // for this we need at least 1 free range

                    // search for a free range
                    for (split_rid = 0; split_rid < NUM_MPROTECT_RANGES; split_rid++) {
                        if (!dm_data.ranges[split_rid].used) {
                            break;
                        }
                    }
                    if (split_rid >= NUM_MPROTECT_RANGES) {
                        ERROR("_untrack_memory has too few ranges available for a split");
                        return false;
                    }
                    // Now do the split
                    // First, truncate beginning
                    // OOOO
                    assert((char*)addr >= (char*)dm_data.ranges[rid].addr);
                    char* tailend = (char*)dm_data.ranges[rid].addr + dm_data.ranges[rid].len;
                    dm_data.ranges[rid].len = (size_t)((char*)addr - (char*)dm_data.ranges[rid].addr);
                    assert((dm_data.ranges[rid].len % PAGESIZE) == 0);
                    assert(dm_data.ranges[rid].len > 0);
                    // Second, store truncated old tail in splittail for later insertion into split_rid
                    // OOOO        OOO
                    splittail.addr = (char*)addr + len;
                    assert((char*)tailend >= (char*)splittail.addr);
                    splittail.len  = (size_t)((char*)tailend - (char*)splittail.addr);
                    assert((splittail.len % PAGESIZE) == 0);
                    assert(((uintptr_t)splittail.addr % PAGESIZE) == 0);
                    splittail.prot = dm_data.ranges[rid].prot;
                    splittail.vkey = dm_data.ranges[rid].vkey;
                    splittail.pkey = dm_data.ranges[rid].pkey;
                    splittail.used = true;
                }
            }
        }
    }

    if (splittail.used) {
        // we insert split tail at the end
        assert(split_rid != SIZE_MAX);
        // 没有使用，因为没有赋值
        assert(!dm_data.ranges[split_rid].used);
        // 这里才赋值的，使用完整的赋值结构体
        dm_data.ranges[split_rid] = splittail;
    }
    //_dm_print_debug_info();
#ifdef ADDITIONAL_DEBUG_CHECKS
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (dm_data.ranges[rid].used) {
            assert(!_memory_overlaps(dm_data.ranges[rid].addr, dm_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    return true;
}
//------------------------------------------------------------------------------
// 通过 dm_data.ranges[] 数据结构来跟踪这段内存区域。即，将这段内存区域保留在 dm_data 数据结构中
// 将一段内存地址范围记录（track）下来，方便之后进行保护（如读、写权限的管理）和追踪
bool D_CODE _track_memory(void *addr, size_t len, int prot, vkey_t vkey, pkey_t pkey) {
    
    DEBUG_MPK("_track_memory(%p, %zu, %d, %d, %d)", addr, len, prot, vkey, pkey);

    assert(((uintptr_t)addr % PAGESIZE) == 0);
    assert((len % PAGESIZE) == 0);

    // count free ranges
    // 需要两个 free ranges
    int FreeRidsRequired = 2;
    int FreeRids = 0;
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!dm_data.ranges[rid].used) {
            FreeRids++;
            if(FreeRids >= FreeRidsRequired){
                break;
            }
        }
    }

    if (FreeRids < FreeRidsRequired) {
        ERROR("_track_memory has too few ranges available for a potential split");
        return false;
    }

    // truncate existing memory that overlaps with new range
    // 这里只是截断，并不保存，保存在下面执行
    if (!_untrack_memory(addr, len)) {
      ERROR("_track_memory: Unable to truncate existing memory");
      return false;
    }

#ifdef ADDITIONAL_DEBUG_CHECKS
// 会再次遍历 dm_data.ranges[]数组，断言没有任何一个已使用的 rid 与新的内存区域重叠。
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (dm_data.ranges[rid].used) {
            assert(!_memory_overlaps(dm_data.ranges[rid].addr, dm_data.ranges[rid].len, addr, len));
        }
    }
#endif // ADDITIONAL_DEBUG_CHECKS

    DEBUG_MPK("_track_memory: inserting new range");
    // insert new range
    // 在 dm_data.ranges[] 数组中寻找一个没有被使用的 rid，将新的内存区域的信息存储在其中
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (!dm_data.ranges[rid].used) {
            dm_data.ranges[rid].addr = addr;
            dm_data.ranges[rid].len  = len;
            dm_data.ranges[rid].prot = prot;
            dm_data.ranges[rid].vkey  = vkey;
            dm_data.ranges[rid].pkey = pkey;
            dm_data.ranges[rid].used = true;
            return true;
        }
    }
    ERROR("_track_memory has too few ranges available."
          "We're potentially in an inconsistent state.");
    return false;
}
//------------------------------------------------------------------------------
/**
 * This function must not use CURRENT_DID, as it might not be available yet.
 */
// prot ： write / read
int D_CODE _dm_pkey_mprotect_underlocked(int did, void *addr, size_t len, int prot, vkey_t vkey){

    DEBUG_MPK("_dm_pkey_mprotect_unchecked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        return cleanup_and_exit(EINVAL, "_dm_pkey_mprotect: memory range is not page-aligned", 0);
    }

    if (!check_domain_exists(did)){
        return cleanup_and_exit(EINVAL, "_dm_pkey_mprotect domain does not exist", 0);
    }

    if(vkey == GET_DEFAULT_VKEY ){
        vkey = _get_default_vkey(did);
        if (vkey == GET_DEFAULT_VKEY) {
            return cleanup_and_exit(EACCES, "_dm_pkey_mprotect domain has no default vkey", 0);
        }
    }
    // 判断是否有密钥的 owner 权限
    if (!_domain_owns_vkey_nocurrdid(did, vkey)){
        return cleanup_and_exit(EACCES, "_dm_pkey_mprotect: domain does not own vkey", 0);
    }
    pkey_t pkey = _get_domain_pkey(did, vkey);

    // 判断是否有这一个内存范围的 owner 权限，也就是拥有这一个内存范围密钥的权限
    // (函数：域是否拥有此内存区域，即对此内存区域对应的vkey 对应的 key数组槽，是否拥有该 owner 权限)
    if (!_domain_owns_memory(did, addr, len)) {
        return cleanup_and_exit(EACCES, "_dm_pkey_mprotect: domain does not own memory range", 0);
    }

    // mprotect 系统调用：addr,len 指向要修改保护属性的内存区域;prot 代表新的保护权限;pkey 代表这块内存区域的密钥(保留位的值)
    int ret = pkey_mprotect(addr, len, prot, pkey);
    if(ret != 0){
        ERROR("_dm_pkey_mprotect: mprotect failed");
        perror("pkey_mprotect");
        return -1;
    }

    if (!_track_memory(addr, len, prot, vkey, pkey)) {
        return cleanup_and_exit(ENOMEM, "_dm_pkey_mprotect_underlocked cannot track more mprotect calls", 0);
    }

    return 0;
}
//------------------------------------------------------------------------------

static inline D_CODE size_t _allocate_key_slot_underlocaked(int did) {
    for (size_t i = 0; i < NUM_KEYS_PER_DOMAIN; i++) {
        if (!dm_data.domains[did].keys[i].used) {
            return i;
        }
    }
    return (size_t)-1; // Indicate failure to allocate
}
//------------------------------------------------------------------------------
int D_CODE _dm_pkey_mprotect_cur_did_underlocked(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_dm_pkey_mprotect_cur_did_underlocked(%d, addr=%p, len=0x%zx, %d, %d)", did, addr, len, prot, vkey);

    //  TODO   实现函数 _domain_is_current_or_child
    // if(!_domain_is_current_or_child(did)){
    //     ERROR("_dm_pkey_mprotect_underlocked only allowed on current DID or child");
    //     ERROR("CURRENT_DID = %d", CURRENT_DID);
    //     errno = EACCES;
    //     return -1;
    // }

    return _dm_pkey_mprotect_underlocked(did, addr, len, prot, vkey);
}
//------------------------------------------------------------------------------
static inline D_CODE pkey_t find_reusable_shared_key() {
    int reuse_count_min = SHARED_MAX;
    pkey_t pkey_min = -1;
    for (size_t i = 0; i < MAX_NUM_KEYS; i++) {
        if (dm_shared_pkeys[i] > 0 && dm_shared_pkeys[i] < reuse_count_min) {
            reuse_count_min = dm_shared_pkeys[i];
            pkey_min = i;
        }
    }
    return pkey_min >= 0 && dm_shared_pkeys[pkey_min] < SHARED_MAX ? pkey_min : -1;
}
//------------------------------------------------------------------------------
// init  _dm_data._dm_domain.domain_key_t
vkey_t D_CODE _dm_pkey_alloc_underlocked(int did, unsigned int flags, unsigned int access_rights){
	
	DEBUG_MPK("_dm_pkey_alloc(%d, %d)", flags, access_rights);

	if (!check_domain_exists(did)) {
        return cleanup_and_exit(EINVAL, "_dm_pkey_alloc domain does not exist", 0);
	}
	if (flags & ~(PK_SHARED_KEY)) {
        return cleanup_and_exit(EINVAL, "_dm_pkey_alloc invalid flags", 0);
	}
    if ((access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE))) {
        return cleanup_and_exit(EINVAL, "_dm_pkey_alloc invalid access rights", 0);
    }

	// find unused key list slot
	size_t KeyID = _allocate_key_slot_underlocaked(did);
    if (KeyID == (size_t)-1) {
        return cleanup_and_exit(ENOMEM, "_dm_domain_assign_pkey could not allocate key slot for domain", 0);
    }

	// check allocation of virtual protection key
	if (_vkey_counter >= VKEY_MAX) {
        return cleanup_and_exit(ENOSPC, "_dm_pkey_alloc could not allocate vkey", 0);
	}

	// allocate new protection key
    pkey_t pkey = pkey_alloc(flags & ~PK_SHARED_KEY, access_rights);
	if (pkey < 0) {
		// no more key
		if (flags & PK_SHARED_KEY) {
		    // Find the share key for the minimum shared counter
            pkey = find_reusable_shared_key();
            if ( pkey == -1 ){
                return cleanup_and_exit(ENOSPC, "_dm_pkey_alloc could not allocate shared key", 0);
            }
		    dm_shared_pkeys[pkey]++;
            DEBUG_MPK("_dm_pkey_alloc reusing shared key %d", pkey);
		} else {
            return cleanup_and_exit(0, "_dm_pkey_alloc could not allocate key", 0);
		}
    } else if (flags & PK_SHARED_KEY) {     	// key alloc success, then set shared if neccessary
        assert(dm_shared_pkeys[pkey] == 0);
        dm_shared_pkeys[pkey] = 1;
    }

	// alloc vkey , and then Global vkey counter ++
	vkey_t vkey = _vkey_counter++;

    // TODO ,注意这里的 release 版本
#ifndef RELEASE 
	if (!(flags & PK_SHARED_KEY)) {
		for (size_t i = 0; i < NUM_DOMAINS && dm_data.domains[i].used; i++) {
			for (size_t j = 0; j < NUM_KEYS_PER_DOMAIN; j++) {
				domain_key_t k = dm_data.domains[i].keys[j];
				//key already used by another domain. double allocation
                assert(!(k.used && k.vkey == vkey));
                assert(!(k.used && k.pkey == pkey));
			}
		}
	}
#endif

	// store key in domain's key slot
	dm_data.domains[did].keys[KeyID].vkey  = vkey;
	dm_data.domains[did].keys[KeyID].pkey  = pkey;
	dm_data.domains[did].keys[KeyID].owner = true;
	dm_data.domains[did].keys[KeyID].perm  = access_rights;
	dm_data.domains[did].keys[KeyID].used  = true;

	return vkey;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
int D_CODE _deinit_root_domain(){
    int ret = 0;
    DEBUG_MPK("deinit domain manager start");

    // TODO  后续再补充

//  TODO  手动注释的，看一下需不需要补充
// #ifdef __x86_64__
//     if (pk_sysfilter && -1 == _pk_unload_sysfilter_module()) {
//       // errno set by _pk_unload_sysfilter_module
//       ret |= -1;
//     }
// #endif
//     // RISC-V uses hardware syscall delegation, so no need for sysfilter module

//     #ifdef SHARED
//     if (-1 == _dm_selfunprotect()) {
//       // errno set by _pk_selfunprotect
//       ERROR("_pk_deinit: unable to unprotect pk memory");
//       ret |= -1;
//     }
//     #endif // SHARED

    #ifdef TIMING
        //save stats file
        FILE* f = fopen("dm_stats.csv", "w");
        if (!f) {
            ERROR("Could not open stats file");
            // errno set by fopen
            ret |= -1;
        } else {
            fprintf(f, "pk_exception_counter, %zu\n", pk_data.stat_num_exceptions);
            fclose(f);
        }
    #endif
    return ret;
    DEBUG_MPK("deinit domain manager end");
}

//------------------------------------------------------------------------------

int D_CODE _init_root_domain(){
	
	DEBUG_MPK("_init_root_domain start");
	if (_dm_initialize_lock()) {
        return cleanup_and_exit(0, "_init_root_domain error: lock initialization failed", 0);
	}

	_dm_acquire_lock();
    const int unlock = 1;
	if(dm_data.initialized){
        return cleanup_and_exit(EACCES, "_init_root_domain: dm already initialized", unlock);
	}

    assert(WORDSIZE == sizeof(uint64_t));
	//print_mem_maps();

	dm_data.pagesize = sysconf(_SC_PAGESIZE);
	if (dm_data.pagesize == -1 ){
        return cleanup_and_exit(EACCES, "_init_root_domain: sysconf(_SC_PAGESIZE) failed", unlock);
	}
	if (dm_data.pagesize != PAGESIZE){
        return cleanup_and_exit(EACCES, "_init_root_domain: pagesize does not match", unlock);
	}

    // create root domain
	did_root = _dm_domain_create_underlocked(0, 0);
	if (did_root == -1){
		return cleanup_and_exit(0, NULL, unlock);
	}
	assert(did_root == DID_FOR_ROOT_DOMAIN);
	assert(_get_default_vkey(did_root) == KEY_FOR_ROOT_DOMAIN);

    dm_data.stacksize = _get_default_stack_size();

    // TODO 这里的 异常处理域和 did root  的区别？？？
    // TODO  did_for_exception_handler 更名，root 不做逻辑处理
    did_for_exception_handler = _dm_domain_create_underlocked(0, 0);
	if (did_root == -1){
		return cleanup_and_exit(0, NULL, unlock);
	}
    assert(did_for_exception_handler == DID_FOR_EXCEPTION_HANDLER);
    assert(_get_default_vkey(did_for_exception_handler) == KEY_FOR_EXCEPTION_HANDLER);
    
    // TODO DELETE did_for_exception_handler = did_root;
    // get trusted TLS offset  
    _dm_ttls_offset = (uint64_t)&dm_trusted_tls.backup_user_stack - GET_TLS_POINTER;

	// TODO  完善与enclave结合
	// TODO Setup exception handler for current thread
    // 6.   init  _dm_data.ranges[]
	void* exception_stack = _dm_setup_thread_exception_stack();
    // 7.  init  _dm_data.threads[], 即  dm_trusted_tls
    int ret = -1;
	ret = _dm_initialize_thread(did_root, exception_stack);
	if(ret != 0){
        return cleanup_and_exit(EACCES, "_init_root_domain: _dm_initialize_thread failed", unlock);
	}

	// initialize architecture
	if (_dm_init_arch()) {
        return cleanup_and_exit(EACCES, "_init_root_domain: _dm_init_arch failed", unlock);
	}


    DEBUG_MPK("protecting dm data");
#ifdef SHARED
	// TODO 
	// allocate read-only key for exception handler memory that can be read by all domains but not written/manipulated
    rokey_for_exception_handler = _dm_pkey_alloc_underlocked(did_for_exception_handler, 0, 0);
    if (rokey_for_exception_handler < 0) {
        ERROR("failed to allocate read-only key");
        goto error;
    }
    if (-1 == _dm_domain_assign_pkey_underlocked(DID_FOR_EXCEPTION_HANDLER, DID_FOR_ROOT_DOMAIN, rokey_for_exception_handler, PK_COPY_KEY, PKEY_DISABLE_WRITE)) {
        ERROR("failed to assign read-only key to root domain");
        goto error;
    }
		
	ret = _dm_selfprotect(did_for_exception_handler, GET_DEFAULT_VKEY);
    if (ret != 0) {
        ERROR("_init_root_domain: failed to mprotect dm code/data");
        // errno set by _dm_selfprotect
        goto error;
    }
#else // SHARED
	// TODO
	size_t dm_data_size = (size_t)((uintptr_t)__stop_dm_data - (uintptr_t)__start_dm_data);
    ret = _dm_pkey_mprotect_underlocked(did_for_exception_handler, (void *)__start_dm_data, dm_data_size, PROT_WRITE | PROT_READ, GET_DEFAULT_VKEY);
    if(ret != 0){
        return cleanup_and_exit(0, "_init_root_domain: failed to mprotect dm data", unlock);
    }
    DEBUG_MPK("protecting dm code");
    size_t dm_code_size = (size_t)((uintptr_t)__stop_dm_code - (uintptr_t)__start_dm_code);
    ret = _dm_pkey_mprotect_underlocked(did_for_exception_handler, (void *)__start_dm_code, dm_code_size,  PROT_EXEC | PROT_READ, GET_DEFAULT_VKEY);
    if(ret != 0){
        return cleanup_and_exit(0, "_init_root_domain: failed to mprotect dm code", unlock);
    }
#endif // SHARED

	// initialize syscall interposition
	// RISC-V uses hardware syscall delegation, so no need for sysfilter module
	// TODO register signal handler via sigaction

	assert(CURRENT_DID == DID_FOR_ROOT_DOMAIN);
	dm_data.initialized = 1; // this is for internal use 

	DEBUG_MPK("_init_root_domain done");
	_dm_release_lock();
	return 0;
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
int D_CODE _dm_domain_assign_pkey_underlocked(int source_did, int target_did, vkey_t vkey, int flags, int access_rights){
    
    DEBUG_MPK("_dm_domain_assign_pkey_underlocked(%d, %d, %d, %d, %d)", source_did, target_did, vkey, flags, access_rights);
    if (!check_domain_exists(source_did)) {
        DEBUG_MPK("The value of myBool is %s\n", dm_data.domains[source_did].used ? "true" : "false");
        return cleanup_and_exit(EINVAL, "_dm_domain_assign_pkey source domain does not exist", 0);
    }
    if (!check_domain_exists(target_did)) {
        return cleanup_and_exit(EINVAL, "_dm_domain_assign_pkey target domain does not exist", 0);
    }

	// 1. get source domain info
    _dm_domain* SourceDomain = &dm_data.domains[source_did];
    int KeyID = _get_domain_keyid_of_vkey(source_did, vkey);
    if (KeyID == -1) {
        return cleanup_and_exit(EACCES, "_dm_domain_assign_pkey domain does not have vkey", 0);
    }

    pkey_t pkey = _get_domain_pkey(source_did, vkey);
    int SourcePerm = SourceDomain->keys[KeyID].perm;

	// 2. flags and access right check
    if (flags & ~(PK_OWNER_KEY | PK_COPY_KEY)) {
        return cleanup_and_exit(EINVAL, "_dm_domain_assign_pkey invalid flags", 0);
    }
    bool IsOwnerKey = (flags & PK_OWNER_KEY);
    if (IsOwnerKey && !SourceDomain->keys[KeyID].owner) {
        return cleanup_and_exit(EACCES, "_dm_domain_assign_pkey domain does not own vkey", 0);
    }
    if (access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
        return cleanup_and_exit(EINVAL, "_dm_domain_assign_pkey invalid access_rights", 0);
    }

    // 3. determine target key slot to use
    // Reuse or allocate new KeyID for target domain
    size_t TargetKeyID = (target_did == source_did) ? KeyID : _allocate_key_slot_underlocaked(target_did);
    if (TargetKeyID == (size_t)-1) {
        return cleanup_and_exit(ENOMEM, "_dm_domain_assign_pkey could not allocate key slot for domain", 0);
    }

    // 4. Setup the key in the target domain
    dm_data.domains[target_did].keys[TargetKeyID].vkey  = vkey;
    dm_data.domains[target_did].keys[TargetKeyID].pkey  = pkey;
    dm_data.domains[target_did].keys[TargetKeyID].owner = IsOwnerKey;
    dm_data.domains[target_did].keys[TargetKeyID].perm  = SourcePerm | access_rights;
    dm_data.domains[target_did].keys[TargetKeyID].used  = true;

    if (!(flags & PK_COPY_KEY) && target_did != source_did) {
        SourceDomain->keys[KeyID].used = false; // Invalidate original key if not copying
    }

    // 5. load key for target domain
    if (_dm_domain_load_key_underlocked(target_did, vkey, PK_SLOT_ANY, 0) != 0) {
        ERROR("_dm_domain_assign_pkey could not load newly assigned key");
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
int D_CODE _dm_domain_load_key_underlocked(int did, vkey_t vkey, int slot, unsigned int flags){

    DEBUG_MPK("_dm_domain_load_key_underlocked(%d, %d, %d, %u)", did, vkey, slot, flags);
    if (flags != 0) {
        return cleanup_and_exit(EINVAL, "_dm_domain_load_key invalid flags", 0);
    }
    if (!check_domain_exists(did)) {
        ERROR("The did is invalid");
        return -1;
    }
    if(vkey == GET_DEFAULT_VKEY){
        vkey = _get_default_vkey(did);
        if ( vkey == VKEY_INVALID ) {
            return cleanup_and_exit(EACCES, "_dm_domain_load_key domain has no default key", 0);
        }
    }

    int KeyID = _get_domain_keyid_of_vkey(did, vkey);
    if (KeyID == -1){
        return cleanup_and_exit(EACCES, "_dm_domain_load_key domain does not have pkey", 0);
    }
    int perm = dm_data.domains[did].keys[KeyID].perm;
    pkey_t pkey = dm_data.domains[did].keys[KeyID].pkey;

    if (_dm_domain_load_key_arch(did, pkey, slot, perm) != 0){
        DEBUG_MPK("_dm_domain_load_key_arch fail");
        return -1;
    }

    if (did == CURRENT_DID) {
        // update current_pkru in TLS to reflect pkru modifications
        dm_trusted_tls.current_pkru = _read_pkru_reg();
    }
    DEBUG_MPK("_dm_domain_load_key_underlocked end");
    return 0;
}




//------------------------------------------------------------------------------

/**
 * @brief This function handles missing-key-exception
 * 
 * TODO: write me
 */
int D_CODE  _dm_exception_key_mismatch_underlocked(void * AccessAddr){
    DEBUG_MPK("_dm_exception_key_mismatch_underlocked(%p)", AccessAddr);
    // keys are assigned on a page granularity
    // Yet, AccessAddr could span two different keys on a page border
    // Load both of them

    // static ensures persistence 

    static D_DATA void * PreviousBadaddr = NULL;
    static D_DATA  size_t PreviousCount = 0;
    const int unlock = 0;
    if (PreviousBadaddr == AccessAddr) {
        if ( ++PreviousCount >= 5 ) {
            PreviousCount = 0;
            return cleanup_and_exit(EPERM, "Triple fault. Giving up", unlock);
        }
    } else {
        PreviousBadaddr = AccessAddr;
        PreviousCount = 1;
    }

    vkey_t vkey1 = _vkey_for_address_nocurrdid(CURRENT_DID, AccessAddr);
    // addresses may be cross-page
    char* TopAddr = (char*)AccessAddr+WORDSIZE-1;
    vkey_t vkey2 = _vkey_for_address_nocurrdid(CURRENT_DID, TopAddr);
    if (VKEY_INVALID == vkey1 || VKEY_INVALID == vkey2) {
        ERROR("domain does not own pkeys for [%p-%p]", AccessAddr, TopAddr);
        return cleanup_and_exit(EPERM, NULL, unlock);
    }
    if ( _dm_domain_load_key_underlocked(CURRENT_DID, vkey1, PK_SLOT_ANY, 0) != 0){
        return cleanup_and_exit(EPERM, "_dm_exception_key_mismatch_underlocked:failed to load vkey1", unlock);
    }
    if (vkey2 != vkey1 && _dm_domain_load_key_underlocked(CURRENT_DID, vkey2, PK_SLOT_ANY, 0) != 0){
        return cleanup_and_exit(EPERM, "_dm_exception_key_mismatch_underlocked:failed to load vkey2", unlock);
    }
    return 0;
}

//------------------------------------------------------------------------------
// TODO  下面的 _dm_exception_handler_underlocked 函数需要用到的一些函数
//------------------------------------------------------------------------------
bool  static inline D_CODE check_stack_push_allowed(_dm_thread_domain * data, uintptr_t stack_pointer, size_t size) {

//  TODO    assert_ifdebug  大部分都注释掉了，也有部分改为 assert
    // assert_ifdebug(data->user_stack_size);
    // assert_ifdebug(data->user_stack_base);
    // assert_ifdebug(size < data->user_stack_size);
//  todo  unlikely
    if((
        stack_pointer - size <  (uintptr_t)data->user_stack_base ||
        stack_pointer        >= (uintptr_t)data->user_stack_base + data->user_stack_size
    )){
        WARNING("Push not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//------------------------------------------------------------------------------
bool static inline D_CODE  check_stack_pop_allowed(_dm_thread_domain * data, uintptr_t stack_pointer, size_t size) {
// todo  见上
    // assert_ifdebug(data->user_stack_size);
    // assert_ifdebug(data->user_stack_base);
    // assert_ifdebug(size < data->user_stack_size);
//  unlikely
    if(( stack_pointer        <  (uintptr_t)data->user_stack_base ||
        stack_pointer + size >= (uintptr_t)data->user_stack_base + data->user_stack_size )){
        WARNING("Pop not allowed: stack frame= (0x%lx, 0x%lx), stack = (%p,0x%lx)", 
            stack_pointer, size, data->user_stack_base, data->user_stack_size);
        return false;
    }
    return true;
}
//------------------------------------------------------------------------------
bool static inline D_CODE check_transition_allowed(int target_did){
    if (CURRENT_DID == 0){
        DEBUG_MPK("current did = 0, transition allowed!");
        return true;
    }
    if(_is_allowed_source_nocurrdid(CURRENT_DID, target_did)){
        DEBUG_MPK("current did (%d) is allowed to transition to %d", CURRENT_DID, target_did);
        return true;
    }
    return false;
}
//------------------------------------------------------------------------------
static inline D_CODE void  _before_get_thread_data(void) {
// todo  assert_ifdebug   ==> assert
    assert(dm_trusted_tls.init);
    assert(dm_trusted_tls.current_did != INVALID_DID);
    assert(dm_trusted_tls.exception_stack_base != 0);
    assert(dm_trusted_tls.exception_stack != 0);
    assert(dm_trusted_tls.tid >= 0 && dm_trusted_tls.tid < NUM_THREADS);
    assert(dm_data.threads[dm_trusted_tls.tid]->tid == dm_trusted_tls.tid);
}

//------------------------------------------------------------------------------
static inline D_CODE _dm_thread_domain * _get_thread_domain_data_nocurrdid(int did) {

    assert(check_domain_exists(did));
    //get data
    _before_get_thread_data();
    _dm_thread_domain * data = &(dm_trusted_tls.thread_domain_data[did]);
    // assert_ifdebug( (uintptr_t)data % WORDSIZE == 0); //check that pointer to member within a packed struct is aligned. TODO move this to a assert that only happens once during init or during compile time

    // initialize lazily/on demand
//  TODO      if(likely(data->user_stack_base != 0)){
    if((data->user_stack_base != 0)){
        // todo  注释掉了 assert_ifdebug(data->user_stack_size != 0);
        return data;
    }

    // int ret = _allocate_user_stack(did, data);
    // TODO   _allocate_user_stack  直接写到函数里面
    // Create new user stack
    data->user_stack_size = dm_data.stacksize;
    data->user_stack_base = _allocate_stack(dm_data.stacksize);
    assert(data->user_stack_size);
    assert(data->user_stack_base);
    // Protect user stack
    int ret = _protect_user_stack(did, data);

    if(ret != 0){
        ERROR_FAIL("_allocate_user_stack failed");
    }

    return data;
}
//------------------------------------------------------------------------------
static inline D_CODE uint64_t *prepare_target_stack(_dm_thread_domain *TargetThreadDomain) {
    uint64_t *TargetStack;
    if (TargetThreadDomain->expected_return) {
        TargetStack = (uint64_t *)TargetThreadDomain->expected_return;
    } else {
        TargetStack = (uint64_t *)((uintptr_t)TargetThreadDomain->user_stack_base + TargetThreadDomain->user_stack_size - 2*WORDSIZE);
    }
    // TODO 删掉
#ifdef __x86_64__
    assert(((uintptr_t)TargetStack % 16) == 0);
#endif
    assert(TargetStack != NULL);
    return TargetStack;
}
//------------------------------------------------------------------------------
// handle_type_call 函数处理类型为 TYPE_CALL 的异常。
// 它首先验证调用的合法性，包括检查 id 是否在合法范围内，检查入口点是否存在，以及确认调用转换是否被允许。
// 接着，它准备目标堆栈，将当前域的信息压入目标堆栈，最后执行域切换。
void D_CODE handle_type_call(uint64_t id, uint64_t *current_stack, void *ReturnAddr, int current_did) {
    // 新增函数，这里的注释对照原版
    DEBUG_MPK("handle type call Start.");
    if (id >= NUM_REGISTERED_ECALLS) {
        ERROR_FAIL("ecall %zu not registered (out of range)", id);
    }

    void *entry = domain_registered_ecalls[id].entry;
    int TargetDid = domain_registered_ecalls[id].did;
    
    // check if id is registered
    if (entry == NULL) {
        ERROR_FAIL("ecall %zu not registered!", id);
    }

    // TODO assert_ifdebug
    assert(ReturnAddr != NULL);
    assert(current_stack != NULL);
    
    // check if call transition allowed
    if (!check_transition_allowed(TargetDid)) {
        ERROR_FAIL("call transition from %d to %d not allowed", current_did, TargetDid);
    }

    _dm_thread_domain *TargetThreadDomain = _get_thread_domain_data_nocurrdid(TargetDid);
    uint64_t *TargetStack = prepare_target_stack(TargetThreadDomain);

    if (!check_stack_push_allowed(TargetThreadDomain, (uintptr_t)TargetStack, sizeof(_return_did))) {
        ERROR_FAIL("invalid target stack pointer, or not enough space");
    }

    // 此处进行堆栈操作和状态转换
    _dm_thread_domain * CurrentThreadDomain = &(dm_trusted_tls.thread_domain_data[current_did]);
    // Check if there's enough space on current stack
    // for pushing expected_return struct
    if(!check_stack_push_allowed(CurrentThreadDomain, (uintptr_t)current_stack, sizeof(_expected_return))) {
        ERROR_FAIL("invalid current stack pointer or not enough space");
    }

    // At this point, all the checks are passed. we're allowed to make the ecall
    // Push expected_return struct onto current stack
    _expected_return* expected_return = (_expected_return*)current_stack - 1;

    // 填充_expected_return结构体
    expected_return->did      = TargetDid;
    expected_return->reentry  = ReturnAddr;
    expected_return->previous = CurrentThreadDomain->expected_return;

    CurrentThreadDomain->expected_return = expected_return;

    // Push caller DID onto target stack.
    // This is needed so that we know to which domain we want to return to.
    _return_did * ret_did = (_return_did*)TargetStack - 1; //allocate _return_did struct on target stack
    TargetStack = (uint64_t*)ret_did;
    ret_did->did = current_did;

    // Load new config of target domain
    pkru_config_t config = dm_data.domains[TargetDid].default_config;

    // Switch stacks and protection keys and prepare entry address
    _dm_domain_switch_arch(TYPE_CALL, TargetDid, config, entry, TargetStack);
    // update current_pkru in TLS to reflect pkru modifications
    dm_trusted_tls.current_pkru = _read_pkru_reg();
    DEBUG_MPK("handle type call end.");
}

//------------------------------------------------------------------------------
void D_CODE handle_type_ret(uint64_t id, uint64_t *current_stack, int current_did) {
    _dm_thread_domain *current_thread_domain = &(dm_trusted_tls.thread_domain_data[current_did]);
    
    if (!check_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(*current_stack))) {
        ERROR_FAIL("invalid current stack pointer");
    }
    current_stack++; // 调整堆栈指针以弹出返回地址
    if (!check_stack_pop_allowed(current_thread_domain, (uintptr_t)current_stack, sizeof(_return_did))) {
        ERROR_FAIL("invalid stack pointer");
    }
    _return_did *ret_did = (_return_did *)current_stack;
    int TargetDid = ret_did->did;

    if (!check_domain_exists(TargetDid)) {
        ERROR_FAIL("Target domain does not exist");
    }

    // get thread-domain data for target did
    _dm_thread_domain *TargetThreadDomain = &(dm_trusted_tls.thread_domain_data[TargetDid]);
    // check if target stack is valid
    if (TargetThreadDomain->expected_return == NULL) {
        ERROR_FAIL("Target domain is not expecting a return");
    }
    _expected_return* expected_return = TargetThreadDomain->expected_return;

    // Check if target stack is valid for popping _expected_return struct
    // This is very unlikely to fail, because this is already checked when making the ECALL
    if(!check_stack_pop_allowed(TargetThreadDomain, (uintptr_t)expected_return, sizeof(_expected_return))) {
        ERROR_FAIL("invalid target stack pointer");
    }

    // check if return transition allowed
    if(expected_return->did != current_did) {
        ERROR_FAIL("Target domain (%d) is not expecting a return from the current domain (%d) ", TargetDid, current_did);
    }

    // Retrieve original ReturnAddr point and stack pointer
    void *     ReturnAddr         = expected_return->reentry;          // Warning: shadowing function argument with same name
    uint64_t * TargetStack    = (uint64_t *)(expected_return + 1); // sp = where expected_return was, "minus" the struct itself
// todo          assert_ifdebug(TargetStack != 0);
    assert(TargetStack != 0);

    // Restore previous expected_return frame
    TargetThreadDomain->expected_return = expected_return->previous;

    // Load new config of target domain
    pkru_config_t config = dm_data.domains[TargetDid].default_config;
    // Switch stacks and protection keys and prepare ReturnAddr address
    _dm_domain_switch_arch(TYPE_RET, TargetDid, config, ReturnAddr, TargetStack);
    // update current_pkru in TLS to reflect pkru modifications
    dm_trusted_tls.current_pkru = _read_pkru_reg();
}

//------------------------------------------------------------------------------

/**
 * @brief This function handles ecalls and returns.
 * 
 * @param type
 *        @c TYPE_ECALL: Stores return information such as the @p ReturnAddr
 *            point in an @c _expected_return frame on the caller's stack
 *            The caller DID is pushed on the target's stack.
 *        @c TYPE_RET: Retrieves the original caller DID from current user
 *            stack, and recover the @c _expected_return frame from the
 *            original caller stack
 * @return
 *        Returns the @p type again
 */
uint64_t D_CODE _dm_exception_handler_underlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * current_stack, void * ReturnAddr){

// data 没用到？
    DEBUG_MPK("_dm_exception_handler_c(id=%zu, type=%zu, ReturnAddr=%p)",id, type, ReturnAddr);

    assert(dm_data.initialized);

// 注释掉
    #if defined(TIMING) && defined(DEBUG)
    dm_data.stat_num_exceptions = dm_data.stat_num_exceptions + 1;
    #endif

    //Note: the ReturnAddr argument is only valid for type == TYPE_CALL

    int    current_did = CURRENT_DID;
    DEBUG_MPK("\tcurrent_did=0x%x", current_did);

    switch(type) {
        case TYPE_CALL:
            // Resolve ecall ID
            handle_type_call(id, current_stack, ReturnAddr, current_did);
            break;
        case TYPE_RET:
            //get thread-domain data
            handle_type_ret(id, current_stack, current_did);
            break;
        case TYPE_API:
            ERROR_FAIL("TYPE_API should have been handled in assembly already");
            break;
        default:
            ERROR_FAIL("Unhandled case in dm_exception_handler_c");
    }

    return type;
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
// 其他 API            
//------------------------------------------------------------------------------

int D_DATA _pthread_child_has_signalled = 0;

void D_CODE  _pthread_init_function_c(void * start_routine, void * current_user_stack) {
  DEBUG_MPK("_pthread_init_function_c(%p, %p)", dm_data.pthread_arg.start_routine, dm_data.pthread_arg.arg);
  // initialize thread
  int ret = _dm_initialize_thread(dm_data.pthread_arg.current_did, dm_data.pthread_arg.exception_stack);
  if (ret) {
    ERROR("_pthread_init_function_c: unable to initialize thread");
    // errno is set by _pk_init_thread
    goto error;
  }

  // we're finished accessing the global pk_data.pthread_arg struct
  // signal the parent pthread that it can now release the lock
  _pthread_child_has_signalled = 1;
  _dm_signal_cond();

  // we acquire the lock for ourselves
  _dm_acquire_lock();

  // enable thread for startup
  pkru_config_t current_config = _read_pkru_reg();
  //_dm_domain_switch_arch(CURRENT_DID, current_config, start_routine, current_user_stack);
    _dm_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, start_routine, current_user_stack);
  _dm_release_lock();
  return;

error:
  // enable thread for self-destruction
  current_config = _read_pkru_reg();
  // TODO: Untested. Also, pass return value correctly to pthread_exit
  _dm_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, pthread_exit, current_user_stack);
  _dm_release_lock();
}


//------------------------------------------------------------------------------
int D_CODE _dm_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg)
{
  DEBUG_MPK("_dm_pthread_create(%p, %p, %p, %p)", thread, attr, start_routine, arg);
  int ret;
  assert(dm_data.initialized);
  _dm_acquire_lock();

  assert(0 == _pthread_child_has_signalled);
  if (!thread || !start_routine) {
    ERROR("_dm_pthread_create: thread or start_routine is NULL");
    ret = EINVAL;
    goto error;
  }

  if(!_domain_owns_memory(CURRENT_DID, (void*)thread, sizeof(thread))) {
    ERROR("_dm_pthread_create: *thread is not owned by current domain");
    ret = EINVAL;
    goto error;
  }

  // TODO: If we want to support attr properly, we need to check whether
  // _domain_owns_memory(*attr) and _domain_owns_memory(internal stack of *attr)
//   if (attr) {
//     ERROR("_dm_pthread_create does not support attributes");
//     ret = EINVAL;
//     goto error;
//   }

  // *start_routine needs no check since it is only interpreted by user code

  // *arg needs no check since it is only interpreted by user code

  // setup exception stack
  void* exception_stack_base = _dm_setup_thread_exception_stack();
  if (!exception_stack_base) {
    ERROR("_dm_pthread_create: failed to setup exception stack");
    ret = EAGAIN;
    goto error;
  }

  dm_data.pthread_arg.exception_stack = (uintptr_t*)exception_stack_base; 
  dm_data.pthread_arg.exception_stack_top = (uintptr_t*)exception_stack_base + EXCEPTION_STACK_WORDS - 2; // TODO: outsource to arch-specific code
  dm_data.pthread_arg.arg = arg;
  dm_data.pthread_arg.start_routine = start_routine;
  dm_data.pthread_arg.current_did = CURRENT_DID;

// TODO PTHREAD_CREATE
  ret = pthread_create(thread, attr, _pthread_init_function_asm, arg);
  if (ret) {
    goto error;
  }

  DEBUG_MPK("pthread parent");
  if (!_pthread_child_has_signalled) {
    // Wait for the child finishing initial setup
    // There's still a tiny window for a deadlock situation if
    // interrupted exactly here
    _dm_wait_cond();
  }

  assert(1 == _pthread_child_has_signalled);
  _pthread_child_has_signalled = 0;

  _dm_release_lock();
  return 0;

error:
  // TODO: correct error handling
  _dm_release_lock();
  return ret;
}
//------------------------------------------------------------------------------
void D_CODE _dm_pthread_exit(void* retval) {
  // Currently, by calling pthread_exit directly, threads can exit
  // However, the exception stack is not free'd.

  // TODO: We probably don't need to wrap pthread_exit

  // Prepare thread for continuing at pthread_exit
  // TODO: backup_user_stack is misaligned
  _dm_acquire_lock();
    pkru_config_t current_config = _read_pkru_reg();
    // TODO
  //_dm_domain_switch_arch( CURRENT_DID, current_config, pthread_exit, dm_trusted_tls.backup_user_stack);
  _dm_domain_switch_arch(TYPE_CALL, CURRENT_DID, current_config, pthread_exit, dm_trusted_tls.backup_user_stack);
  assert(false);
  _dm_release_lock();

  // Delete dormant exception stack in subsequent pthread_join by a call to dm_pthread_clean
}
//------------------------------------------------------------------------------

int D_CODE _dm_current_did(){
    return CURRENT_DID;
}

//------------------------------------------------------------------------------

int D_CODE _dm_register_exception_handler(void (*handler)(void*)) {
  DEBUG_MPK("_dm_register_exception_handler(%p)", handler);
  assert(dm_data.initialized);

  _dm_acquire_lock();

  if (!handler) {
    ERROR("_dm_register_exception_handler: empty handler");
    errno = EINVAL;
    goto error;
  }

  if (!_domain_owns_memory(CURRENT_DID, handler, WORDSIZE)) {
    ERROR("_dm_register_exception_handler: domain does not own handler %p", handler);
    errno = EACCES;
    goto error;
  }

  if (dm_data.user_exception_handler) {
    ERROR("_dm_register_exception_handler: already configured");
    errno = EPERM;
    goto error;
  }

  dm_data.user_exception_handler = handler;

  _dm_release_lock();
  return 0;

error:
  _dm_release_lock();
  return -1;
}
//------------------------------------------------------------------------------
int D_CODE _dm_domain_create(unsigned int flags, unsigned int isa_set){
    DEBUG_MPK("_dm_domain_create(0x%x)", flags);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    int ret = _dm_domain_create_underlocked(flags, isa_set);
    _dm_release_lock();

    return ret;
}
//------------------------------------------------------------------------------
int D_CODE _dm_domain_free(int did){
    DEBUG_MPK("_dm_domain_free(%d)", did);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    if (DOMAIN_GET_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!check_domain_exists(did)){
        ERROR("_dm_domain_free domain is not exists");
        goto error;
    }
    
    if(did == CURRENT_DID){
        // FREE 所有的子域
        int  child_num_ = dm_data.domains[did].child_num;
        while(child_num_!=0){
            dm_data.domains[did].child_num = dm_data.domains[did].child_num -1;
            _dm_domain_release_child(dm_data.domains[did].child[child_num_]);
        }
        isa_delete(dm_data.domains[did].isa_did);
        memset(&dm_data.domains[did], 0, sizeof(_dm_domain));
    }
    else if(CURRENT_DID == dm_data.domains[did].parent_did){
        isa_delete(dm_data.domains[did].isa_did);
        memset(&dm_data.domains[did], 0, sizeof(_dm_domain));
    }
    else{
        if(did== DID_FOR_ROOT_DOMAIN || did == DID_FOR_EXCEPTION_HANDLER){
            isa_delete(dm_data.domains[did].isa_did);
            memset(&dm_data.domains[did], 0, sizeof(_dm_domain));
        }
        else{
            // did 既不是当前的did，也不是当前的父did,说明没有权限
            ERROR("_dm_domain_free current domain has no prem to free domain");
            goto error;
        }
    }

error:
    errno = EINVAL;
    _dm_release_lock();
    return -1;
}

//------------------------------------------------------------------------------
int D_CODE _dm_domain_release_child(int did){
    DEBUG_MPK("_dm_domain_release_child(%d)", did);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    // 把_domain_is_child 分解
    if (!check_domain_exists(did)) {
        ERROR("_dm_domain_release_child domain is invalid");
        errno = EINVAL;
        goto error;
    }
    if (!(CURRENT_DID == dm_data.domains[did].parent_did)) {
        ERROR("_dm_domain_release_child domain is not child");
        errno = EINVAL;
        goto error;
    }

    dm_data.domains[did].parent_did = INVALID_DID;
    _dm_release_lock();
    return 0;
error:
    _dm_release_lock();
    return -1;
}

//------------------------------------------------------------------------------

int D_CODE _dm_pkey_free(vkey_t vkey){
    DEBUG_MPK("_dm_pkey_free(%d)", vkey);
    assert(dm_data.initialized);
    int ret;

    _dm_acquire_lock();
    if (!check_domain_exists(CURRENT_DID)) {
        ERROR("_dm_pkey_free domain does not exist");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_vkey_nocurrdid(CURRENT_DID, vkey)) {
        ERROR("_dm_pkey_free domain does not own vkey");
        errno = EACCES;
        goto error;
    }

    //unload key
    ret = _dm_domain_load_key_underlocked(CURRENT_DID, vkey, PK_SLOT_NONE, 0);
    if (-1 == ret) {
        ERROR("Unloading of the key failed.");
        goto error;
    }

    // check that vkey is unused
    for (size_t rid = 0; rid < NUM_MPROTECT_RANGES; rid++) {
        if (dm_data.ranges[rid].used && dm_data.ranges[rid].vkey == vkey) {
            ERROR("_dm_pkey_free range[%zu] addr %p len %zu still uses vkey", rid, dm_data.ranges[rid].addr, dm_data.ranges[rid].len);
            errno = EPERM;
            goto error;
        }
    }

    // check that pkey is not loaded
    // If pkey is allocated under more than one virtual key (vkey),
    // this check is omitted, since multiple vkeys
    // could legitimately be loaded under the same pkey
    pkey_t pkey = _get_domain_pkey(CURRENT_DID, vkey);
    assert(pkey >= 0 && pkey < MAX_NUM_KEYS);
    if (dm_shared_pkeys[pkey] <= 1) {
        bool ret = _dm_is_key_loaded_arch(pkey);
        if (ret) {
            ERROR("_dm_pkey_free: pkey is loaded. Unload it first");
            errno = EPERM;
            goto error;
        }
    }

    // revoke vkey in all domains
    for (size_t did = 0; did < NUM_DOMAINS; did++) {
        if (dm_data.domains[did].used) {
            _dm_domain * domain = &dm_data.domains[did];
            for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN; KeyID++) {
                if (domain->keys[KeyID].used && domain->keys[KeyID].vkey == vkey) {
                    domain->keys[KeyID].used = false;
                    DEBUG_MPK("_dm_pkey_free: revoked domain[%zu].keys[%zu]\n", did, KeyID);
                }
            }
        }
    }

    if (dm_shared_pkeys[pkey] >= 1) {
      // decrement sharing count down to zero
      dm_shared_pkeys[pkey]--;
      ret = 0;
    } else {
      // free pkey in the kernel
      ret = pkey_free(pkey);
    }


    _dm_release_lock();
    return ret;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------

//  _dm_pkey_alloc   调用的API，这是待补充的
vkey_t D_CODE _dm_pkey_alloc(unsigned int flags, unsigned int access_rights){
    DEBUG_MPK("_dm_pkey_alloc(%d, %d)", flags, access_rights);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    vkey_t vkey = _dm_pkey_alloc_underlocked(CURRENT_DID, flags, access_rights);
    if (-1 == vkey) {
      ERROR("_dm_pkey_alloc_dm_domain_assign_pkey could not allocate vkey");
      vkey = -1;
    }

    int ret = _dm_domain_load_key_underlocked(CURRENT_DID, vkey, PK_SLOT_ANY, 0);
    if (-1 == ret) {
      ERROR("_dm_pkey_alloc_dm_domain_assign_pkey could not load newly assigned vkey");
      ret = _dm_pkey_free(vkey); 
      if (-1 == ret) {
        ERROR("_dm_pkey_free failed");
      }
      vkey = -1;
    }

    _dm_release_lock();
    return vkey;
}
//------------------------------------------------------------------------------
//  TODO  合并了这两个 API    eg: did == -1?

int D_CODE _dm_pkey_mprotect(int did, void *addr, size_t len, int prot, vkey_t vkey){
    DEBUG_MPK("_dm_pkey_mprotect(%d, %p, %zu, %d, %d)", did, addr, len, prot, vkey);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    if (DOMAIN_GET_CURRENT == did) {
      did = CURRENT_DID;
    }
    int ret = _dm_pkey_mprotect_underlocked(did, addr, len, prot, vkey);

    //print_mem_maps();
    //_dm_print_debug_info();

    _dm_release_lock();

    return ret;
}
//------------------------------------------------------------------------------
// TODO  将下面三个API 合并
void* D_CODE _dm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  return _dm_mmap2(CURRENT_DID, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------
void* D_CODE _dm_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_dm_mmap2(%d, %p, %zu, %d, %d, %d, %ld)", did, addr, length, prot, flags, fd, offset);
  return _dm_mmap_internal(did, GET_DEFAULT_VKEY, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------
void* D_CODE _dm_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  DEBUG_MPK("_dm_mmap3(%d, %p, %zu, %d, %d, %d, %ld)", vkey, addr, length, prot, flags, fd, offset);
  return _dm_mmap_internal(DOMAIN_GET_CURRENT, vkey, addr, length, prot, flags, fd, offset);
}
//------------------------------------------------------------------------------
void* D_CODE _dm_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    DEBUG_MPK("_dm_mmap_internal(%d, %d, %p, %zu, %d, %d, %d, %ld)", did, vkey, addr, length, prot, flags, fd, offset);
    assert(dm_data.initialized);

    _dm_acquire_lock();

    //print_mem_maps();

    void* mem = MAP_FAILED;

    if (DOMAIN_GET_CURRENT == did) {
        did = CURRENT_DID;
    }

    // did must be current domain or child
    //  分解了  _domain_is_current_or_child
    if(!check_domain_exists(did)){
        ERROR("_dm_mmap_internal: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }
 // TODO    if(!(_domain_is_current_or_child(did))){
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_mmap_internal: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // pad to page size
    length = ((length + PAGESIZE-1)) & ~(PAGESIZE-1);
    
    if ((uintptr_t)addr % PAGESIZE || length % PAGESIZE) {
        ERROR("_dm_mmap_internal: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }
//  TODO  MMAP
    mem = mmap(addr, length, prot, flags, -1, offset);
    if (MAP_FAILED == mem) {
        ERROR("_dm_mmap_internal: failed to map memory");
        // errno is set by mmap
        goto error;
    }


    // set protection key
    //   TODO    注意函数名的更改 _dm_pkey_mprotect_underlocked_nodid_check
    int ret = _dm_pkey_mprotect_underlocked(did, mem, length, prot, vkey);
    if (-1 == ret) {
        ERROR("_dm_mmap_internal: failed to set protection key");
        // errno is set by _dm_pkey_mprotect_underlocked
        goto error;
    }

    _dm_release_lock();
    return mem;

error:
    if (MAP_FAILED != mem) {
        ret = munmap(addr, length);
        if (ret) {
            ERROR("_dm_mmap_internal: Unable to unmap memory. We have a memory leak");
        }
    }
    _dm_release_lock();
    return MAP_FAILED;
}

//------------------------------------------------------------------------------
// 合并  ， 使用的时候，注意给定did的值

int D_CODE _dm_munmap(int did, void* addr, size_t len){
    DEBUG_MPK("_dm_munmap(%d, %p, %zu)",did, addr, len);
    assert(dm_data.initialized);

    _dm_acquire_lock();

    if (DOMAIN_GET_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    //  分解了  _domain_is_current_or_child
    if(!check_domain_exists(did)){
        ERROR("_dm_munmap: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }
 // TODO    if(!(_domain_is_current_or_child(did))){
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_munmap: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // pad to page size
    len = (len + (PAGESIZE-1)) & ~(PAGESIZE-1);

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_dm_munmap: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    if (!_domain_owns_memory(did, addr, len)) {
        ERROR("_dm_munmap: domain does not own memory range");
        errno = EACCES;
        goto error;
    }

    if (!_untrack_memory(addr, len)) {
        ERROR("_dm_munmap cannot untrack memory range");
        errno = ENOMEM;
        goto error;
    }
//  MUNMAP
    int ret = munmap(addr, len);
    if (ret) {
        ERROR("_dm_munmap unable to unmap memory");
        // errno is set by munmap
        goto error;
    }

    _dm_release_lock();
    return 0;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------
// 合并 API

int D_CODE _dm_mprotect(int did, void *addr, size_t len, int prot) {
    DEBUG_MPK("_dm_mprotect(%d, %p, %zu, %d)",did, addr, len, prot);
    assert(dm_data.initialized);

    _dm_acquire_lock();

    if (DOMAIN_GET_CURRENT == did) {
      did = CURRENT_DID;
    }

    // did must be current domain or child
    //  分解了  _domain_is_current_or_child
    if(!check_domain_exists(did)){
        ERROR("_dm_mprotect: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }
 // TODO    if(!(_domain_is_current_or_child(did))){
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_mprotect: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    if ((uintptr_t)addr % PAGESIZE || len % PAGESIZE) {
        ERROR("_dm_mprotect: memory range is not page-aligned");
        errno = EINVAL;
        goto error;
    }

    //_dm_print_debug_info();
    if (!_domain_owns_memory(did, addr, len)) {
            //_dm_print_debug_info();

        ERROR("_dm_mprotect: domain does not own memory range");
        errno = EACCES;
        goto error;
    }
//  TODO  MPROTECT
    int ret = mprotect(addr, len, prot);
    if (-1 == ret) {
        ERROR("_dm_mprotect: failed to mprotect");
        // errno is set by mprotect
        goto error;
    }

    // Track newly protected memory
    // Note: since mprotect does not change protection keys
    // we need to iterate over all pages to also maintain protection keys
    // in our internal tracking system.
    vkey_t vkey = VKEY_INVALID;
    uintptr_t a;
    uintptr_t s;
    for (a = s = (uintptr_t)addr; a < (uintptr_t)addr + len; a += PAGESIZE) {
        // obtain vkey for current page
        // If page is not tracked yet, this returns VKEY_INVALID
        int pg_vkey = _vkey_for_address_nocurrdid(did, (void*)a);
        if (vkey == pg_vkey) {
            // determine the whole range which uses the same vkey
            continue;
        } else {
            // The key changed. Track this memory range
            if (VKEY_INVALID != vkey) {
                // Update this memory range only if it is already tracked (i.e. vkey!=VKEY_INVALID)
                if (!_track_memory((void*)s, a - s, prot, vkey, _get_domain_pkey(did, vkey))) {
                    ERROR("_dm_mprotect cannot track memory");
                    errno = ENOMEM;
                    goto error;
                }
            }
            s = a;          // Track new range start
            vkey = pg_vkey; // Track new range's protection key
        }
    }
    if (VKEY_INVALID != vkey) {
        // Update final memory range only if already tracked
        // In the simplest case, this is the whole address range using the same single pkey
        if (!_track_memory((void*)s, a - s, prot, vkey, _get_domain_pkey(did, vkey))) {
            ERROR("_dm_mprotect cannot track final memory");
            errno = ENOMEM;
            goto error;
        }
    }

    _dm_release_lock();
    return 0;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------
//  合并
// register ecall 注册一个gate,使得可以调用这个did，可以切换到这个did
// ecall id 是自己定义的注册 id，需要检查 id? ecall id 并不是did
int D_CODE _dm_domain_register_ecall(int did, int ecall_id, void* entry){
    DEBUG_MPK("_dm_domain_register_ecall(%d, %d, %p)", did, ecall_id, entry);
    assert(dm_data.initialized);

    _dm_acquire_lock();

    if (DOMAIN_GET_CURRENT == did) {
        did = CURRENT_DID;
    }

    if(!check_domain_exists(did)){
        ERROR("_dm_domain_register_ecall: Domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // did must be current domain or child
    // 检查域是否为当前域或子域。
    //  分解了  _domain_is_current_or_child
 // TODO    if(!(_domain_is_current_or_child(did))){
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_domain_register_ecall: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // obtain next free ecall_id
    if (PK_ECALL_ANY == ecall_id) {
        for (ecall_id = 0; ecall_id < NUM_REGISTERED_ECALLS; ecall_id++) {
            if (!domain_registered_ecalls[ecall_id].entry) {
                // We found an empty ecall slot
                break;
            }
        }
    }

    // check for valid id
    if(ecall_id < 0 || ecall_id >= NUM_REGISTERED_ECALLS){
        ERROR("_dm_domain_register_ecall: ecall_id is out of range");
        errno = EACCES;
        goto error;
    }

    if(domain_registered_ecalls[ecall_id].entry != 0){
        ERROR("_dm_domain_register_ecall: ecall_id already used");
        errno = EACCES;
        goto error;
    }

    // register ecall
    domain_registered_ecalls[ecall_id].did   = did;
    domain_registered_ecalls[ecall_id].entry = entry;
    _dm_release_lock();
    return ecall_id;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------
//   TODO   合并
int D_CODE _dm_domain_allow_caller(int caller_did, unsigned int flags){
    DEBUG_MPK("_dm_domain_allow_caller(%d, %u)", caller_did, flags);
    assert(dm_data.initialized);

    return _dm_domain_allow_caller2(DOMAIN_GET_CURRENT, caller_did, flags);
}
//------------------------------------------------------------------------------
// 这个函数是(注册)允许 caller_did 调用 did
int D_CODE _dm_domain_allow_caller2(int did, int caller_did, unsigned int flags){
    DEBUG_MPK("_dm_domain_allow_caller2(%d, %d, %u)", did, caller_did, flags);
    assert(dm_data.initialized);

    _dm_acquire_lock();

    if (DOMAIN_GET_CURRENT == did) {
      did = CURRENT_DID;
    }

    if(!check_domain_exists(caller_did)){
        ERROR("_dm_domain_allow_caller2: Caller domain does not exist");
        errno = EINVAL;
        goto error;
    }

    // only allowed if we're the target or its parent
    //  分解了  _domain_is_current_or_child
    if(!check_domain_exists(did)){
        ERROR("_dm_domain_allow_caller2: Callee domain does not exist");
        errno = EINVAL;
        goto error;
    }
 // TODO    if(!(_domain_is_current_or_child(did))){
    // 只允许调用当前域或者当前域的子域(因为被调用权限应该是自主的，不能由其他域来注册可调用当前域)
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_domain_allow_caller2 only allowed on self or children");
        errno = EACCES;
        goto error;
    }

    if (_is_allowed_source_nocurrdid(caller_did, did)) {
        DEBUG_MPK("_dm_domain_allow_caller2 already allowed, doing nothing.");
    } else {
        size_t * count = &(dm_data.domains[did].allowed_source_domains_count);
        if(*count >= NUM_SOURCE_DOMAINS){
            ERROR("_dm_domain_allow_caller2: no more slots available");
            errno = ENOMEM;
            goto error;
        }
        dm_data.domains[did].allowed_source_domains[*count] = caller_did;
        (*count)++;
    }

    _dm_release_lock();
    return 0;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------
int D_CODE _dm_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights){
    DEBUG_MPK("_dm_domain_assign_pkey(%d, %d, %d, %d)", did, vkey, flags, access_rights);
    assert(dm_data.initialized);

    _dm_acquire_lock();
    if (DOMAIN_GET_CURRENT == did) {
        did = CURRENT_DID;
    }
    int ret = _dm_domain_assign_pkey_underlocked(CURRENT_DID, did, vkey, flags, access_rights);

    _dm_release_lock();
    return ret;
}
//------------------------------------------------------------------------------
int D_CODE _dm_domain_default_key(int did){
    DEBUG_MPK("_dm_domain_default_key(%d)", did);
    assert(dm_data.initialized);

    int vkey = -1;
    _dm_acquire_lock();
    if (DOMAIN_GET_CURRENT == did) {
        did = CURRENT_DID;
    }

   //  分解了  _domain_is_current_or_child
    if(!check_domain_exists(did)){
        ERROR("_dm_domain_allow_caller2: domain does not exist");
        errno = EINVAL;
        goto error;
    }
 // TODO    if(!(_domain_is_current_or_child(did))){
    if(!(CURRENT_DID == did || 
            CURRENT_DID == dm_data.domains[did].parent_did)){
        ERROR("_dm_domain_default_key: only allowed on current domain or child");
        errno = EACCES;
        goto error;
    }

    // if(!_domain_is_current_or_child(did)){
    //     ERROR("_dm_domain_default_key: only allowed on current domain or child");
    //     errno = EACCES;
    //     goto error;
    // }

    vkey = _get_default_vkey(did);
    if (VKEY_INVALID == vkey) {
        ERROR("_dm_domain_default_key: could not retrieve default vkey");
        errno = EACCES;
        goto error;
    }

    _dm_release_lock();
    return vkey;

error:
    _dm_release_lock();
    return -1;
}
//------------------------------------------------------------------------------
int  D_CODE _dm_domain_load_key(vkey_t vkey, int slot, unsigned int flags){
    DEBUG_MPK("_dm_domain_load_key(%d, %d, %u)", vkey, slot, flags);
    assert(dm_data.initialized);
    _dm_acquire_lock();
    int ret = _dm_domain_load_key_underlocked(CURRENT_DID, vkey, slot, flags);
    _dm_release_lock();
    return ret;
}

//------------------------------------------------------------------------------
// Debug-only API functions
//------------------------------------------------------------------------------
void D_CODE _dm_print_debug_info(){

    fprintf(stderr, "\n");
    //printf(COLOR_INFO);
    if (dm_trusted_tls.init) {
        // This requires access to CURRENT_DID
        fprintf(stderr, "[INFO] current config reg: ");
        dm_print_reg_arch(_read_pkru_reg());
    }

    for (size_t tid = 0; tid < NUM_THREADS; tid++) {
        if (NULL == dm_data.threads[tid]) {
          continue;
        }
        _dm_tls* thread_data = dm_data.threads[tid];

        fprintf(stderr, "[INFO] Thread %zu: exception_stack_base: %p, exception_stack: %p, backup_user_stack: %p\n", 
            tid,
            thread_data->exception_stack_base,
            thread_data->exception_stack,
            thread_data->backup_user_stack
        );

        for (size_t did = 0; did < NUM_DOMAINS; did++) {
            if (!dm_data.domains[did].used) {
                continue;
            }
            _dm_thread_domain threaddomaindata = thread_data->thread_domain_data[did];
            if(!threaddomaindata.user_stack_base){
                continue;
            }
            fprintf(stderr, "\t└ Domain %zu: user_stack_base/size: %p -- %p\n", 
                did, threaddomaindata.user_stack_base, threaddomaindata.user_stack_base + threaddomaindata.user_stack_size);

            _expected_return * expected_return = threaddomaindata.expected_return;
            //fprintf(stderr, "\t\t└ expected_return:\n");
            while(expected_return){
                fprintf(stderr, "\t\t└ expected_return (current thread): did=%d, ReturnAddr=%p, previous=%14p",
                    expected_return->did,
                    expected_return->reentry,
                    expected_return->previous
                );
                #ifdef ADDITIONAL_DEBUG_CHECKS
                    fprintf(stderr, ", sp=%14p", expected_return->sp);
                #endif
                fprintf(stderr, "\n");
                expected_return = expected_return->previous;
            }
        }
    }

    for (size_t did = 0; did < NUM_DOMAINS; did++) {
        if (!dm_data.domains[did].used) {
            continue;
        }
        fprintf(stderr, "[INFO] Domain %zu:\n", did);
        _dm_domain dom = dm_data.domains[did];

        fprintf(stderr, "\t└ parent_did = %d\n", dom.parent_did);
        fprintf(stderr, "\t└ ISA id = %d\n", dom.isa_did);
        fprintf(stderr, "\t└ is ISA inherit = %d, is ISA can be modified%d \n", dom.is_inherit, dom.can_update_isa);

        fprintf(stderr, "\t└ default_config:  ");
        dm_print_reg_arch(dom.default_config);

        fprintf(stderr, "\t└ keys: [");
        for (size_t KeyID = 0; KeyID < NUM_KEYS_PER_DOMAIN; KeyID++) {
            if (dom.keys[KeyID].used) {
              fprintf(stderr, "%d-%d(%s), ",
                  dom.keys[KeyID].pkey, dom.keys[KeyID].vkey,
                  dom.keys[KeyID].owner ? "owner" : "copy"
              );
          }
        }
        fprintf(stderr, "]\n");

        fprintf(stderr, "\t└ allowed_source_domains: [");
        for (size_t i = 0; i < dom.allowed_source_domains_count; i++) {
            fprintf(stderr, "%d, ", dom.allowed_source_domains[i]);
        }
        fprintf(stderr, "]\n");
    }

    fprintf(stderr, "[INFO] Memory ranges:\n");
    for (size_t range_id = 0; range_id < NUM_MPROTECT_RANGES; range_id++) {
        mprotect_t range = dm_data.ranges[range_id];
        if (range.used) {
            fprintf(stderr, "\t└ mprotect-range %zu: addr=%16p -- %16p, len=0x%8zx, prot=%2d, key=%2d-%2d\n", 
            range_id, range.addr, 
            (void*)((uintptr_t)range.addr + range.len), range.len, range.prot, range.pkey, range.vkey);
        }
    }

    //fprintf(stderr, COLOR_RESET);
    fprintf(stderr, "\n");
}

//------------------------------------------------------------------------------
int D_CODE _dm_update_isaBuffer(const UpdateBitmapParams* params){
    assert(check_domain_exists(params->domainId));
    int update_isa_id = dm_data.domains[params->domainId].isa_did;

    int update_size = 3 + 2 * (params->instCount + params->regReadCount + params->regWriteCount);
    int* updates = malloc(update_size * sizeof(int));
    if (!updates) {
        return -1; // 内存分配失败
    }

    updates[0] = params->instCount;
    updates[1] = params->regReadCount;
    updates[2] = params->regWriteCount;

    int offset = 3;

    for (int i = 0; i < params->instCount; i++) {
        int instIndex = getInstructionIndexByName(params->instNames[i]);
        updates[offset++] = instIndex;
        updates[offset++] = params->instValues[i];
    }

    for (int i = 0; i < params->regReadCount; i++) {
        int regIndex = getRegisterIndexByName(params->regReadNames[i]);
        updates[offset++] = regIndex;
        updates[offset++] = params->regReadValues[i];
    }

    for (int i = 0; i < params->regWriteCount; i++) {
        int regIndex = getRegisterIndexByName(params->regWriteNames[i]);
        updates[offset++] = regIndex;
        updates[offset++] = params->regWriteValues[i];
    }
    
    int result = isa_update_bitBuffer(UPDATE_DOMAIN, update_isa_id, (void *)updates, update_size * sizeof(int));

    free(updates);
    return result;
}

//------------------------------------------------------------------------------
//  TODO   一个简单测试的 API 
int D_CODE _test_simple_api(int a, int b, int c, int d, int e, int f){
    int ret = a+b+c+d+e+f;
    DEBUG_MPK("_test_simple_api(a=%d, b=%d, c=%d, d=%d, e=%d, f=%d). returning %d", a,b,c,d,e,f, ret);
    return ret;
}

//------------------------------------------------------------------------------
void* D_CODE _dm_malloc(size_t size) {
    DEBUG_MPK("_dm_malloc");
    return malloc(size);
}
//------------------------------------------------------------------------------
int D_CODE _dm_unused(){
    ERROR("This API call is not implemented");
    errno = ENOSYS;
    return -1;
}
//------------------------------------------------------------------------------

D_DATA void (*_dm_api_table[API_TABLE_SIZE]) = {
    [_API_unused0]                       = _dm_unused,
    [_API_dm_deinit]                     = _deinit_root_domain,
    [_API_dm_current_did]                = _dm_current_did,
    [_API_dm_register_exception_handler] = _dm_register_exception_handler,
    [_API_unused4]                       = _dm_unused,
    [_API_dm_domain_create]              = _dm_domain_create,
    [_API_dm_domain_free]                = _dm_domain_free,
    [_API_dm_domain_release_child]       = _dm_domain_release_child,
    [_API_unused8]                       = _dm_unused,
    [_API_unused9]                       = _dm_unused,
    [_API_dm_pkey_alloc]                 = _dm_pkey_alloc,
    [_API_dm_pkey_free]                  = _dm_pkey_free,
    [_API_dm_pkey_mprotect]              = _dm_pkey_mprotect,
    [_API_unused13]                      = _dm_unused,
    [_API_unused14]                      = _dm_unused,
    [_API_unused15]                      = _dm_unused,
    [_API_unused16]                      = _dm_unused,
    [_API_unused17]                      = _dm_unused,
    [_API_unused18]                      = _dm_unused,
    [_API_unused19]                      = _dm_unused,
    [_API_dm_mmap]                       = _dm_mmap,
    [_API_dm_mmap2]                      = _dm_mmap2,
    [_API_dm_mmap3]                      = _dm_mmap3,
    [_API_unused23]                      = _dm_unused,
    [_API_dm_munmap]                     = _dm_munmap,
    [_API_unused25]                      = _dm_unused,
    [_API_dm_mprotect]                   = _dm_mprotect,
    [_API_unused27]                      = _dm_unused,
    [_API_unused28]                      = _dm_unused,
    [_API_unused29]                      = _dm_unused,
    [_API_unused30]                      = _dm_unused,
    [_API_dm_domain_register_ecall]      = _dm_domain_register_ecall,
    [_API_dm_domain_allow_caller]        = _dm_domain_allow_caller,
    [_API_dm_domain_allow_caller2]       = _dm_domain_allow_caller2,
    [_API_dm_domain_assign_pkey]         = _dm_domain_assign_pkey,
    [_API_dm_domain_default_key]         = _dm_domain_default_key,
    [_API_dm_domain_load_key]            = _dm_domain_load_key,
    [_API_unused37]                      = _dm_unused,
    [_API_unused38]                      = _dm_unused,
    [_API_update_isaBuffer]              = _dm_update_isaBuffer,
    [_API_dm_pthread_create]             = _dm_pthread_create,
    [_API_dm_pthread_exit]               = _dm_pthread_exit,
    [_API_dm_print_debug_info]           = _dm_print_debug_info,
    [_API_test_simple_api]               = _test_simple_api,
    [_API_dm_malloc]                     = _dm_malloc,
};
//------------------------------------------------------------------------------




