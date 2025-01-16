#pragma once

#include "dm_defines.h"
#include "dm_handler.h"

//------------------------------------------------------------------------------
//Defines for the API table
//NOTE this cannot be an enum because we need the values in assembly
#define _API_unused0                       0
#define _API_dm_deinit                     1
#define _API_dm_current_did                2
#define _API_dm_register_exception_handler 3
#define _API_unused4                       4
#define _API_dm_domain_create              5
#define _API_dm_domain_free                6
#define _API_dm_domain_release_child       7
#define _API_unused8                       8
#define _API_unused9                       9
#define _API_dm_pkey_alloc                10
#define _API_dm_pkey_free                 11
#define _API_dm_pkey_mprotect             12
#define _API_unused13            13
#define _API_unused14                     14
#define _API_unused15                     15
#define _API_unused16                     16
#define _API_unused17                     17
#define _API_unused18                     18
#define _API_unused19                     19
#define _API_dm_mmap                      20
#define _API_dm_mmap2                     21
#define _API_dm_mmap3                     22
#define _API_unused23                    23
#define _API_dm_munmap                   24
#define _API_unused25                  25
#define _API_dm_mprotect                 26
#define _API_unused27                     27
#define _API_unused28                     28
#define _API_unused29                     29
#define _API_unused30                     30
#define _API_dm_domain_register_ecall    31
#define _API_dm_domain_allow_caller       32
#define _API_dm_domain_allow_caller2      33
#define _API_dm_domain_assign_pkey        34
#define _API_dm_domain_default_key        35
#define _API_dm_domain_load_key           36
#define _API_unused37                     37
#define _API_unused38                     38
#define _API_update_isaBuffer                     39
#define _API_dm_pthread_create            40
#define _API_dm_pthread_exit              41
#define _API_dm_print_debug_info          42
#define _API_test_simple_api           43
#define _API_dm_malloc                    44
#define API_TABLE_SIZE                    45 // must be exactly 1 more than the highest API id
//------------------------------------------------------------------------------

/**********************************************************************/
// Global Defines
/**********************************************************************/

// Max. number of ECALLs (over all domains)
#define NUM_REGISTERED_ECALLS 64

#define KEY_FOR_UNPROTECTED       0
#define KEY_FOR_ROOT_DOMAIN       1
#define KEY_FOR_EXCEPTION_HANDLER 2

#define DID_FOR_ROOT_DOMAIN       0
#define INVALID_DID              -1
#define DID_FOR_EXCEPTION_HANDLER 1
#define DID_FOR_SERVER_DOMAIN     2

//------------------------------------------------------------------------------
// wwwwwww   shoud be check save or delete
#define EXCEPTION_STACK_WORDS (1024*(PAGESIZE/WORDSIZE)) // 4MB


/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>

#include "domain_key.h"
#include "dm_debug.h"
#include "syscall.h"


#ifdef __cplusplus
extern "C" {
#endif
//------------------------------------------------------------------------------
#ifndef SHARED
// extern 是一个存储类说明符，它表示这个变量是在别的源文件中定义的，这个源文件只是引用它
// uintptr_t 是一个可选的无符号整数类型，它可以存储一个指向 void 的指针，然后再转换回指针，结果与原来的指针相等。
// 它通常与指针一样大小,定义在 <cstdint> 头文件
extern uintptr_t __start_dm_all[];
extern uintptr_t __stop_dm_all[];
extern uintptr_t __start_dm_data[];
extern uintptr_t __stop_dm_data[];
extern uintptr_t __start_dm_code[];
extern uintptr_t __stop_dm_code[];

extern uintptr_t __tls_static_start[];
extern uintptr_t __tls_static_end[];
#endif


//------------------------------------------------------------------------------
// Generic PK typedefs
//------------------------------------------------------------------------------

/* Struct which is pushed on caller stack upon dcall, and verified upon dreturn */
typedef struct _expected_return {
    int      did;
    void *   reentry;
    void *   previous;
#ifdef ADDITIONAL_DEBUG_CHECKS
    void *   sp;
    uint64_t cookie;
#endif
#ifdef EXPECTED_RETURN_PADDING
    unsigned char padding[EXPECTED_RETURN_PADDING];
#endif
} _expected_return;

//------------------------------------------------------------------------------

/* 用于维护域的保护键的结构 */
typedef struct __attribute__((packed)) {
    vkey_t   vkey;            // 虚拟密钥，防止重放攻击
    pkey_t   pkey;            // protection key
    bool     owner : 1;       // 是否是 key 的所有者
    int      perm  : 4;       // key 的权限
    bool     used  : 1;       // Is key slot used
    int      _reserved : 10;
} domain_key_t;
// pk_key_t
//------------------------------------------------------------------------------

/* Struct which is pushed on target stack upon dcall such that it knows where to return to */
typedef struct _return_did {
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie1;
#endif
    int64_t did;
#ifdef ADDITIONAL_DEBUG_CHECKS
    uint64_t cookie2;
#endif
} _return_did;
//------------------------------------------------------------------------------

/* 表示域的结构体 */
typedef struct _dm_domain {
    bool           used;         // Is domain slot used
    int           parent_did;   // did of domain which created this domain, or -1 if none
    int           child_num;
    int           child[NUM_DOMAINS];   // 域的子域id，delete 用
    int           isa_did;
    bool          is_inherit;
    bool          can_update_isa;
    domain_key_t  keys[NUM_KEYS_PER_DOMAIN];    // 每个域hold的key List
    
    // TODO Caches pkru config
    pkru_config_t default_config;
    int           previous_slot;  // 保存先前的槽，用于密钥轮询

    // List of domains that can call into our domain
    int           allowed_source_domains[NUM_SOURCE_DOMAINS]; 
    // Number of valid domains in allowed_source_domains
    size_t        allowed_source_domains_count;  

} _dm_domain;
// _pk_domain
//------------------------------------------------------------------------------
/* Struct for storing stack information in TLS */
typedef struct _dm_thread_domain {
    _expected_return * expected_return; // points to the stack where the struct lives in case a dcall is pending (waiting for return), or null.
    uint64_t *         user_stack_base; // base address of user stack
    size_t             user_stack_size; // size in bytes
} _dm_thread_domain;
// _pk_thread_domain;
//------------------------------------------------------------------------------
/* Struct for keeping trusted data in TLS */
typedef  struct  __attribute__ ((packed)) _dm_tls{
#ifdef TLS_MISALIGNMENT_BUG
    char padding1[PAGESIZE];
#endif

    uint64_t * backup_user_stack;    // This must be the first element for asm code to work. 
                                     // holds user stack pointer during exception handling
    uint64_t * exception_stack;      // This must be the second element for asm code to work. top of exception stack, used for exception handling
    uint64_t * exception_stack_base; // base address of exception stack
    pkru_config_t current_pkru;      // This must be the fourth element for asm code to work. 
                                     // holds current pkru config for this thread and is also needed for _dm_domain_is_key_loaded_arch

    _dm_thread_domain thread_domain_data[NUM_DOMAINS] __attribute__((aligned(8)));; // User stacks for all domains this thread visits
                                                   

    int current_did;                 // domain ID in which thread is currently executing
    int tid;                         // thread ID
                                     // 在dm_data.threads[]中的索引
    bool init;                       // Is the thread already initialized by our library? If not, current_did and other fields are invalid, and CURRENT_DID might not be used

// 可以删掉这个了
#ifdef TLS_MISALIGNMENT_BUG
    char padding2[PAGESIZE];
#endif
} _dm_tls;
// _pk_tls
//------------------------------------------------------------------------------




//------------------------------------------------------------------------------
/* Struct for book-keeping memory mappings */
typedef struct mprotect_t {
    void *   addr;  // start address
    size_t   len;   // length in bytes
    int      prot;  // page permissions, according to mmap/mprotect
    vkey_t   vkey;  // virtual protection key
    pkey_t   pkey;  // physical protection key
    bool   used;    // shows whether this mprotect_t slot is in use or not
} mprotect_t;
//------------------------------------------------------------------------------
typedef struct pthread_arg_t{
  void* exception_stack;
  void* exception_stack_top;
  void* start_routine;
  void* arg;
  int current_did;
} pthread_arg_t;
// 将pthread_create 参数从父节点临时传递给子节点
//------------------------------------------------------------------------------
/* 所有基本数据的全局结构体 */
typedef struct _dm_data {
    int             initialized;
    // TODO 锁变量
    pthread_mutex_t mutex;                              // Global PK mutex
    pthread_mutex_t condmutex;                          // Mutex for cond
    pthread_cond_t  cond;                               // Condition variable for syncing pthread creation
    int             pagesize;                           // 页面大小：4KB
    size_t          stacksize;                          // Size of user stacks we lazily allocating pthread stacks

    pthread_arg_t   pthread_arg;                        // 将 pthread_create 参数从父线程传递到子线程

    void            (*user_exception_handler)(void*);   // TODO    异常处理程序 Forward pk exceptions to a user program (currently only for debugging)

    _dm_domain      domains[NUM_DOMAINS];               // List of all domains

    _dm_tls *       threads[NUM_THREADS];               // Pointers to TLS to manage threads which are currently not running
    mprotect_t      ranges[NUM_MPROTECT_RANGES];        // List of memory mappings
    
    // TODO 内存映射要和 keystone 结合
} _dm_data;
// _pk_data
//------------------------------------------------------------------------------

/* Struct for registered ecalls */
typedef struct _dm_ecall {
    void * entry;   // Ecall entry point
    int did;        // Ecall registered for this domain
} _dm_ecall;
//------------------------------------------------------------------------------




//------------------------------------------------------------------------------
// Internal API functions    
//------------------------------------------------------------------------------
int D_CODE _init_root_domain(void);
int D_CODE _deinit_root_domain(void);
int D_CODE  _dm_current_did(void);

int D_CODE  _dm_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);

void D_CODE  _dm_pthread_exit(void* retval);
int D_CODE      _dm_register_exception_handler(void (*handler)(void*));
int D_CODE  _dm_domain_create(unsigned int flags, unsigned int isa_set);
int D_CODE  _dm_domain_free(int did);
int D_CODE  _dm_domain_release_child(int did);
int D_CODE  _dm_pkey_free(vkey_t vkey);
vkey_t D_CODE  _dm_pkey_alloc(unsigned int flags, unsigned int access_rights);
int D_CODE  _dm_pkey_mprotect(int did, void *addr, size_t len, int prot, vkey_t vkey);
void* D_CODE  _dm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* D_CODE  _dm_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* D_CODE  _dm_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* D_CODE  _dm_mmap_internal(int did, vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int D_CODE  _dm_munmap(int did, void* addr, size_t len);
int D_CODE  _dm_mprotect(int did, void *addr, size_t len, int prot);
int D_CODE  _dm_domain_register_ecall(int did, int ecall_id, void* entry);
int D_CODE  _dm_domain_allow_caller(int caller_did, unsigned int flags);
int D_CODE  _dm_domain_allow_caller2(int did, int caller_did, unsigned int flags);
int D_CODE  _dm_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);
int D_CODE  _dm_domain_default_key(int did);
int D_CODE  _dm_domain_load_key(vkey_t vkey, int slot, unsigned int flags);
void D_CODE  _dm_print_debug_info(void);
int D_CODE  _test_simple_api(int a, int b, int c, int d, int e, int f);
void* D_CODE  _dm_malloc(size_t size);
int D_CODE _dm_unused(void);

//------------------------------------------------------------------------------
// Internal functions    
//------------------------------------------------------------------------------
int D_CODE   _dm_exception_key_mismatch_underlocked(void * access_addr);

uint64_t D_CODE  _dm_exception_handler_underlocked(uint64_t data, uint64_t id, uint64_t type, uint64_t * current_stack, void * reentry);
void     D_CODE handle_type_call(uint64_t id, uint64_t *current_stack, void *reentry, int current_did);
void   D_CODE handle_type_ret(uint64_t id, uint64_t *current_stack, int current_did);
int    D_CODE  _dm_pkey_mprotect_underlocked(int did, void *addr, size_t len, int prot, vkey_t vkey);
int    D_CODE  _dm_pkey_mprotect_cur_did_underlocked(int did, void *addr, size_t len, int prot, vkey_t vkey);
vkey_t D_CODE   _dm_pkey_alloc_underlocked(int did, unsigned int flags, unsigned int access_rights);

int D_CODE   _dm_domain_assign_pkey_underlocked(int source_did, int target_did, vkey_t vkey, int flags, int access_rights);
int D_CODE   _dm_domain_load_key_underlocked(int did, vkey_t vkey, int slot, unsigned int flags);

int   D_CODE  _dm_initialize_thread(int did, void* exception_stack);
void* D_CODE  _dm_setup_thread_exception_stack(void);
int   D_CODE  _dm_domain_create_underlocked(unsigned int flags, unsigned int isa_set);
void  D_CODE     _pthread_init_function_c(void * start_routine, void * current_user_stack);

// TODO?
void* D_CODE _allocate_stack(size_t stack_size);
bool  D_CODE _untrack_memory(void *addr, size_t len);
bool  D_CODE _track_memory(void *addr, size_t len, int prot, vkey_t vkey, pkey_t pkey);

int D_CODE _dm_update_isaBuffer(const UpdateBitmapParams* params);

//------------------------------------------------------------------------------
// Variable declarations
//------------------------------------------------------------------------------
extern _dm_data dm_data;                  // Global dm data
extern __thread _dm_tls  dm_trusted_tls;  // Per-thread dm data
extern uint64_t _dm_ttls_offset;          // Offset of dm_trusted_tls from thread pointer (fs on x86, or tp on RISC-V)


//------------------------------------------------------------------------------
// Inline functions
//------------------------------------------------------------------------------

// TODO   static inline ==>  FORCE_INLINE
// TODO seL4
static inline int _dm_initialize_lock() {
  int ret;
  pthread_mutexattr_t attr;
  if (0 != pthread_mutexattr_init(&attr) ||
      0 != pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
    ERROR("Unable to initialize mutex attributes");
    errno = EINVAL;
    return -1;
  }
  ret = pthread_mutex_init(&dm_data.mutex, &attr);
  if (ret) {
    ERROR("Unable to initialize mutex");
    errno = EINVAL;
    return -1;
  }
  assert(0 == pthread_mutexattr_destroy(&attr));

  ret = pthread_mutex_init(&dm_data.condmutex, NULL);
  if (ret) {
    ERROR("Unable to initialize cond-mutex");
    errno = EINVAL;
    return -1;
  }

  ret = pthread_cond_init(&dm_data.cond, NULL);
  if (ret) {
    ERROR("Unable to initialize condition variable");
    errno = EINVAL;
    return -1;
  }

  return 0;
}
//------------------------------------------------------------------------------

// TODO   static inline ==>  FORCE_INLINE
// TODO seL4
static inline void _dm_acquire_lock() {
  DEBUG_MPK("start %p", (void*)pthread_self());
  assert(0 == pthread_mutex_lock(&dm_data.mutex));
  DEBUG_MPK("end");
}
//------------------------------------------------------------------------------

// TODO   static inline ==>  FORCE_INLINE
// TODO seL4
static inline void _dm_release_lock() {
  DEBUG_MPK("start %p", (void*)pthread_self());
  int ret = pthread_mutex_unlock(&dm_data.mutex);
  DEBUG_MPK("res: %d: %s", ret, strerror(ret));
  assert(0 == ret);
  DEBUG_MPK("release lock end");
}
//------------------------------------------------------------------------------
static inline int cleanup_and_exit(int err_code, const char* error_msg, int lock_held) {
    if (err_code != 0){
        errno = err_code;
    }
    if (error_msg != NULL) {
        ERROR("%s", error_msg);
    }
    if (lock_held) {
        _dm_release_lock();
    }
    return -1;
}
//------------------------------------------------------------------------------

// TODO   static inline ==>  FORCE_INLINE
// TODO seL4
static inline void _dm_wait_cond() {
  DEBUG_MPK("lock");
  assert(0 == pthread_mutex_lock(&dm_data.condmutex));
  DEBUG_MPK("wait");
  assert(0 == pthread_cond_wait(&dm_data.cond, &dm_data.condmutex));
  DEBUG_MPK("unlock");
  assert(0 == pthread_mutex_unlock(&dm_data.condmutex));
  DEBUG_MPK("end");
}
//------------------------------------------------------------------------------

// TODO   static inline ==>  FORCE_INLINE
// TODO seL4
static inline void _dm_signal_cond() {
  DEBUG_MPK("start");
  assert(0 == pthread_cond_signal(&dm_data.cond));
  DEBUG_MPK("end");
}
//------------------------------------------------------------------------------


#ifdef __cplusplus
}
#endif

#endif // __ASSEMBLY__