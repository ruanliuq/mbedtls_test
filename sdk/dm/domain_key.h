// dm.h
#pragma once

#include "dm_defines.h"
#include "dm_debug.h"
#include "dm_key_arch.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif
//------------------------------------------------------------------------------


#define WORDSIZE 8 //sizeof(uint64_t)
#define PAGESIZE 4096
#define PAGEMASK (PAGESIZE-1)
#define MAX_NUM_KEYS 1023 // NOTE: 1023 is an invalid key. the kernel should never give this key away.
// PK_NUM_KEYS
#define SHARED_MAX 4096

// #define PK_DOMAIN_ROOT               0
#define DOMAIN_ROOT                   0
#define DOMAIN_GET_CURRENT           -1
#define DOMAIN_ANY                   -2
// #define PK_DOMAIN_ANY               -2

#define PK_SLOT_ANY                 -1
#define PK_SLOT_NONE                -2

//   TODO  未分析
#define PK_ECALL_ANY      -1

// Indicates that it needs to be obtained via get_default_vkey
#define GET_DEFAULT_VKEY              -1

// Max. number of distinct contiguous memory regions dm can track
#define NUM_MPROTECT_RANGES 4096

enum {
  PK_OWNER_KEY   = 1,
  PK_COPY_KEY    = 2,
  PK_SHARED_KEY  = 4,
  PK_INHERIT_KEY = 8,
};

// Virtual protection key   vkey > 0
typedef int vkey_t;
#define VKEY_MAX INT_MAX
#define VKEY_INVALID                -1


//------------------------------------------------------------------------------
// PK API Functions
//------------------------------------------------------------------------------

int domain_manager_init(void);
int domain_manager_deinit(void);
int dm_current_did(void);
int dm_register_exception_handler(void (*handler)(void*));
int dm_domain_create(unsigned int flags);
int dm_domain_free(int did);
int dm_domain_release_child(int did);
vkey_t dm_pkey_alloc(unsigned int flags, unsigned int access_rights);
int dm_pkey_free(vkey_t vkey);
int dm_pkey_mprotect(int did, void *addr, size_t len, int prot, vkey_t vkey);
void* dm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* dm_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* dm_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int dm_munmap(int did, void* addr, size_t len);
int dm_mprotect(int did, void *addr, size_t len, int prot);
int dm_domain_register_ecall(int did, int ecall_id, void* entry);
int dm_domain_allow_caller(int caller_did, unsigned int flags);
int dm_domain_allow_caller2(int did, int caller_did, unsigned int flags);
int dm_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);
int dm_domain_default_key(int did);
int dm_domain_load_key(vkey_t vkey, int slot, unsigned int flags);
void dm_print_debug_info(void);

int dm_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine) (void *), void *arg);
int dm_pthread_exit(void *retval);
int  test_simple_api(int a, int b, int c);

void  dm_print_current_reg(void);


#ifdef __cplusplus
}
// TODO 是否需要?
// #include "pku_wrapper.h"
#endif

#endif // __ASSEMBLY__
