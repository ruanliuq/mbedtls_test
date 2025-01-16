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


//  TODO  修改？   This is for user programs to use !?

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
// isa_set
enum {
    ISA_INHERIT = 1,
    ISA_CANNOT_UPDATE = 2,
};

// Virtual protection key   vkey > 0
typedef int vkey_t;
#define VKEY_MAX INT_MAX
#define VKEY_INVALID                -1

typedef struct {
    uintptr_t domainId;
    const char** instNames;     // 指令名称数组
    int* instValues;            // 对应的权限值数组
    int instCount;              // 指令数量

    const char** regReadNames;  // 寄存器读权限名称数组
    int* regReadValues;         // 寄存器读权限值数组
    int regReadCount;           // 读寄存器数量

    const char** regWriteNames; // 寄存器写权限名称数组
    int* regWriteValues;        // 寄存器写权限值数组
    int regWriteCount;          // 写寄存器数量
} UpdateBitmapParams;


//------------------------------------------------------------------------------
// PK API Functions
//------------------------------------------------------------------------------
 /**
 * @brief Initialize Domain manager
 * 函数将会设置当前代码作为根域，其did等于0.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 */
int domain_manager_init(void);

/**
 * @brief Deinitialize PK
 *
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 */
int domain_manager_deinit(void);


int dm_current_did(void);
int dm_register_exception_handler(void (*handler)(void*));

/**
 * @brief Create a new domain
 * 函数创建一个拥有自己私有保护密钥的新保护域。新域将是当前域的子域。
 * @param flags
 *         0
 *            Protection key of new domain is guaranteed to be unique
 *         @c PK_SHARED_KEY
 *            Protection key of new domain can be shared. This allows
 *            to allocate a higher number of protection keys than the
 *            architecture natively supports. However, it only gives
 *            probabilistic isolation guarantees.
 *         @c PK_INHERIT_KEY
 *            Protection key of new domain is inherited to the calling
 *            domain as if the new domain executed @c dm_domain_assign_pkey(
 *                did, vkey, 0 [|PK_COPY_KEY] [|PK_OWNER_KEY], 0)
 *         @c PK_COPY_KEY
 *            Only valid with @c PK_INHERIT_KEY
 *         @c PK_OWNER_KEY
 *            Only valid with @c PK_INHERIT_KEY
 * @param isa_set
 *         0
 *            Default value, which is not inherited and allows permission modification
 *         @c ISA_INHERIT
 *            Inherits the ISA permissions of the parent domain
 *         @c ISA_CANNOT_UPDATE
 *            Whether the ISA permission of the domain can be modified
 * @return
 *        The new domain id @c did, which is always positive,
 *        or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p flags are invalid.
 *        @c ENOMEM
 *            if there is no more space for new domains
 */
int dm_domain_create(unsigned int flags, unsigned int isa_set);

/**
 * @brief Frees a domain
 * 
 * This function cleans up a protection domain, reclaim the key and domain ID. 
 * If the ISA ID is non-inherited, ISA ID is also reclaimed.
 * If the parent domain needs to be free, call @c dm_domain_release_child to release all subdomains, 
 * and set the parent ID of the subdomain to @c DID_FOR_ROOT_DOMAIN
 * Only the root domain, the parent domain of the current domain, and the current domain itself can call this function
 * It requires any allocated protection keys to be free'd.
 * 
 * @param did
 *        The domain to free. Can be @c CURRENT_DID.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not a child domain
 *        @c EPERM
 *            if @p did has allocated protection keys that are not yet
 *            free'd
 */
int dm_domain_free(int did);

/**
 * @brief Relinquish control over child domain. It's like a parent-child process
 * 
 * This function removes a parent-child relationship such that the
 * calling domain cannot act on behalf of its child anymore.
 *
 * @param did 
 *        The child domain to release.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not a child domain
 */
int dm_domain_release_child(int did);

/**
 * @brief Allocate a new protection key. 
 * 
 * This function allocates a new protection key via @c pkey_alloc. syscall
 * In addition, it assigns the allocated protection key to the
 * current protection domain. The protection key might be transferred to
 * other domains via @c dm_domain_assign_pkey.
 * 
 * @param flags
 *         0
 *            Allocated protection key is guaranteed to be unique
 *         @c PK_SHARED_KEY
 *            Allocated protection key can be shared across different calls
 * @param access_rights 
 *         may contain zero or more disable operations:
 *         @c PKEY_DISABLE_ACCESS
 *            Disables both read and write access. Code fetces might
 *            still be allowed, depending on the architecture.
 *         @c PKEY_DISABLE_WRITE
 *            Disables write access.
 * @return
 *        The allocated protection key, which is always positive,
 *        or VKEY_INVALID (which is -1) on error, and errno is set to:
 *        @c EINVAL
 *            if @p flags or @p access_rights is invalid.
 *        @c ENOSPC
 *            if no more free protection keys are available, or the
 *            architecture does not support protection keys.
 */
vkey_t dm_pkey_alloc(unsigned int flags, unsigned int access_rights);

/**
 * @brief Free a protection key
 * 
 * This function frees a protection key. It does so by first
 * unloading it from the current thread via 
 * @c dm_domain_load_key(CURRENT_DID, SLOT_NONE, 0), and then
 * handing it back to the kernel via @c pkey_free.
 * 
 * In order to free a vkey, it must not be in use, e.g. by @c dm_pkey_mprotect.
 * Either unuse it by another call to @c dm_pkey_mprotect clearing the
 * @p vkey, or unmap all relevant pages first via @c dm_unmap. Also, 
 * the key must not be loaded in foreign threads via @c dm_domain_load_key, 
 * or it must be unloaded first via 
 * @c dm_domain_load_key(CURRENT_DID, SLOT_NONE, 0).
 * 
 * The protection key has to be allocated via @c dm_pkey_alloc. A domain
 * cannot free its default key. Moreover, the current domain needs
 * to have ownership. A domain has ownership either by executing
 * @c dm_pkey_alloc itself and not delegating ownership, or it was
 * granted ownership via @c dm_domain_assign_pkey and the
 * @c PK_OWNER_KEY flag.
 * 
 * The @p vkey is free'd for all domains 
 * that may hold a copy via
 * @c dm_domain_assign_pkey with the @c PK_COPY_KEY flag.
 *
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if current domain does not own @p vkey.
 *        @c EPERM
 *            if key is still in use
 */
int dm_pkey_free(vkey_t vkey);


/**
 * @brief Protect a memory range with a protection key
 * 
 * This function protects a memory range via @c pkey_mprotect. In addition,
 * the current domain needs to have access to @p vkey, and the requested
 * protection needs to be allowed by this @p vkey.
 *
 * @param did
 *        The domain to which the memory range belongs. Must be the
 *        current or a child domain. If omitted or set to
 *        @c CURRENT_DID, the current domain.
 * @param addr
 *        The page-aligned address pointing to the start of the memory
 *        range to protect.
 * @param len
 *        The length in bytes of the memory range to protect.
 * @param prot
 *        Any combination of @c PROT_NONE, @c PROT_READ, @c PROT_WRITE,
 *        @c PROT_EXEC, etc. allowed by @c pkey_mprotect.
 * @param vkey
 *        The protection key. Can be @c GET_DEFAULT_VKEY to specify the
 *        default key of the domain @p did.
 * @return
 *        0 on success, or -1 on error, and errno is set according to @c pkey_mprotect
 *        @c EINVAL
 *            if @p vkey is invalid.
 *        @c EACCES
 *            if @p did is not current or child domain, or
 *            if current domain does not own @p vkey, or
 *            if the address range is owned by a different @p vkey
 *        @c ENOMEM
 *            if there is no more space for keeping track of mprotect calls
 *        Any other error code specified for @c pkey_mprotect.
 */
int dm_pkey_mprotect(int did, void *addr, size_t len, int prot, vkey_t vkey);

/**
 * @brief Map a memory range
 * 
 * This function maps a memory range via a call to @c mmap.
 * In addition, it protects the mapped range with the domain's default
 * 
 * @param did
 *        The domain to which the memory range shall be assigned. Must be
 *        the current or a child domain. If omitted, is set to
 *        @c CURRENT_DID.
 * @param vkey
 *        The protection key. If omitted, is set to @c GET_DEFAULT_VKEY to
 *        specify the default key of the domain @p did.
 * @param addr
 *        see @c mmap
 * @param length
 *        see @c mmap
 * @param prot
 *        see @c mmap
 * @param flags
 *        see @c mmap
 * @param fd
 *        see @c mmap
 * @param offset
 *        see @c mmap
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c mmap, or @c dm_pkey_mprotect.
 */
void* dm_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* dm_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* dm_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);

/**
 * @brief Unmap a memory range
 * 
 * This function unmaps a memory range via a call to @c munmap.
 * The memory has to be owned by @p did. 
 *
 * @param did
 *        The domain from which the memory range shall be freed. Must be
 *        the current or a child domain. If omitted, is set to
 *        @c CURRENT_DID.
 * @param addr
 *        see @c munmap
 * @param len
 *        see @c munmap
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c munmap
 */
int dm_munmap(int did, void* addr, size_t len);

/**
 * @brief Protect a memory range
 * 
 * This function protects a memory range via a call to @c mprotect.
 * While this function does not modify protection keys, it verifies
 * that the memory range's protection keys are owned by the calling
 * domain.
 *
 * @param did
 *        The domain from which the memory range shall be protected.
 *        Must be the current or a child domain. If omitted, is set to
 *        @c CURRENT_DID.
 * @param addr
 *        see @c mprotect
 * @param len
 *        see @c mprotect
 * @param prot
 *        see @c mprotect
 * @return 
 *        0 on success, or -1 on error, and errno is set according to 
 *        @c mprotect
 */
int dm_mprotect(int did, void *addr, size_t len, int prot);

/**
 * @brief Register a new ecall.
 * 
 * This function registers a new ecall with which another domain can
 * call the specified domain.
 * 
 * @param did
 *        The domain for which a new ecall shall be registered.
 *        If omitted or set to @c CURRENT_DID, the current domain.
 * @param ecall_id
 *        The positive, unique id of the ecall. If @c PK_ECALL_ANY, the implementation
 *        allocates the next free ecall id.
 * @param entry
 *        The entry point of the ecall
 * @return
 *        the positive ecall_id on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is neither the current domain nor a child domain.
 *        @c EINVAL
 *            if @p entry does not point into the memory of @p did, or
 *            @p ecall_id is invalid.
 *        @c ENOMEM
 *            if there is no more space for registering ecalls
 */
int dm_domain_register_ecall(int did, int ecall_id, void* entry);

/**
 * @brief Permit other domains to invoke ecalls.
 *
 * This function permits other domains to invoke ecalls of the specified
 * domain.
 *
 * @param did
 *        The domain to which ecalls are permitted.
 *        If omitted or set to @c CURRENT_DID, the current domain.
 * @param caller_did
 *        The domain which is permitted to invoke ecalls of @p did. 
 *        If @c DOMAIN_ANY, any current and future domain is permitted
 *        to invoke ecalls of @p did
 * @param flags
 *        Optional flags for future use. Must be 0 in current implementations.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is neither the current domain nor a child domain.
 *        @c EINVAL
 *            if @p caller_did or @p flags are invalid.
 *        @c ENOMEM
 *            if there is no more space for new callers
 */
int dm_domain_allow_caller(int caller_did, unsigned int flags);
int dm_domain_allow_caller2(int did, int caller_did, unsigned int flags);

/**
 * @brief Assign a protection key to a domain
 * 
 * This function assigns a protection key to a domain. The key has to
 * be allocated via @a dm_pkey_alloc, and the current domain needs to
 * have proper access to it. A domain can assign a protection key if
 * it has executed @a dm_pkey_alloc itself and did not transfer ownership,
 * or it was granted access to the key via @a dm_domain_assign_pkey without
 * the @c PK_COPY_KEY flag.
 * 
 * A domain can also assign a protection key to itself, in which case
 * the original key will be lost. E.g. a domain can drop @p access_rights
 * onto a @p vkey while keeping ownership via @c PK_OWNER_KEY, or losing
 * ownership via @c PK_COPY_KEY. 
 * 
 * @param did 
 *        The domain to assign the protection key to. Can be 
 *        @c CURRENT_DID to reduce its privileges.
 * @param vkey
 *        The protection key
 * @param flags
 *        A bitwise combination by any of those
 *        @c PK_OWNER_KEY
 *            The new domain gets ownership, allowing it to use @p vkey
 *            for memory mapping (@p dm_mmap, @p dm_munmap, @p dm_mprotect, 
 *            @p dm_pkey_mprotect) and free it via @p dm_pkey_free.
 *        @c PK_COPY_KEY
 *            The new domain gets a copy of @p vkey which it can use for
 *            accessing memory assigned to @p vkey, or making other
 *            copies with the @c PK_COPY_KEY flag. Depending on
 *            @c PK_OWNER_KEY, this copy has ownership access. Without
 *            this flag, the current domain loses access to @p vkey.
 * @param access_rights
 *        The access rights for @p vkey. They must be equal or more
 *        restrictive than the current domain's access rights for this
 *        @p vkey.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p did, @p flags or @p access_rights is invalid.
 *        @c EACCES
 *            if the current domain does not own @p vkey, or
 *            if @p access_rights is more permissive than current
 *            domain's access rights
 *        @c ENOMEM
 *            if there is no more space for assigning @p pkeys
 */
int dm_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);

/**
 * @brief Get a domain's default protection key
 * 
 * This function retrieves a domain's default protection key, which is
 * allocated at dm_domain_create.
 * 
 * @param did
 *        The domain, which must be the current or a child domain
 * @return
 *        vkey on success, or -1 on error, and errno is set to:
 *        @c EACCES
 *            if @p did is not current or child domain
 */
int dm_domain_default_key(int did);

/**
 * @brief Load or unload a protection key
 * 
 * This function loads a specific @p vkey for the current domain into the
 * protection register. Depending on the architecture, it might have only
 * a limited number of slots available. In this case, setting a @p vkey
 * to a specific slot invalidates the previous key in this slot. Also,
 * this function can be used to unload a @p vkey.
 * 
 * @param vkey
 *        the protection key, can also be @c GET_DEFAULT_VKEY
 * @param slot
 *        if supported by the architecture, loads @p vkey into the
 *        specified slot. If @c PK_SLOT_ANY, the implementation decides
 *        which slot to use. If @c PK_SLOT_NONE, the key is unloaded.
 * @param flags
 *        Optional flags for future use. Must be 0 in current implementations.
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p slot, @p perm or @p flags is invalid. An implementation can
 *            use this error code to determine the number of available
 *            slots.
 *        @c EACCES
 *            if current domain does not own @p vkey.
 */
int dm_domain_load_key(vkey_t vkey, int slot, unsigned int flags);

void dm_print_debug_info(void);

int dm_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                      void *(*start_routine) (void *), void *arg);
int dm_pthread_exit(void *retval);

int  test_simple_api(int a, int b, int c, int d, int e, int f);

void  dm_print_current_reg(void);

/**
 * @brief Update the ISA permissions of the domain
 * 
 * @param params 
 *        @c domainId       要更新 ISA 权限的域ID，可以由Root域、父域、当前域自身调用此函数
 *        @c instNames      要更新权限的指令名称数组, @c getInstructionIndexByName 会将指令名称映射到唯一的指令索引，
 * 系统软件硬件中，指令名称到指令索引的映射一致
 *        @c instValues     指令名称数组对应的权限值数组，TODO: 元素个数和 @c instNames 要一致
 *        @c instCount      要更新权限的指令数量，也即 @c instNames 和 @c instValues 数组的有效尺寸
 *        @c regReadNames   要更新读权限的寄存器名称数组, @c getRegisterIndexByName 会将寄存器名称映射到唯一的寄存器索引，
 * 系统软件硬件中，寄存器名称到寄存器索引的映射一致
 *        @c regReadValues  上述寄存器名称数组对应的读权限值数组
 *        @c regReadCount   要更新权限的读寄存器数量
 *        @c regWriteNames  要更新写权限的寄存器名称数组, @c getRegisterIndexByName 会将寄存器名称映射到唯一的寄存器索引，
 * 系统软件硬件中，寄存器名称到寄存器索引的映射一致
 *        @c regWriteValues 上述寄存器名称数组对应的写权限值数组
 *        @c regWriteCount  要更新权限的写寄存器数量
 * @return
 *        0 on success, or -1 on error, and errno is set to:
 *        @c EINVAL
 *            if @p slot, @p perm or @p flags is invalid. An implementation can
 *            use this error code to determine the number of available
 *            slots.
 *        @c EACCES
 *            if current domain does not own @p vkey.
 */
int dm_update_isaBuffer(const UpdateBitmapParams* params);
int getRegisterIndexByName(const char* name);
int getInstructionIndexByName(const char* name);

//  这里验证 mode 
// void dm_debug_usercheck(int expected_did);

/*
int pk_init(void);
int pk_deinit(void);
int pk_domain_create(unsigned int flags);
vkey_t pk_pkey_alloc(unsigned int flags, unsigned int access_rights);
int pk_pkey_free(vkey_t vkey);
int pk_domain_assign_pkey(int did, vkey_t vkey, int flags, int access_rights);

int pk_domain_default_key(int did);
int pk_domain_release_child(int did);
int pk_domain_free(int did);
int pk_pkey_mprotect(void *addr, size_t len, int prot, vkey_t vkey);
int pk_pkey_mprotect2(int did, void *addr, size_t len, int prot, vkey_t vkey);
int pk_module_protect(int did, vkey_t vkey, const void* self, const char* module);
void* pk_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* pk_mmap2(int did, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* pk_mmap3(vkey_t vkey, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int pk_munmap(void* addr, size_t len);
int pk_munmap2(int did, void* addr, size_t len);
*/


#ifdef __cplusplus
}
// TODO 是否需要?
// #include "pku_wrapper.h"
#endif

#endif // __ASSEMBLY__
