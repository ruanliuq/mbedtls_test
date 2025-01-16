
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
//  TODO   understand
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <unistd.h>
#include <sys/syscall.h>

#include "dm_internal.h"
#include "syscall.h"
#include "domain_key.h"



//------------------------------------------------------------------------------
// Internal trusted functions       // ALL  DM_API
//------------------------------------------------------------------------------

// TODO 系统调用

#ifdef FAKE_PKEY_SYSCALLS

// The first protection key is reserved
unsigned char pkey_alloced[MAX_NUM_KEYS] = {1,0,};
int D_API pkey_alloc(unsigned int flags, unsigned int access_rights) {
    WARNING("Syscall: Fake pkey_alloc(%u, %u)", flags, access_rights);
    if (flags || access_rights & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE)) {
      errno = EINVAL;
      return -1;
    }
    for (size_t i = 0; i < MAX_NUM_KEYS; i++) {
    if (!pkey_alloced[i]) {
      pkey_alloced[i] = 1;
      return i;
    }
  }
  WARNING("Syscall: Fake pkey_alloc ran out of keys");
  errno = ENOSPC;
  return -1;
}
int D_API pkey_free(int pkey) {
    WARNING("Syscall: Fake pkey_free(%d)", pkey);
    if (pkey <= 0 || pkey >= MAX_NUM_KEYS) {
        // key 0 cannot be free'd
        WARNING("pkey_free: invalid key");
        errno = EINVAL;
        return -1;
    }
    pkey_alloced[pkey] = 0;
    return 0;
}
int D_API pkey_mprotect(void *addr, size_t len, int prot, int pkey) {
    WARNING("Syscall:  Fake pkey_mprotect(%p, %zu, %d, %d)", addr, len, prot, pkey);
    if (pkey >= 0 && pkey < MAX_NUM_KEYS && pkey_alloced[pkey]) {
      return syscall(SYS_mprotect, addr, len, prot);
    } else {
      WARNING("pkey_mprotect: invalid key");
      errno = EINVAL;
      return -1;
    }
}

#else // FAKE_PKEY_SYSCALLS   TODO  finish syscall

int D_API pkey_mprotect(void *ptr, size_t len, int prot, int pkey)
{
    DEBUG_MPK("Syscall: pkey_mprotect(%p, %zu, %d, %d)", ptr, len, prot, pkey);
    int ret = syscall(SYS_pkey_mprotect, ptr, len, prot, pkey);
    if (-1 == ret) {
      errno = EPERM; // just guessing
    }
    DEBUG_MPK("Syscall: pkey_mprotect(%p, %zu, %d, %d). ret = %d", ptr, len, prot, pkey, ret);
    return ret;
}

int D_API pkey_alloc(unsigned int flags, unsigned int access_rights)
{
    DEBUG_MPK("Syscall: pkey_alloc(%u, %u)", flags, access_rights);
    int ret = syscall(SYS_pkey_alloc, flags, access_rights);
    if (-1 == ret) {
      errno = ENOSPC; // just guessing
    }
    DEBUG_MPK("Syscall: pkey_alloc(%u, %u). ret = %d", flags, access_rights, ret);
    return ret;
}

int D_API pkey_free(int pkey)
{
    DEBUG_MPK("Syscall: pkey_free(%d)", pkey);
    int ret = syscall(SYS_pkey_free, pkey);
    if (-1 == ret) {
      errno = EINVAL;
    }
    return ret;
}

int D_API isa_create_new_did(){
    DEBUG_PRINTF("Syscall: create ISA");
    int ret = syscall(SYS_isa_create);
    if (ret == SBI_ERR_ISA_NOT_PERMISSION) {
        WARNING("Syscall: can not create new ISA, no permission!");
        DEBUG_PRINTF("Syscall: create ISA(%d)", ret);
    }
    if(ret == SBI_ERR_ISA_INVALID_ID){
        WARNING("Syscall: unknown error: ISA id conflict!");
        assert(false);
    }
    return ret;
}

int isa_delete(int isa_did){
    DEBUG_PRINTF("Syscall: delete ISA %d", isa_did);
    int ret = syscall(SYS_isa_delete, isa_did);
    if (ret == SBI_ERR_ISA_NOT_PERMISSION) {
        WARNING("Syscall: can not delete a ISA, no permission!");
    }
    if(ret == SBI_ERR_ISA_INVALID_ID){
        WARNING("Syscall: ISA id is invailed!");
    }
    return ret;
}

int isa_update_bitBuffer(int flag, int isa_did, void* updates, size_t size){
    DEBUG_PRINTF("Syscall: update BitBuffer of ISA %d ", isa_did);
    int ret = 0;
    if(flag == UPDATE_DEFAULT)
        ret = syscall(SYS_isa_update_buffer_default, isa_did, updates, size);
    else
        ret = syscall(SYS_isa_update_buffer, isa_did, updates, size);
    if (ret == SBI_ERR_ISA_NOT_PERMISSION) {
        WARNING("Syscall: can not delete a ISA, no permission!");
    }
    else if(ret == SBI_ERR_ISA_INVALID_ID){
        WARNING("Syscall: ISA id is invailed!");
    }
    else if(ret != 0)
        ERROR_FAIL("Syscall update bitBuffer: copy memory failed!");
    return ret;
}

#define SBI_ERR_ISA_CTRL_SUCCESS 1

int isa_open(){
    DEBUG_PRINTF("Syscall: Open ISA Check");
    int ret = syscall(SYS_isa_open);
    DEBUG_PRINTF("Syscall: create ISA(%d)", ret);
    if (ret != SBI_ERR_ISA_CTRL_SUCCESS) {
        WARNING("Syscall: can not open ISA check, unknow error!");
        DEBUG_PRINTF("Syscall: create ISA(%d)", ret);
    }
    return ret;
}

int isa_close(){
    DEBUG_PRINTF("Syscall: Close ISA Check");
    unsigned int ret = syscall(SYS_isa_close);
    DEBUG_PRINTF("Syscall: create ISA(%d)", ret);
    if (ret != SBI_ERR_ISA_CTRL_SUCCESS) {
        WARNING("Syscall: can not close ISA check, unknow error!");
        DEBUG_PRINTF("Syscall: create ISA(%d)", ret);
    }
    return ret;
}

#endif // FAKE_PKEY_SYSCALLS
