#pragma once

// TODO  finish syscall
#include "dm_defines.h"
/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/

#include <sys/mman.h> // pkey_alloc, pkey_free, mprotect, pkey_mprotect

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <sys/syscall.h>

// Error codes
#define SBI_ERR_ISA_SUCCESS                    0
#define SBI_ERR_ISA_UNKNOWN_ERROR              200000
#define SBI_ERR_ISA_INVALID_ID                 200001
#define SBI_ERR_ISA_NOT_EVICT                  200002
#define SBI_ERR_ISA_NOT_PERMISSION              200003
#define SBI_ERR_ISA_NOT_RUNNABLE               200004
#define SBI_ERR_ISA_NOT_DESTROYABLE            200005
#define SBI_ERR_ISA_NOT_ACCESSIBLE             200007
#define SBI_ERR_ISA_ILLEGAL_ARGUMENT           200008
#define SBI_ERR_ISA_NOT_RUNNING                200009
#define SBI_ERR_ISA_NOT_RESUMABLE              200010
#define SBI_ERR_ISA_EDGE_CALL_HOST             200011
#define SBI_ERR_ISA_NOT_INITIALIZED            200012
#define SBI_ERR_ISA_NO_FREE_RESOURCE           200013
#define SBI_ERR_ISA_SBI_PROHIBITED             200014
#define SBI_ERR_ISA_NOT_FRESH                  200016

int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_free(int pkey);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);

// create
int isa_create_new_did();
// update
// flag 为 0 表示更新 default 规则， 否则更新指定域的 bitmap ，只能在域0中进行更新
int isa_update_bitBuffer(int flag, int isa_did, void * updates, size_t size);
// delete
int isa_delete(int isa_did);
// register

#ifndef SYS_pkey_mprotect
#if __x86_64__
#define SYS_pkey_mprotect 329
#else
#define SYS_pkey_mprotect 288
#endif
#endif

#ifndef SYS_pkey_alloc
// i386 和 x86_64 都是指CPU的架构。其中，i386 是32位的架构，而 x86_64 是64位的架构
#if __x86_64__
#define SYS_pkey_alloc 330
#else
#define SYS_pkey_alloc 289
#endif
#endif


#ifndef SYS_pkey_free
#if __x86_64__
#define SYS_pkey_free 331
#else
#define SYS_pkey_free 290
#endif
#endif

#define SYS_isa_create 291
#define SYS_isa_delete 292
#define SYS_isa_update_buffer 293
#define SYS_isa_register_gate 294
#define SYS_isa_update_buffer_default 295

// 仅用于性能测试，不用于正常模式
#define SYS_isa_open 296
#define SYS_isa_close 297


#endif // __ASSEMBLY__
