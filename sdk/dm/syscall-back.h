#pragma once

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

int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_free(int pkey);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);



#define SYS_pkey_mprotect 288



#define SYS_pkey_alloc 289



#define SYS_pkey_free 290

int isa_open();
int isa_close();
#endif // __ASSEMBLY__
