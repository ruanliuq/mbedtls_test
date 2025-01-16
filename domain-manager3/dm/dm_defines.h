#pragma once

//------------------------------------------------------------------------------
// compile-dependent 
//------------------------------------------------------------------------------
// TODO    把这些放到 makefile 文件里面
/*CCFLAGS+=-DRELEASE
CCFLAGS+=-DTIMING
CCFLAGS+=-DFAKE_TLS_SWAP
#define RELEASE
*/ 
// #define FAKE_PKEY_SYSCALLS


#undef  ADDITIONAL_DEBUG_CHECKS
#undef  EXPECTED_RETURN_PADDING
#undef  PROXYKERNEL
#undef  SHARED
#undef  __x86_64
//------------------------------------------------------------------------------

// Max. number of foreign domains that can invoke current domain
#define NUM_SOURCE_DOMAINS 16

// Max. number of keys a domain can hold
#define NUM_KEYS_PER_DOMAIN 2048

// Max. number of domains
#define NUM_DOMAINS 512  //9     
#define NUM_ISA     1024 //10      
#define NUM_THREADS 256

#define UPDATE_DOMAIN   1
#define UPDATE_DEFAULT  0

#define PKEY_DISABLE_ACCESS (0x1)
#define PKEY_DISABLE_WRITE (0x2)

#ifndef __ASSEMBLY__

#define FAKE_THREAD
// #define FAKE_PKRU

#ifdef FAKE_PKRU
extern D_DATA unsigned long long fake_pkru;
#endif

#ifdef FAKE_THREAD
#define EYRIE_USER_STACK_START 0x0000000040000000
#define EYRIE_USER_STACK_SIZE 0x20000
#define USER_THREAD_STACK (EYRIE_USER_STACK_START + EYRIE_USER_STACK_SIZE + PAGESIZE*10)
#define USER_THREAD_SIZE 0x64000    // 100*4096
#define EYRIE_USER_STACK_END (EYRIE_USER_STACK_START - EYRIE_USER_STACK_SIZE)
#endif
// Internal PK code
#define D_CODE __attribute__((section(".dm"),used))
// Internal PK data
#define D_DATA __attribute__((section(".dm_data"),used))
// PK code/data that is exported via shared library
#define D_API  __attribute__ ((visibility ("default")))

// // Some functions are used in both, trusted and untrusted code.
// // FORCE_INLINE will inline them in the corresponding sections.
// //
// // If the compiler for some reason decides not to inline, the function
// // will be placed in a dead section, and the linker will fail
// #define FORCE_INLINE __attribute__((always_inline)) __attribute__((section(".deadcode"))) static inline

#endif /* __ASSEMBLY__ */

