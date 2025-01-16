#pragma once


#include "dm_debug.h"
#include "dm_key_arch.h"

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void (*dm_utvec_table)(void);

// internal arch-specific functions

int   D_CODE _dm_init_arch();
void  D_CODE _dm_setup_exception_stack_arch(void* exception_handler_stack);
void  D_CODE _dm_setup_exception_handler_arch();
void  D_CODE _dm_setup_domain_arch(int did, pkey_t pkey);
int   D_CODE _dm_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm);

uint64_t D_CODE _dm_exception_handler_dispatch(uint64_t data, uint64_t id, uint64_t type);
void  D_CODE _dm_exception_handler(void);

// 是否可以简化？void      _dm_domain_switch_arch(int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack);
void  D_CODE _dm_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack);
void* D_CODE _pthread_init_function_asm(void *arg);
void  D_CODE _dm_exception_handler_end(void);

bool D_CODE _dm_is_key_loaded_arch(pkey_t pkey);

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/


#endif // defined __ASSEMBLY__
