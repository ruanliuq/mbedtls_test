#define __ASSEMBLY__
#include "dm_internal.h"

.section .text
.global dm_exception_handler              # Externally visible
.type   dm_exception_handler, @function

// Auto-generate wrappers for dm API calls
// NOTE: CODE BELOW is not protected! (outside of the dm section)
// Functions that override (e.g., preload) libc/pthread are generated via
// GEN_CALL_WRAPPER_API_FALLBACK. This creates a fallback to the native library
// function in case dm is not initialized yet

GEN_CALL_WRAPPER_API          domain_manager_deinit                      _API_dm_deinit
GEN_CALL_WRAPPER_API          dm_current_did                 _API_dm_current_did
GEN_CALL_WRAPPER_API          dm_register_exception_handler  _API_dm_register_exception_handler
GEN_CALL_WRAPPER_API          dm_domain_create               _API_dm_domain_create
GEN_CALL_WRAPPER_API          dm_domain_free                 _API_dm_domain_free
GEN_CALL_WRAPPER_API          dm_domain_release_child        _API_dm_domain_release_child
GEN_CALL_WRAPPER_API          dm_pkey_alloc                  _API_dm_pkey_alloc
GEN_CALL_WRAPPER_API          dm_pkey_free                   _API_dm_pkey_free
GEN_CALL_WRAPPER_API_FALLBACK pkey_mprotect                  _API_dm_pkey_mprotect
GEN_CALL_WRAPPER_API_FALLBACK mmap                           _API_dm_mmap
GEN_CALL_WRAPPER_API          dm_mmap2                       _API_dm_mmap2
GEN_CALL_WRAPPER_API          dm_mmap3                       _API_dm_mmap3
GEN_CALL_WRAPPER_API          munmap                         _API_dm_munmap
GEN_CALL_WRAPPER_API          mprotect                       _API_dm_mprotect
GEN_CALL_WRAPPER_API          dm_domain_register_ecall       _API_dm_domain_register_ecall
GEN_CALL_WRAPPER_API          dm_domain_allow_caller         _API_dm_domain_allow_caller
GEN_CALL_WRAPPER_API          dm_domain_allow_caller2        _API_dm_domain_allow_caller2
GEN_CALL_WRAPPER_API          dm_domain_assign_pkey          _API_dm_domain_assign_pkey
GEN_CALL_WRAPPER_API          dm_domain_default_key          _API_dm_domain_default_key
GEN_CALL_WRAPPER_API          dm_domain_load_key             _API_dm_domain_load_key
GEN_CALL_WRAPPER_API_FALLBACK pthread_create                 _API_dm_pthread_create
GEN_CALL_WRAPPER_API_FALLBACK pthread_exit                   _API_dm_pthread_exit
GEN_CALL_WRAPPER_API          dm_print_debug_info            _API_dm_print_debug_info
GEN_CALL_WRAPPER_API          test_simple_api             _API_test_simple_api
GEN_CALL_WRAPPER_API_FALLBACK malloc                         _API_dm_malloc



