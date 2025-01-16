
#include <signal.h>
#include <errno.h>

#include "domain_key.h"
#include "dm_internal.h"

//------------------------------------------------------------------------------
// Internal globals
//------------------------------------------------------------------------------

pthread_mutex_t init_mutex;

unsigned char domain_manager_initialized = 0;

extern int domain_set_init();

// 0.4中记得删除这部分=======
#ifdef DLU_HOOKING
// Intercept libc/pthread functions and forward them to pk
// For this to work, libpku.so needs to be preloaded
// 这里有两部分

#else // DLU_HOOKING

#endif // DLU_HOOKING

#ifdef CONSTRUCTOR
// Automatically initialize and deinitialize pk
//------------------------------------------------------------------------------
#endif /* CONSTRUCTOR *///

void D_API  dm_print_current_reg() {
    dm_print_reg_arch(_read_pkru_reg());
}

// void D_API pk_debug_usercheck(int expected_did) {
//     assert(pk_current_did() == expected_did);
//     pk_debug_usercheck_arch();
// }

// TODO  FORCE_INLINE
// static inline void  pk_debug_usercheck_arch() {
//   // If called from main, expected mode is 0
//   pkru_config_t reg = _read_pkru();
//   assert_warn(reg.mode == 0);
// }


// 信号处理还不可用
void* D_API _pk_sa_sigaction_c(int sig, siginfo_t *info, void *ucontext){}



#ifdef SHARED
#endif // SHARED


#ifdef TIMING   //yes---wangm
#endif

// 0.4中记得删除这部分=======


// TODO : section
// 把 domain_manager_local_init 删掉？
int D_API domain_manager_init(void) {
  int domain_manager_local_init = 0;
  assert(pthread_mutex_lock(&init_mutex) == 0);

  // 临界区
  if (domain_manager_initialized) {
    WARNING("domain manager already initialized");
    assert(pthread_mutex_unlock(&init_mutex) == 0);
    return 0;
  }

  int ret = domain_set_init();
  if (ret == -1) {
    // we set domain_set_init error return to domain_manager_init
    if (domain_manager_local_init) {
      if(domain_manager_deinit() != 0){
        ERROR("domain_manager_deinit failed");
      }
    }
    else{
      ERROR("domain_manager_init failed");
    }
  }
  // init success
  else {
    domain_manager_local_init = 1;
    domain_manager_initialized = 1;
  }
  assert(pthread_mutex_unlock(&init_mutex) == 0);
  return ret;
}
