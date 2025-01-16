
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

void D_API  dm_print_current_reg() {
    dm_print_reg_arch(_read_pkru_reg());
}

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
