#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "syscall.h"
#include "domain_key.h"
#include "dm_debug.h"

#ifndef SHARED
extern unsigned char domain_manager_initialized;
#endif


void test1_api() {
  int did1, did2, did3;
  int pkey1, pkey2, pkey3, pkey4;
  int ret;

  printf("domain manager initialized = %d\n",domain_manager_initialized);
  assert(domain_manager_initialized);
  // test1_pkey_alloc();

  //--------------------------------------------------------------------
  // test dm_domain_create
  //--------------------------------------------------------------------
  
  // invalid flags
  printf("dm_domain_create(-1) fail\n");
  ret = dm_domain_create(-1);
  assert(ret == -1 && errno == EINVAL);
  printf("dm_domain_create(PK_OWNER_KEY) fail\n");
  ret = dm_domain_create(PK_OWNER_KEY);
  assert(ret == -1 && errno == EINVAL);
  printf("dm_domain_create(PK_COPY_KEY) fail\n");
  ret = dm_domain_create(PK_COPY_KEY);
  assert(ret == -1 && errno == EINVAL);

  printf("did1 = dm_domain_create(0) \n");
  did1 = dm_domain_create(0);
  assert(did1 > 0);

  printf("did2 = dm_domain_create(0) \n");
  did2 = dm_domain_create(0);
  assert(did2 > 0 && did1 != did2);

  printf("did3 = dm_domain_create(0) \n");
  did3 = dm_domain_create(0);
  assert(did3 > 0 && did2 != did3);

  //--------------------------------------------------------------------
  // test dm_pkey_alloc
  //--------------------------------------------------------------------

  // invalid flags
  printf("dm_pkey_alloc(-1, 0) \n");
  ret = dm_pkey_alloc(-1, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid access_rights
  printf("dm_pkey_alloc(0, 0x8) \n");
  ret = dm_pkey_alloc(0, 0x8);
  assert(ret == -1 && errno == EINVAL);

  // allocate four pkeys
  printf("pkey1 = dm_pkey_alloc(0, ACCESS | WRITE) \n");
  pkey1 = dm_pkey_alloc(0, PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE);
  assert(pkey1 > 0);
  // an allocated key belongs to the current domain and can be loaded
  // infinitely often

  printf("dm_domain_load_key(pkey1, ANY, 0) first\n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey1, ANY, 0) second\n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey1, ANY, 0) third\n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey1, ANY, 0) fourth\n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("pkey2 = dm_pkey_alloc(0, 0) \n");
  pkey2 = dm_pkey_alloc(0, 0);
  assert(pkey2 > 0 && pkey1 != pkey2);

  printf("dm_domain_load_key(pkey2, ANY, 0) \n");
  ret = dm_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("pkey3 = dm_pkey_alloc(0, 0) \n");
  pkey3 = dm_pkey_alloc(0, 0);
  assert(pkey3 > 0 && pkey2 != pkey3);

  printf("dm_domain_load_key(pkey3, ANY, 0) \n");
  ret = dm_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("pkey4 = dm_pkey_alloc(0, 0) \n");
  pkey4 = dm_pkey_alloc(0, 0);
  assert(pkey4 > 0 && pkey3 != pkey4);

  printf("dm_domain_load_key(pkey4, ANY, 0) \n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  //--------------------------------------------------------------------
  // test dm_domain_load_key
  //--------------------------------------------------------------------
  // test invalid pkey
  printf("dm_domain_load_key(0x7FFFFFFF, ANY, 0) fail\n");
  ret = dm_domain_load_key(0x7FFFFFFF, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);
  
  // test permission flags
  // key can be loaded multiple times
  printf("dm_domain_load_key(pkey4, ANY, 0) first\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey4, ANY, 0) second\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey4, ANY, 0) third\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey4, ANY, 0) fourth\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  printf("dm_domain_load_key(pkey4, ANY, 0) fifth\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // invalid flags
  printf("dm_domain_load_key(pkey4, ANY, 1) fail\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 1);
  assert(ret == -1 && errno == EINVAL);

  printf("dm_domain_load_key(pkey4, PK_SLOT_ANY, -1) fail\n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, -1);
  assert(ret == -1 && errno == EINVAL);

  //--------------------------------------------------------------------
  // test dm_domain_assign_pkey(int did, int pkey, int flags, int access_rights)
  //--------------------------------------------------------------------

  // invalid did
  printf("dm_domain_assign_pkey(100, pkey1, 0, 0) fail\n");
  ret = dm_domain_assign_pkey(100, pkey1, 0, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid pkey
  printf("dm_domain_assign_pkey(did1, -1, 0, 0) fail\n");
  ret = dm_domain_assign_pkey(did1, -1, 0, 0);
  assert(ret == -1 && errno == EACCES);

  // invalid flags
  printf("dm_domain_assign_pkey(did1, pkey1, -1, 0) fail\n");
  ret = dm_domain_assign_pkey(did1, pkey1, -1, 0);
  assert(ret == -1 && errno == EINVAL);

  // invalid access rights
  printf("dm_domain_assign_pkey(did1, pkey1, 0, -1) fail\n");
  ret = dm_domain_assign_pkey(did1, pkey1, 0, -1);
  assert(ret == -1 && errno == EINVAL);

  // assign key to self. Should succeed an arbitrary number of times
  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, OWNER/COPY, 0) success 1\n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, PK_OWNER_KEY | PK_COPY_KEY, 0);
  assert(ret == 0);

  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, OWNER/COPY, 0) success 2\n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, PK_OWNER_KEY | PK_COPY_KEY, 0);
  assert(ret == 0);

  // PK_COPY_KEY is redundant when assigning to key to self.
  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, OWNER, 0) success 1\n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, PK_OWNER_KEY, 0);
  assert(ret == 0);

  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, OWNER, 0) success 2\n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, PK_OWNER_KEY, 0);
  assert(ret == 0);

  // we still have pkey
  printf("dm_domain_load_key(pkey1, ANY, 0) success \n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // assign key to self without ownership transfer. Makes the key immutable
  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, 0, 0) success \n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, 0, 0);
  assert(ret == 0);

  // no ownership
  printf("dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, OWNER, 0) fail\n");
  ret = dm_domain_assign_pkey(DOMAIN_GET_CURRENT, pkey1, PK_OWNER_KEY, 0);
  assert(ret == -1 && errno == EACCES);

  // we still have pkey, although without owner permission
  printf("dm_domain_load_key(pkey1, ANY, 0) success \n");
  ret = dm_domain_load_key(pkey1, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // copy key to other domains but keep ownership
  printf("dm_domain_assign_pkey(did2, pkey2, COPY, 0) success \n");
  ret = dm_domain_assign_pkey(did2, pkey2, PK_COPY_KEY, 0);
  assert(ret == 0);

  printf("dm_domain_assign_pkey(did3, pkey3, COPY, 0) success \n");
  ret = dm_domain_assign_pkey(did3, pkey3, PK_COPY_KEY, 0);
  assert(ret == 0);

  // we still have pkey
  printf("dm_domain_load_key(pkey2, ANY, 0) success \n");
  ret = dm_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // we still have pkey
  printf("dm_domain_load_key(pkey3, ANY, 0) success \n");
  ret = dm_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == 0);

  // migrate key to others
  printf("dm_domain_assign_pkey(did2, pkey4, OWNER, 0) success \n");
  ret = dm_domain_assign_pkey(did2, pkey4, PK_OWNER_KEY, 0);
  assert(ret == 0);

  // no ownership
  printf("dm_domain_assign_pkey(did3, pkey4, OWNER, 0) fail \n");
  ret = dm_domain_assign_pkey(did3, pkey4, PK_OWNER_KEY, 0);
  assert(ret == -1 && errno == EACCES);

  // we lost access to pkey4
  printf("dm_domain_load_key(pkey4, ANY, 0) fail \n");
  ret = dm_domain_load_key(pkey4, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);

  //--------------------------------------------------------------------
  // test dm_pkey_free
  //--------------------------------------------------------------------

  // invalid pkey
  printf("dm_pkey_free(-1) fail\n");
  ret = dm_pkey_free(-1);
  assert(ret == -1 && errno == EACCES);

  // missing ownership
  printf("dm_pkey_free(pkey1) fail\n");
  ret = dm_pkey_free(pkey1);
  assert(ret == -1 && errno == EACCES);

  printf("dm_pkey_free(pkey4) fail\n");
  ret = dm_pkey_free(pkey4);
  assert(ret == -1 && errno == EACCES);

  #if __riscv && ! defined PROXYKERNEL
    //skip key-freeing, because kernel implementation can only free most recently allocated key for now.
    return;
  #endif

  // TODO 下面这些没被执行.........

  // key is still in use, but unloaded within free
  printf("dm_pkey_free(pkey2) success \n");
  ret = dm_pkey_free(pkey2);
  assert(ret == 0);

  // free keys
  //ret = dm_domain_load_key(pkey2, PK_SLOT_NONE, 0);
  //assert(ret == 0);
  //ret = dm_pkey_free(pkey2);
  //assert(ret == 0);
  printf("dm_domain_load_key(pkey3, NONE, 0) success \n");
  ret = dm_domain_load_key(pkey3, PK_SLOT_NONE, 0);
  assert(ret == 0);

  printf("dm_pkey_free(pkey3) success \n");
  ret = dm_pkey_free(pkey3);
  assert(ret == 0);

  // we lost access to pkeys
  printf("dm_domain_load_key(pkey2, ANY, 0) fail \n");
  ret = dm_domain_load_key(pkey2, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);

  printf("dm_domain_load_key(pkey3, ANY, 0) fail \n");
  ret = dm_domain_load_key(pkey3, PK_SLOT_ANY, 0);
  assert(ret == -1 && errno == EACCES);

  // double free
  printf("dm_pkey_free(pkey3) fail \n");
  ret = dm_pkey_free(pkey3);
  assert(ret == -1 && errno == EACCES);
  
  // parent can act in place of child
  printf("dm_domain_register_ecall(did1, ANY, test1_api) \n");
  ret = dm_domain_register_ecall(did1, PK_ECALL_ANY, test1_api);
  assert(ret >= 0);

  printf("dm_domain_register_ecall(did1, ANY, test1_api) second\n");
  ret = dm_domain_register_ecall(did1, PK_ECALL_ANY, test1_api);
  assert(ret >= 0);

  // until we release it
  printf("dm_domain_release_child(did1) success\n");
  ret = dm_domain_release_child(did1);
  assert(0 == ret);

  printf("dm_domain_release_child(did1) fail\n");
  ret = dm_domain_release_child(did1);
  assert(-1 == ret && errno == EINVAL);

  printf("dm_domain_register_ecall(did1, ANY, test1_api) fail\n");
  ret = dm_domain_register_ecall(did1, PK_ECALL_ANY, test1_api);
  assert(-1 == ret && errno == EACCES);
}

