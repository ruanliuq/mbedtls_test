#include "dm_internal.h"
#include "syscall.h"


extern unsigned char domain_manager_initialized; 

int __attribute__((naked)) domain_set_init(){
    asm volatile (
        // the `_init_root_domain` may overwritten ra ,so we should save ra
        "addi     sp,sp,-8;"
        "sd       ra,0(sp);" 
        "call     _init_root_domain;"   
        // set domain_manager_initialized to true
        "la       ra, %[initialized];"
        "li       a0, 1;"
        "sb       a0, 0(ra);"
        // restore ra and remove stack frame
        "ld       ra,0(sp);" 
        "addi     sp,sp,8;" 
        // set return value  to 0
        "li       a0,0;"
        // Set uepc to ra
        "csrrw zero, %[uepc], ra;"  
        "uret;"
        : 
        : [initialized] "X"(&domain_manager_initialized), [uepc] "i"(CSR_UEPC)
    );
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// Internal trusted functions       全都是 DM_CODE
//------------------------------------------------------------------------------
int D_CODE  _dm_init_arch() {
    DEBUG_MPK("_dm_init_arch start");

    // check pkru register
    pkru_config_t reg = _read_pkru_reg();

    //reset pkru
    // 重置为当前线程(pk_trusted_tls)的默认 pkru 值（也就是 root 域）
    reg = dm_data.domains[CURRENT_DID].default_config;
    assert(reg.sw_did == DID_FOR_ROOT_DOMAIN);
    _write_pkru_reg(reg);
    DEBUG_MPK("_dm_init_arch end");
    return 0;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Internal  functions       ALL DM_CODE
//------------------------------------------------------------------------------
void D_CODE  _dm_setup_exception_stack_arch(void* exception_stack) {
    DEBUG_MPK("_dm_setup_exception_stack_arch start");
    dm_trusted_tls.exception_stack_base = exception_stack;
    dm_trusted_tls.exception_stack = (uint64_t*)exception_stack + EXCEPTION_STACK_WORDS - 2;
    //-2 because the stack must be aligned by 128-bit according to the RISC-V psABI spec
    assert_warn(CSRR(CSR_USCRATCH) == 0);
    CSRW(CSR_USCRATCH, dm_trusted_tls.exception_stack);
    DEBUG_MPK("_dm_setup_exception_stack_arch end");
}
//------------------------------------------------------------------------------
void D_CODE  _dm_setup_exception_handler_arch() {
    DEBUG_MPK("_dm_setup_exception_handler_arch start");
    uint64_t utvec = (uint64_t)&dm_utvec_table | 1;
    // assert(CSRR(CSR_UTVEC) == 0);
    CSRW(CSR_UTVEC, utvec);
    DEBUG_MPK("_dm_setup_exception_handler_arch end");
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
void D_CODE _dm_setup_domain_arch(int did, pkey_t pkey) {
    
    assert(did >= 0 && did < NUM_DOMAINS && dm_data.domains[did].used);
    assert(pkey > 0 && pkey < MAX_NUM_KEYS);

    dm_data.domains[did].default_config.mode = 1;
    dm_data.domains[did].default_config.sw_did = did;
    if (did != DID_FOR_EXCEPTION_HANDLER){
        dm_data.domains[did].default_config.slot_0_mpkey = pkey;
    }
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// 
int D_CODE _dm_domain_load_key_arch(int did, pkey_t pkey, int slot, int perm){

    DEBUG_MPK("_dm_domain_load_key_arch(%u, %d, %d)", pkey, slot, perm);

    assert(pkey > 0 && pkey < MAX_NUM_KEYS);
    if (slot != PK_SLOT_ANY && slot != PK_SLOT_NONE) {
        return cleanup_and_exit(EINVAL, "domain load key:Invalid slots", 0);
    }
    if ( perm & ~(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE) ) {
        return cleanup_and_exit(EINVAL, "domain load key:Invalid permissions", 0);
    }

    // Used to distinguish between mount and unmount?
    if (slot == PK_SLOT_NONE) {
        // Both permissions are disabled, means key is unloaded
        perm = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
    }

    pkru_config_t pkru_old = (did == CURRENT_DID) ? _read_pkru_reg() : dm_data.domains[did].default_config;

    // try to reuse existing pkey
    if (pkru_old.slot_0_mpkey == pkey) {
        slot = 0;
        DEBUG_MPK("Reusing slot %d", slot);
    } else if (pkru_old.slot_1_mpkey == pkey) {
        slot = 1;
        DEBUG_MPK("Reusing slot %d", slot);
    } else if (pkru_old.slot_2_mpkey == pkey) {
        slot = 2;
        DEBUG_MPK("Reusing slot %d", slot);
    } else if (pkru_old.slot_3_mpkey == pkey) {
        slot = 3;
        DEBUG_MPK("Reusing slot %d", slot);
    } else if (slot == PK_SLOT_ANY) {
        //get actual slot number
        int * previous_slot = &(dm_data.domains[CURRENT_DID].previous_slot);
        slot = (*previous_slot % 3) + 1; //0th slot is always the default key
        DEBUG_MPK("_dm_domain_load_key_arch: previous_slot = %d new = %d", *previous_slot, slot);
        *previous_slot = slot;
        DEBUG_MPK("Updating slot %d", slot);
    }

    // unload
    if (slot == PK_SLOT_NONE){
        DEBUG_MPK("Key not loaded. Nothing to do");
        return 0;
    }
    // prepare new pkru value
    int wd = (perm & PKEY_DISABLE_WRITE) ? 1 : 0;
    // 二进制的 mask 0b代表二进制 11个1
    uint64_t key_mask = (uint64_t)0b11111111111ULL << (slot * 11);
    uint64_t key_val  = (uint64_t)((uint64_t)pkey | ((uint64_t)wd << 10)) << (slot * 11);

    //0th slot is always the default key. 
    assert((slot > 0 && slot < 4) || (slot == 0 && pkru_old.slot_0_wd == wd));
    // slot 0 is (only) allowed if nothing would change
    //Because for some reason assign_key is called (by our tests) with the key that's already in slot 0

    // erase key slot
    uint64_t      tmp = PKRU_TO_INT(pkru_old) & ~key_mask;

    if (!(perm & PKEY_DISABLE_ACCESS)) {
      // set new protection key
      tmp |= key_val;
    }
    pkru_config_t pkru_new = INT_TO_PKRU(tmp);

    assert(pkru_new.sw_did    == pkru_old.sw_did);
    assert(pkru_new.sw_unused == pkru_old.sw_unused);

    //update register
    if (did == CURRENT_DID) {
      _write_pkru_reg(pkru_new);
    } else {
      dm_data.domains[did].default_config = pkru_new;
    }
    return 0;
}

//------------------------------------------------------------------------------
int  _domain_halt() {
  ERROR("_domain_halt: No exception handler installed. Do not know how to proceed!");
  _dm_print_debug_info();
  DEBUG_MPK("The process will be die!");
  // print_mem_maps();
  assert(false);
}
//------------------------------------------------------------------------------

uint64_t D_CODE _dm_exception_handler_dispatch(uint64_t data, uint64_t id, uint64_t type){

    DEBUG_MPK("_dm_exception_handler_dispatch(data=%zu, id=%zu, type=%zu)" ,data, id, type);

    _dm_acquire_lock();

    if (type < 0 || type > 3) {
        return cleanup_and_exit(0, "_dm_exception_handler_dispatch:Illegal Exception types", 1);
    }
    int ret = type;
    uint64_t * StackOfCaller = (uint64_t*)CSRR(CSR_USCRATCH);
    void * ReturnAddr = (void*)CSRR(CSR_UEPC);

    // Handle specific type of exception.
    if((type == TYPE_EXCEPTION)){
        void * AccessAddr = (void*)CSRR(CSR_UTVAL);
        // Try to resolve key mismatch
        if (_dm_exception_key_mismatch_underlocked(AccessAddr) == 0) {
            // key exception resolved
            ret = 0;
        }else if (dm_data.user_exception_handler) {
            // If exception is registered,than invoker user exception handler
            // Call target code (without changing the current domain)
            // By returning a non-zero value, the assembler wrappe
            DEBUG_MPK("Invoking user exception handler");
            void * TargetHandlerCode = dm_data.user_exception_handler;
            pkru_config_t config = _read_pkru_reg();
            _dm_domain_switch_arch(TYPE_EXCEPTION, CURRENT_DID, config, TargetHandlerCode, StackOfCaller);
            ret = 1;
        }else{
            // Halt if unable to handle the exception
            _domain_halt();
        }
    }else{
        // handler ecall\return\api
        _dm_exception_handler_underlocked(data, id, type, StackOfCaller, ReturnAddr);
    }

    _dm_release_lock();
    return ret;
}
//------------------------------------------------------------------------------
void D_CODE _dm_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    
    DEBUG_MPK("_dm_domain_switch_arch( %d,%d, %p, %p)", type,target_did, entry_point, target_stack);

    //actual switch: write pkru,uepc,uscratch
    _write_pkru_reg(config);
    CSRW(CSR_UEPC,     entry_point);
    CSRW(CSR_USCRATCH, target_stack);

    // check if the domain-transition was successful
    assert(CURRENT_DID == target_did);
    //When returning to the root-domain, there should not be any old keys loaded
    //Default key for target domain should be loaded
    assert(_read_pkru_reg().slot_0_mpkey == dm_data.domains[target_did].default_config.slot_0_mpkey);
}

//------------------------------------------------------------------------------
void* D_CODE __attribute__((naked)) _pthread_init_function_asm(void *arg) {
  // We're entering here with the new user stack but in trusted mode
  // switch to trusted exception stack and call into C wrapper
  // Note: Using s0 as arg for start_routine because it's preserved across calls
  asm volatile(
    "mv  s3, a1\n"                    // save a1

    "ld  a0, %0\n"                    // save start_routine as first argument in a0
    "mv  a1, sp\n"                    // save current_user_stack as second argument a1
    "ld  sp, %1\n"                    // load exception stack
    "ld  s0, %2\n"                    // load *arg for start_routine into callee-saved register (s0)
    //"mv  s1, ra\n"                    // save ra to s1 (which is callee-saved)
    "call _pthread_init_function_c\n" // _pthread_init_function_c(start_routine, current_user_stack)
    "mv  a0, s0\n"                    // load *arg as first argument for start_routine
    //"mv  ra, s1\n"                    // restore ra which was previously saved to s1. it should probably point to pthread_exit or similar
    "la ra, pthread_exit\n"           // For some reason the old ra doesnt work here, so we just set it to pthread_exit instead
    "mv  a1, s3\n"                    // restore a1
    "j _dm_exception_handler_end\n"
    : // no output operands
    : "m"(dm_data.pthread_arg.start_routine),
      "m"(dm_data.pthread_arg.exception_stack_top),
      "m"(dm_data.pthread_arg.arg)
  );
}
//------------------------------------------------------------------------------
bool D_CODE  _dm_is_key_loaded_arch(pkey_t pkey) {

    assert(pkey > 0 && pkey < MAX_NUM_KEYS);

    for (size_t tid = 0; tid <  NUM_THREADS; tid++) {
        if (NULL == dm_data.threads[tid]) {
            continue;
        }
        assert(dm_data.threads[tid]->init);
        pkru_config_t pkru = dm_data.threads[tid]->current_pkru;
        if (pkru.slot_0_mpkey == pkey ||
            pkru.slot_1_mpkey == pkey ||
            pkru.slot_2_mpkey == pkey ||
            pkru.slot_3_mpkey == pkey) {

            WARNING("_dm_domain_is_key_loaded_arch: thread[%zu] has key %d loaded", tid, pkey);
            errno = EPERM;
            return -1;
        }
    }
    return 0;
}
//------------------------------------------------------------------------------

