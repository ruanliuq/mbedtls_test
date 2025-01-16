#include "dm_internal.h"
#include "syscall.h"



//------------------------------------------------------------------------------
// Public API functions
//------------------------------------------------------------------------------
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
    //wwwwwwwwwwwww
    // CSR_UMISA 存储了当前支持的指令集拓展
    /*  TODO  
    uint64_t misa = CSRR(CSR_UMISA);
    char misa_str[27] = {0, };
    char* str_p = misa_str;
    for (size_t i = 0; i < 26; i++) {
        if ( misa & (1 << i) ) {
            *str_p++ = 'a' + i;
        }
    }
    DEBUG_MPK("misa = %zx = %s", misa, misa_str);
    assert( misa & (1 << ('u' - 'a')) );
    assert( misa & (1 << ('s' - 'a')) );
    assert( misa & (1 << ('i' - 'a')) );
    assert( misa & (1 << ('m' - 'a')) );
    assert( misa & (1 << ('a' - 'a')) );
    assert( misa & (1 << ('c' - 'a')) );
    assert( misa & (1 << ('n' - 'a')) );
    */

    //check if utvec table is protected
    // dm_utvec_table 是 dm_code 的一部分？？？？

// #ifndef SHARED
//     DEBUG_MPK("dm_utvec_table  = %p", ((char*)&dm_utvec_table));
//     assert( ((uintptr_t*)&dm_utvec_table) >= __start_dm_all);
//     assert( ((uintptr_t*)&dm_utvec_table) < __stop_dm_all);
//     assert( ((uintptr_t*)&dm_utvec_table) >= __start_dm_code);
//     assert( ((uintptr_t*)&dm_utvec_table) < __stop_dm_code);
// #endif

    // check pkru register
    pkru_config_t reg = _read_pkru_reg();
    //_print_reg(reg);
    //assert_warn(reg.mode == 1);
    //if(reg.mode != 1){
    //    reg.mode = 1;
    //    _write_pkru(reg);
    //    reg = _read_pkru_reg();
    //}

// TODO
// #ifndef FAKE_MPK_REGISTER
//     assert(reg.mode == 1);
// #endif

    //reset pkru
    // 重置为当前线程(pk_trusted_tls)的默认 pkru 值（也就是 root 域）
    reg = dm_data.domains[CURRENT_DID].default_config;
    assert(reg.sw_did == DID_FOR_ROOT_DOMAIN);
//    assert(reg.mode == 1);
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
    // 这里 mode 设置为 1 ，因此会根据中断原因来定位要执行的中断处理程序。注意，这里把异常处理设置为中断异常处理
    uint64_t utvec = (uint64_t)&dm_utvec_table | 1;
    // assert(CSRR(CSR_UTVEC) == 0);
    CSRW(CSR_UTVEC, utvec);
    DEBUG_MPK("_dm_setup_exception_handler_arch end");
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// set _dm_domain.pkru_config_t default_config
void D_CODE _dm_setup_domain_arch(int did, pkey_t pkey) {
    
    assert(did >= 0 && did < NUM_DOMAINS && dm_data.domains[did].used);
    assert(pkey > 0 && pkey < MAX_NUM_KEYS);

    // set default reg value
    // Note: setting mode to 1, otherwise we'd lock ourselves out when we write the register. Mode will be set to zero with the uret instruction
    // TEST IN DONKY
     dm_data.domains[did].default_config.mode            = 1;
    
    dm_data.domains[did].default_config.sw_did       = did;
    dm_data.domains[did].default_config.isa_id = dm_data.domains[did].isa_did;
    DEBUG_PRINTF("setup domain %d of ISA %d", did, dm_data.domains[did].isa_did);

    if (did != DID_FOR_EXCEPTION_HANDLER){
        //the key only gets set for normal domains otherwise we'd still have the exception handler's key loaded when returning to "the root" where the exception handler was registered
        dm_data.domains[did].default_config.slot_0_mpkey = pkey;
    }
}


//------------------------------------------------------------------------------


//------------------------------------------------------------------------------

// _dm_domain_load_key_underlocked   call  it       “updata pkru”
// 负责在特定域内加载或更新保护密钥的配
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

    // 根据权限是否可写以及slot值，构造新的PKRU值

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

    //  TODO    没有字段mode
    // assert(pkru_new.mode      == pkru_old.mode);
    assert(pkru_new.sw_did    == pkru_old.sw_did);
    assert(pkru_new.isa_id == pkru_old.isa_id);

//#ifndef RELEASE
    DEBUG_MPK("Updating PKRU from");
    dm_print_reg_arch(pkru_old);
    DEBUG_MPK("to");
    dm_print_reg_arch(pkru_new);
//#endif

    // TODO 这么一大坨怎么搞
    // 检查密钥是否只被加载了一次，以及在不同槽位的密钥和权限是否正确更新
    if (perm & PKEY_DISABLE_ACCESS) {
      assert(pkru_new.slot_0_mpkey != pkey);
      assert(pkru_new.slot_1_mpkey != pkey);
      assert(pkru_new.slot_2_mpkey != pkey);
      assert(pkru_new.slot_3_mpkey != pkey);
    } else {
      //checking bit-mask magic
      // 每两行 分别验证 替代了 slot 0 或者 没有替代 slot 0
      assert((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_mpkey == pkru_old.slot_0_mpkey);
      assert((slot == 0 && pkru_new.slot_0_mpkey == pkey && pkru_new.slot_0_wd == wd) || pkru_new.slot_0_wd    == pkru_old.slot_0_wd);
      assert((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_mpkey == pkru_old.slot_1_mpkey);
      assert((slot == 1 && pkru_new.slot_1_mpkey == pkey && pkru_new.slot_1_wd == wd) || pkru_new.slot_1_wd    == pkru_old.slot_1_wd);
      assert((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_mpkey == pkru_old.slot_2_mpkey);
      assert((slot == 2 && pkru_new.slot_2_mpkey == pkey && pkru_new.slot_2_wd == wd) || pkru_new.slot_2_wd    == pkru_old.slot_2_wd);
      assert((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_mpkey == pkru_old.slot_3_mpkey);
      assert((slot == 3 && pkru_new.slot_3_mpkey == pkey && pkru_new.slot_3_wd == wd) || pkru_new.slot_3_wd    == pkru_old.slot_3_wd);
      // pkey is loaded exactly once
      assert((pkru_new.slot_0_mpkey == pkey) + (pkru_new.slot_1_mpkey == pkey) + (pkru_new.slot_2_mpkey == pkey) + (pkru_new.slot_3_mpkey == pkey) == 1);
    }

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

// data 没用到？
    DEBUG_MPK("_dm_exception_handler_dispatch(data=%zu, id=%zu, type=%zu)" ,data, id, type);

#ifdef TIMING
    bool timing = (TIMING_HANDLER_C != 0) && (type == TIMING_HANDLER_C_TYPE);
    if (timing) TIME_START(TIMING_HANDLER_C);
#endif

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
#if defined(TIMING) && TIMING_HANDLER_C != 0
    if(type == TIMING_HANDLER_C_TYPE)
        TIME_STOP(TIMING_HANDLER_C);
#endif
    return ret;
}

//------------------------------------------------------------------------------
// void  _dm_domain_switch_arch(int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
void D_CODE _dm_domain_switch_arch(int type, int target_did, pkru_config_t config, void* entry_point, uint64_t* target_stack) {
    
    DEBUG_MPK("_dm_domain_switch_arch( %d,%d, %p, %p)", type,target_did, entry_point, target_stack);

    // ISA 域切换
    int cur_isa_did = CURRENT_ISA;
    int dest_isa_did = dm_data.domains[target_did].isa_did;

    //actual switch: write pkru,uepc,uscratch
    _write_pkru_reg(config);
    CSRW(CSR_UEPC,     entry_point);
    CSRW(CSR_USCRATCH, target_stack);

    if(cur_isa_did != dest_isa_did)
        isa_call(dest_isa_did, cur_isa_did);

    // check if the domain-transition was successful
    // TODO assert_ifdebug
    assert(CURRENT_DID == target_did);
    assert(CURRENT_ISA == dest_isa_did);
    //When returning to the root-domain, there should not be any old keys loaded
    //assert_ifdebug(target_did != 0 || CSRR(CSR_MPK) == 0x8000000000000000LL);
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

