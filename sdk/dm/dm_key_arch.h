#pragma once
#include "dm_defines.h"


// Do not change these values, as asm code would break!
#define TYPE_RET  0
#define TYPE_CALL 1
#define TYPE_API  2
#define TYPE_EXCEPTION 3


// Distinguishes ECALLs and returns
#define reg_a2_type a2
// Holds the CALL ID
#define reg_a1_id   a1
// Holds ms data 
#define reg_a0_data a0


//------------------------------------------------------------------------------
// CSR defines for interrupt handling
//------------------------------------------------------------------------------
#define CSR_UEPC 0x041              // 用户异常返回地址寄存器
#define CSR_USTATUS 0x000       // 用户状态寄存器
#define CSR_UIE 0x004                   // 用户中断使能，定义哪些中断可以在用户模式下处理
#define CSR_UTVEC 0x005           // 用户异常处理程序基地址,  异常处理程序的入口
#define CSR_USCRATCH 0x040  // 用户中断临时寄存器
#define CSR_UCAUSE 0x042      // 用户中断原因
#define CSR_UTVAL 0x043         // 中断陷阱值
#define CSR_UIP 0x044               // 中断挂起

//------------------------------------------------------------------------------
// defines for PKRU  register
//------------------------------------------------------------------------------
#define CSR_UPKRU 0x048   // 定义的PKRU寄存器
// 异常代码为14
#define CAUSE_MPKEY_MISMATCH_FAULT 0xe

/**********************************************************************/
// For C only
#ifndef __ASSEMBLY__
/**********************************************************************/
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t pkey_t;

typedef struct __attribute__((__packed__)) {
    uint slot_0_mpkey : 10;
    uint slot_0_wd    :  1;
    uint slot_1_mpkey : 10;
    uint slot_1_wd    :  1;
    uint slot_2_mpkey : 10;
    uint slot_2_wd    :  1;
    uint slot_3_mpkey : 10;
    uint slot_3_wd    :  1;
    uint sw_did       :  8;
    uint sw_unused    : 11;
    uint mode         :  1;
} pkru_config_t;

typedef union{
    pkru_config_t pkru;
    uint64_t pkru_as_int;
} union_pkru_config_t;

// TODO   static inline ==>  FORCE_INLINE
static inline uint64_t PKRU_TO_INT(pkru_config_t pkru) {
    union_pkru_config_t u_pkru;
    u_pkru.pkru = pkru;
    return u_pkru.pkru_as_int;
}

// TODO   static inline ==>  FORCE_INLINE
static inline pkru_config_t INT_TO_PKRU(uint64_t reg) {
    union_pkru_config_t u_pkru;
    u_pkru.pkru_as_int = reg;
    return u_pkru.pkru;
}

//------------------------------------------------------------------------------
//  read  or  write  pkru register
//------------------------------------------------------------------------------

// read/write pkru directly goes to the pkru register
#define CSRR(csr_id) ({uint64_t ret; asm volatile ("csrr %0, %1" : "=r"(ret) : "i"(csr_id)); ret;}) // GCC statement expression

// TODO   static inline ==>  FORCE_INLINE
static inline void CSRW(const uint64_t csr_id, const uint64_t csr_val){

    asm volatile ("csrw %0, %1" : : "i"(csr_id), "r"(csr_val));
}

#define CSRW(x,y) CSRW((x), (uint64_t)(y))


// TODO   static inline ==>  FORCE_INLINE
static inline pkru_config_t _read_pkru_reg() {
#ifdef FAKE_PKRU
    uint64_t value = fake_pkru;
#else
    uint64_t value = CSRR(CSR_UPKRU);
#endif
    return INT_TO_PKRU(value);
}

// TODO   static inline ==>  FORCE_INLINE
static inline void _write_pkru_reg(pkru_config_t new_config) {
    uint64_t reg = PKRU_TO_INT(new_config);
#ifdef FAKE_PKRU
    fake_pkru = reg;
#else
    CSRW(CSR_UPKRU, reg);
    // In theory we need an instruction-fence here, 
    // unless we can guarantee that we execute more instructions before uret
    // such that the pipeline never contains invalid instructions?
#endif
    #ifdef ADDITIONAL_DEBUG_CHECKS
        if(CSRR(CSR_UPKRU) != reg){
            ERROR_FAIL("Failed to set CSR_UPKRU to 0x%lx. Its value is  0x%lx", reg, CSRR(CSR_UPKRU));
        }
    #endif
}

// #define _read_pkru()     _read_pkru_reg()
// #define _write_pkru(new_config) _write_pkru_reg(new_config)

#define CURRENT_DID ({ assert(dm_trusted_tls.init); _read_pkru_reg().sw_did;})

//------------------------------------------------------------------------------
// TODO   static inline ==>  FORCE_INLINE
static inline void dm_print_reg_arch(pkru_config_t reg){
    fprintf(stderr,"raw = 0x%zx, ", PKRU_TO_INT(reg));
    fprintf(stderr,"did = %4u ", reg.sw_did);
    fprintf(stderr,"keys = [%4u](wd=%1u) [%4u](wd=%1u) [%4u](wd=%1u) [%4u](wd=%1u)", 
        reg.slot_3_mpkey, reg.slot_3_wd,
        reg.slot_2_mpkey, reg.slot_2_wd,
        reg.slot_1_mpkey, reg.slot_1_wd,
        reg.slot_0_mpkey, reg.slot_0_wd
    );
}

#define GET_TLS_POINTER ((uintptr_t)_get_tp())

// TODO   static inline ==>  FORCE_INLINE
static inline uint64_t _get_tp() {
    register uint64_t ret asm("tp");
    return ret;
}

#ifdef __cplusplus
}
#endif

/**********************************************************************/
// For ASM only
#elif defined __ASSEMBLY__
/**********************************************************************/

.macro loadword reg label
    la   \reg, \label
    ld   \reg, 0(\reg)
.endm

.macro DIE
    ld t0, 0(zero)
    //j .
.endm

.macro SLOW_PUSH reg
    addi    sp, sp, -8
    sd      \reg,  0(sp)
.endm

.macro SLOW_POP reg
    ld      \reg,  0(sp)
    addi    sp, sp, 8
.endm


.macro trigger_exception
    SLOW_PUSH ra
    la ra, 1f
    //Trigger exception by loading a word from the handler
    //Note: using unused caller-saved register.
    loadword t5 _dm_exception_handler
    //loadword t5 domain_manager_initialized
.align 2 // uepc needs to be 2-byte aligned
1:  SLOW_POP ra
.endm



.macro goto_exception_handler id type

    // exception data to regs
    li       reg_a1_id, \id
    li       reg_a2_type, \type

    //go to exception handler
    trigger_exception
.endm

.macro CLEAR_CALLER_SAVED_TEMP_REGS
mv      t0,  x0
mv      t1,  x0
mv      t2,  x0
mv      t3,  x0
mv      t4,  x0
mv      t5,  x0
mv      t6,  x0
.endm

.macro CLEAR_CALLEE_SAVED_REGS
mv      s0,  x0
mv      s1,  x0
mv      s2,  x0
mv      s3,  x0
mv      s4,  x0
mv      s5,  x0
mv      s6,  x0
mv      s7,  x0
mv      s8,  x0
mv      s9,  x0
mv      s10, x0
mv      s11, x0
.endm

.macro SAVE_CALLEE_REGS
addi    sp, sp, -12*8
sd      s0,  11*8(sp)
sd      s1,  10*8(sp)
sd      s2,   9*8(sp)
sd      s3,   8*8(sp)
sd      s4,   7*8(sp)
sd      s5,   6*8(sp)
sd      s6,   5*8(sp)
sd      s7,   4*8(sp)
sd      s8,   3*8(sp)
sd      s9,   2*8(sp)
sd      s10,  1*8(sp)
sd      s11,  0*8(sp)
.endm

.macro RESTORE_CALLEE_REGS
ld      s0,  11*8(sp)
ld      s1,  10*8(sp)
ld      s2,   9*8(sp)
ld      s3,   8*8(sp)
ld      s4,   7*8(sp)
ld      s5,   6*8(sp)
ld      s6,   5*8(sp)
ld      s7,   4*8(sp)
ld      s8,   3*8(sp)
ld      s9,   2*8(sp)
ld      s10,  1*8(sp)
ld      s11,  0*8(sp)
addi    sp, sp, 12*8
.endm


//NOTE: Using t* registers, because they're caller saved.
//      So we do not have to backup&restore them.
//      Also we avoid PLT issues this way.
// mv指令是将后面的源寄存器移动到第一个的目标寄存器
.macro ECALL_REGS_TO_TMP
    mv t0, reg_a0_data
    mv t1, reg_a1_id
    mv t2, reg_a2_type
.endm

.macro TMP_REGS_TO_ECALL
    mv reg_a0_data, t0
    mv reg_a1_id,   t1
    mv reg_a2_type, t2
.endm


// domain_key.h中声明的函数在此处实现
.macro GEN_CALL_WRAPPER_API name id
.global \name
\name:
    ECALL_REGS_TO_TMP
    goto_exception_handler \id TYPE_API
_reentry_\name:
    // NOTE: exception preserves RA reg, so we safely return
    ret
.endm

/**
 * Macro for generating call wrappers that fall back to the libc function
 * if not initialized yet (i.e. pk_initialized is false)
 * 
 * @param name points to the original libc function. The generated wrapper
 *             function gets a pk_ prefix.
 * @param id   Unique integer of the wrapped function
 * @param type TYPE_ECALL or TYPE_API
 */
.macro GEN_CALL_WRAPPER_API_FALLBACK name id
.global dm_\name
dm_\name:
    # If dm is not initialized yet, call the native function
    lb   t0, domain_manager_initialized
    beqz t0, \name
    GEN_CALL_WRAPPER_API dm2_\name \id
.endm

.macro GEN_CALL_WRAPPER name id
.global ecall_\name
ecall_\name:
    //NOTE we save s* regs because they're callee-saved, but we can't trust our callee to do that
    //NOTE reg_ecall_* (a0..a2) are not required to be preserved across calls
    SAVE_CALLEE_REGS



    //NOTE: if argument registers are also callee-saved (in other architectures)
    //      we could also save them here instead of doing that in the exception handler code
    //      just make sure that we don't do it twice!

    // Save ecall argument regs to temp registers because we use them in goto_exception_handler
    ECALL_REGS_TO_TMP

    goto_exception_handler \id TYPE_CALL
_reentry_\name: //label just for debugging
    TMP_REGS_TO_ECALL //TODO do we need to restore all or just a0,a1?

    RESTORE_CALLEE_REGS
    // NOTE: exception preserves RA reg, so we safely return
    ret
.endm


.macro GEN_CALLEE_WRAPPER name id
.global _ecall_receive_\name
_ecall_receive_\name:

    //Restore (previously saved) function arguments from tmp-regs
    TMP_REGS_TO_ECALL


    call \name

    //move return values (if any), to t0..t2.
    //(so that we can restore them later at _reentry_\name)
    //TODO technically we probably only need to do a0,a1
    ECALL_REGS_TO_TMP



    // Callee-saved regs are already restored by \name due to ABI

    goto_exception_handler \id TYPE_RET
    DIE
.endm

// 包装器
// .global ecall_register_\name: 这行代码将ecall_register_\name（替换后的名称）标记为全局符号，使得链接器可以在其他文件中引用它。
// ecall_register_\name:: 定义一个标签，这是注册函数的入口点。
// li a1, \id: 将ECALL的唯一标识符（id）加载到寄存器a1中。[a0=did]
// la a2, ecall_receive\name: 将_ecall_receive_\name（替换后的名称）的地址加载到寄存器a2中。这可能是处理ECALL的回调函数或接收器的地址。
// a1被设置为ecall_id，
// a2被设置为指向_ecall_receive_\name的指针，这应该是ECALL的处理函数。
// a0（未显示设置）假定为函数的第一个参数did，是调用者传递的。
// 存储ra, 因为接下来的call指令将会改写ra寄存器
// call pk_domain_register_ecall2: 调用pk_domain_register_ecall2函数，注册ECALL。假设这个函数使用a1作为ECALL的ID，a2作为处理该ECALL的函数地址。

.macro GEN_REGISTER name id
.global ecall_register_\name
ecall_register_\name:
    // note: a0 = did = function argument
    //       a1 will be the id of the ecall
    //
    //loadword a1, ECALL_TEST2_ID
    li       a1, \id
    la       a2, _ecall_receive_\name
    //
    addi     sp,sp,-8
    sd       ra,0(sp)
    call     dm_domain_register_ecall
    ld       ra,0(sp)
    addi     sp,sp,8
    ret
.endm

//generate all 3 wrappers for functions with simple arguments (args fit into regs)
.macro GEN_ALL_SIMPLE name id
    GEN_REGISTER       \name \id
    GEN_CALL_WRAPPER   \name \id
    GEN_CALLEE_WRAPPER \name \id
.endm


#endif // __ASSEMBLY__
