/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef vcore_h
#define vcore_h

#include <stdio.h>

#include <Hypervisor/Hypervisor.h>

#include "hvftool.h"
#include "vmm.h"



// see Arm documentation on SPSR_EL1 bits M in aarch64 mode:
// https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/SPSR-EL3--Saved-Program-Status-Register--EL3-?lang=en
// The trouble with EL1H is that it seems raising synchronous exception (curr_el_spx_sync)
// on using andy EL1 instructions/registers (mrs CurrentEL raises one)
// EL1T seem to be running just fine
#define PSR_EL1T    0b0100      // EL1 running on EL0 stack
#define PSR_EL1H    0b0101      // EL1 running on EL1 stack
#define PSR_EL2T    0b1000      // EL3 running on EL1 stack
#define PSR_EL2H    0b1001      // EL3 running on EL1 stack
#define PSR_EL3T    0b1100      // EL3 running on EL1 stack
#define PSR_EL3H    0b1101      // EL3 running on EL1 stack

#define PSR_DEBUG_EXCEPTION_MASK    (1 << 9)         // masks debug exceptions when set
#define PSR_SINGLE_STEP     (1 << 21)         // Singlestep debugging

#define LR_POISION          ((uint64_t)-4)
#define DBG_MDSCR_SS        (1 << 0)
#define DBG_MDSCR_KDE       (1 << 13)
#define DBG_MDSCR_MDE       (1 << 15)

extern gva_t EMULATION_TLBI_INDEX;


/* ---------------------------------------- */
/* VM EXIT stuff */

// Exceptions are EL2 exception (see ESR_EL2 for decoding)

#define WF_EXCEPTION                    (0b000001)
#define DATA_ABORT_EXCEPTION            (0b100100)
#define HVC_EXCEPTION                   (0b010110)
#define SMC_EXCEPTION                   (0b010111)
#define MRS_EXCPETION                   (0b011000)
#define BRK_EXCEPTION                   (0b111100)
#define INSTRUCTION_ABORT_EXCEPTION     (0b100000)
#define BREAKPOINT_EXCEPTION            (0b110000)
#define SOFTWARE_STEP_EXCEPTION         (0b110010)


struct vmm_context; // defined in vmm.h
struct vcore;
struct sys_reg_info;
/*
8012
 
 op0 op1 CRn CRm op2
0b10 0b000 0b0000 0b0010 0b010
 
 1000 0000 0001 0010
*/

/*

 The Linux kernel and other OSes are using the following values to program a hw breakpoint
 https://elixir.bootlin.com/linux/v5.19.5/source/tools/testing/selftests/kvm/aarch64/debug-exceptions.c#L80
 
 #define DBGBCR_LEN8    (0xff << 5)
 #define DBGBCR_EXEC    (0x0 << 3)
 #define DBGBCR_EL1    (0x1 << 1)
 #define DBGBCR_E    (0x1 << 0)
 
 The DBGBCR_EXEC touches bits that are marked Res0... as it is set to 0, no issues though.
 
 But the specification does not mention any LEN or EXEC...
 see
 D2.9.1
 and
 D.9.3
and in particular Table D2-8 Summary of breakpoint HMC, SSC, and PMC encodings

 The Linux encoding is equivalent to:
 HV_SYS_REG_DBGBCR0_EL1=1e3
     Enabled: 1
     PMC: 1
     Res0: 0
     BAS: 0xf, DBGBCR - Use for A64 and A32 instructions
     Res0: 0
     HMC: 0
     SSC: 0
     LBN: 0
     BT: 0x0, Unlinked instruction address match.
     LBN: 0
 
 According to table 2-8, {SSC=0, HMC=0, PMC=1} will trap only at EL1

 so the resulting bit field is OK but with improper building
 
 something like

 // See  table 2-8 to encode {SSC, HMC, PMC}
 #define BPCR_EXEC_EL1          (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(1)))
 #define BPCR_EXEC_EL0          (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(2)))
 #define BPCR_EXEC_EL1_0        (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(3)))
 
Is far better IMHO
 
 */

#define DBGCR_BT(n)     (((n) & 0xF) << 20)
#define BP_BT_EXEC      0
#define DBGCR_LBN(n)    (((n) & 0xF) << 16)
#define DBGCR_SSC(n)    (((n) & 0x3) << 14)
#define DBGCR_HSC(n)    (((n) & 0x1) << 13)
#define DBGCR_BAS(n)    (((n) & 0xF) << 5)
#define BP_BAS_A64      0xF
#define DBGCR_PMC(n)    (((n) & 0x3) << 1)
#define DBGCR_E(n)      (((n) & 0x1) << 0)
#define BP_ENABLE       1

// See  table 2-8 to encode {SSC, HMC, PMC}
#define BPCR_EXEC_EL1          (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(1)))
#define BPCR_EXEC_EL0          (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(2)))
#define BPCR_EXEC_EL1_0        (DBGCR_E(BP_ENABLE) | DBGCR_BT(BP_BT_EXEC) | DBGCR_BAS(BP_BAS_A64) | (DBGCR_SSC(0) | DBGCR_HSC(0) | DBGCR_PMC(3)))



// ADDED REGISTERS just for decoding, HVF DOES NOT GIVE ACCESS TO THEM, AT LEAST DIRECTLY
// do not have the HV_ prefix in the name as they are not defiined by HVF
#define SYS_REG_ESR_EL2                 0xc291  // what is the real value?
#define CNTPCT_EL0                      0xdf01  // for get ticks
#define SYS_REG_ID_AA64ISAR2_EL1        0xc032
#define SYS_REG_ID_AA64ZFR0_EL1         0xc024
#define SYS_REG_ID_AA64SMFR0_EL1        0xc025
#define SYS_REG_ICC_CTLR_EL1            0xc664
#define SYS_REG_ICC_PMR_EL1             0xc230
#define SYS_REG_ICC_BPR1_EL1            0xc663
#define SYS_REG_ICC_IGRPEN1_EL1         0xc667
#define SYS_REG_ICC_IAR1_EL1            0xc660
#define SYS_REG_ICC_EOIR1_EL1           0xc661

#define SYS_REG_PMCR_EL0                0xdce0

#define SYS_REG_OSDLR_EL1               0x809c // just define to ignore this register!
#define SYS_REG_OSLAR_EL1               0x8084 // just define to ignore this register!

#define SYS_REG_CPUACTLR_EL1            0xcf90  // used during TFA BL1 processor init/errata management
#define SYS_REG_ECTLR_EL1               0xcf91

#define SYS_REG_SCTLR_EL3               0xf080
#define SYS_REG_SCR_EL3                 0xf088
#define SYS_REG_CPTR_EL3                0xf08a
#define SYS_REG_TTBR0_EL3               0xf100
#define SYS_REG_TCR_EL3                 0xf102
#define SYS_REG_MAIR_EL3                0xf510
#define SYS_REG_VBAR_EL3                0xf600

/* ----------------------------- */



typedef int (*formatter_f)(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);

typedef vmm_action_t (*getter_f)(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, struct sys_reg_info* sys_reg);
typedef vmm_action_t (*setter_f)(struct vmm_context* context, struct vcore* vcore, struct sys_reg_info* sys_reg, hv_reg_t reg);

typedef struct sys_reg_info {
    hv_sys_reg_t    id;
    uint64_t        reset_value;
    uint64_t        value;
    uint64_t        minimal_el;
    char*           name;
    char*           description;
    formatter_f     formatter;
    getter_f        read;
    setter_f        write;
} sys_reg_info_t;


typedef void (*sysreg_callback)(hv_sys_reg_t sysreg, uint64_t value);

// in vcore_debugging.c
int vcore_disable_single_step(vcore_t* vcore);
int vcore_enable_single_step(vcore_t* vcore);
vmm_action_t vcore_interactive_debug(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, vmm_action_t action_for_quit);
void vcore_disassemble_at(vmm_context_t* context, vcore_t* vcore, const char* prefix, gva_t gva);
void vcore_disassemble_caller(vmm_context_t* context, vcore_t* vcore, const char* prefix);
void vcore_disassemble_one(struct vmm_context* context, struct vcore* vcore, const char* prefix);
int vcore_get_current_el(struct vcore* vcore);
int vcore_get_sys_reg_value(vcore_t* vcore,  hv_sys_reg_t key, uint64_t* value);
void for_each_sysreg(vcore_t* vcore, sysreg_callback callback);
// in vcore.c
int get_index(hv_sys_reg_t reg);
int vcore_get_sys_reg_count(void);
vmm_action_t vcore_invoke_getter(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, hv_sys_reg_t key);
vmm_action_t vcore_invoke_setter(struct vmm_context* context, struct vcore* vcore, hv_sys_reg_t key, hv_reg_t reg);
int vcore_run(struct vmm_context* context, struct vcore* vcore);
int vcore_init(struct vmm_context* context, struct vcore* vcore);

#endif /* vcore_h */
