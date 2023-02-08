/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <malloc/_malloc.h>
#include <errno.h>
#include <string.h>

#include <pthread.h>
#include <signal.h>

#include "hvftool.h"
#include "vcore.h"
#include "trace.h"
#include "vcore_info.h"
#include "vmm.h"
#include "loader.h"
#include "mmio.h"

#define IMPORT_REGISTER(name) \
vmm_action_t name ## _read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg); \
vmm_action_t name ## _write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg);

// defined in gic-v3.c
IMPORT_REGISTER(gic_icc_ctlr)
IMPORT_REGISTER(gic_icc_pmr)
IMPORT_REGISTER(gic_icc_bpr)
IMPORT_REGISTER(gic_icc_igrpen1)
IMPORT_REGISTER(gic_icc_iar1_el1)
IMPORT_REGISTER(gic_icc_eoir1_el1)

// defined in vcore_emulate.c
IMPORT_REGISTER(SP_EL1)
IMPORT_REGISTER(SCTLR_EL3)
IMPORT_REGISTER(VBAR_EL3)
IMPORT_REGISTER(MAIR_EL3)
IMPORT_REGISTER(TCR_EL3)
IMPORT_REGISTER(TTBR0_EL3)
IMPORT_REGISTER(SCR_EL3)
IMPORT_REGISTER(CPTR_EL3)

vmm_action_t IGNORE_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg) {
    return VMM_CONTINUE;
}

vmm_action_t IGNORE_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg) {
    return VMM_CONTINUE;
}

vmm_action_t CNTPCT_EL0_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg) {
    volatile uint64_t value;
    asm("mrs %0, CNTPCT_EL0; isb": "=r" (value));
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    return VMM_CONTINUE;
}

vmm_action_t VBAR_EL1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, vcore->vbar_el1);
    printf("x%d = VBAR_EL1 (%llx)\n", reg, vcore->vbar_el1);
    return VMM_CONTINUE;
}

vmm_action_t VBAR_EL1_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    uint64_t value;
    hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    printf("VBAR_EL1 = x%d (%llx)", reg, value);
    vcore->vbar_el1 = value;
    return VMM_CONTINUE;
}

vmm_action_t ID_AA64ISAR2_EL1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    // not defined for the moment
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, 0);
    return VMM_CONTINUE;
}

vmm_action_t ID_AA64SMFR0_EL1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    // not defined for the moment
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, 0);
    return VMM_CONTINUE;
}



sys_reg_info_t sys_regs_metadata[] = {
    { HV_SYS_REG_DBGBVR0_EL1, 0, 0, 1, "DBGBVR0_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR0_EL1, 0, 0, 1, "DBGBCR0_EL1", "", dbg_cr },
    { HV_SYS_REG_DBGWVR0_EL1, 0, 0, 1, "DBGWVR0_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR0_EL1, 0, 0, 1, "DBGWCR0_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR1_EL1, 0, 0, 1, "DBGBVR1_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR1_EL1, 0, 0, 1, "DBGBCR1_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR1_EL1, 0, 0, 1, "DBGWVR1_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR1_EL1, 0, 0, 1, "DBGWCR1_EL1", "", NULL },
    { HV_SYS_REG_MDCCINT_EL1, 0, 0, 1, "MDCCINT_EL1", "", NULL },
    { HV_SYS_REG_MDSCR_EL1, 0, 0, 1, "MDSCR_EL1", "Monitor Debug System Control Register",   NULL , IGNORE_read, IGNORE_write},
    { HV_SYS_REG_DBGBVR2_EL1, 0, 0, 1, "DBGBVR2_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR2_EL1, 0, 0, 1, "DBGBCR2_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR2_EL1, 0, 0, 1, "DBGWVR2_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR2_EL1, 0, 0, 1, "DBGWCR2_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR3_EL1, 0, 0, 1, "DBGBVR3_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR3_EL1, 0, 0, 1, "DBGBCR3_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR3_EL1, 0, 0, 1, "DBGWVR3_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR3_EL1, 0, 0, 1, "DBGWCR3_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR4_EL1, 0, 0, 1, "DBGBVR4_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR4_EL1, 0, 0, 1, "DBGBCR4_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR4_EL1, 0, 0, 1, "DBGWVR4_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR4_EL1, 0, 0, 1, "DBGWCR4_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR5_EL1, 0, 0, 1, "DBGBVR5_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR5_EL1, 0, 0, 1, "DBGBCR5_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR5_EL1, 0, 0, 1, "DBGWVR5_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR5_EL1, 0, 0, 1, "DBGWCR5_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR6_EL1, 0, 0, 1, "DBGBVR6_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR6_EL1, 0, 0, 1, "DBGBCR6_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR6_EL1, 0, 0, 1, "DBGWVR6_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR6_EL1, 0, 0, 1, "DBGWCR6_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR7_EL1, 0, 0, 1, "DBGBVR7_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR7_EL1, 0, 0, 1, "DBGBCR7_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR7_EL1, 0, 0, 1, "DBGWVR7_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR7_EL1, 0, 0, 1, "DBGWCR7_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR8_EL1, 0, 0, 1, "DBGBVR8_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR8_EL1, 0, 0, 1, "DBGBCR8_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR8_EL1, 0, 0, 1, "DBGWVR8_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR8_EL1, 0, 0, 1, "DBGWCR8_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR9_EL1, 0, 0, 1, "DBGBVR9_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR9_EL1, 0, 0, 1, "DBGBCR9_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR9_EL1, 0, 0, 1, "DBGWVR9_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR9_EL1, 0, 0, 1, "DBGWCR9_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR10_EL1, 0, 0, 1, "DBGBVR10_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR10_EL1, 0, 0, 1, "DBGBCR10_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR10_EL1, 0, 0, 1, "DBGWVR10_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR10_EL1, 0, 0, 1, "DBGWCR10_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR11_EL1, 0, 0, 1, "DBGBVR11_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR11_EL1, 0, 0, 1, "DBGBCR11_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR11_EL1, 0, 0, 1, "DBGWVR11_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR11_EL1, 0, 0, 1, "DBGWCR11_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR12_EL1, 0, 0, 1, "DBGBVR12_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR12_EL1, 0, 0, 1, "DBGBCR12_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR12_EL1, 0, 0, 1, "DBGWVR12_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR12_EL1, 0, 0, 1, "DBGWCR12_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR13_EL1, 0, 0, 1, "DBGBVR13_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR13_EL1, 0, 0, 1, "DBGBCR13_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR13_EL1, 0, 0, 1, "DBGWVR13_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR13_EL1, 0, 0, 1, "DBGWCR13_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR14_EL1, 0, 0, 1, "DBGBVR14_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR14_EL1, 0, 0, 1, "DBGBCR14_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR14_EL1, 0, 0, 1, "DBGWVR14_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR14_EL1, 0, 0, 1, "DBGWCR14_EL1", "", NULL },
    { HV_SYS_REG_DBGBVR15_EL1, 0, 0, 1, "DBGBVR15_EL1", "", NULL },
    { HV_SYS_REG_DBGBCR15_EL1, 0, 0, 1, "DBGBCR15_EL1", "", NULL },
    { HV_SYS_REG_DBGWVR15_EL1, 0, 0, 1, "DBGWVR15_EL1", "", NULL },
    { HV_SYS_REG_DBGWCR15_EL1, 0, 0, 1, "DBGWCR15_EL1", "", NULL },
    { HV_SYS_REG_MIDR_EL1, 0, 0, 1, "MIDR_EL1", "", NULL },
    { HV_SYS_REG_MPIDR_EL1, 0, 0, 1, "MPIDR_EL1", "", NULL },
    { HV_SYS_REG_ID_AA64PFR0_EL1, 0, 0, 1, "ID_AA64PFR0_EL1", "AArch64 Processor Feature Register 0", pfr0_el1 },
    { HV_SYS_REG_ID_AA64PFR1_EL1, 0, 0, 1, "ID_AA64PFR1_EL1", "AArch64 Processor Feature Register 1", pfr1_el1 },
    { HV_SYS_REG_ID_AA64DFR0_EL1, 0, 0, 1, "ID_AA64DFR0_EL1", " AArch64 Debug Feature Register 0", dfr0_el1 },
    { HV_SYS_REG_ID_AA64DFR1_EL1, 0, 0, 1, "ID_AA64DFR1_EL1", " AArch64 Debug Feature Register 1", dfr1_el1 },
    { HV_SYS_REG_ID_AA64ISAR0_EL1, 0, 0, 1, "ID_AA64ISAR0_EL1", "AArch64 Instruction Set Attribute Register 0", isar0_el1 },
    { HV_SYS_REG_ID_AA64ISAR1_EL1, 0, 0, 1, "ID_AA64ISAR1_EL1", "AArch64 Instruction Set Attribute Register 1", isar1_el1 },
    { HV_SYS_REG_ID_AA64MMFR0_EL1, 0, 0, 1, "ID_AA64MMFR0_EL1", "AArch64 Memory Model Feature Register 0", mfr0_el1 },
    { HV_SYS_REG_ID_AA64MMFR1_EL1, 0, 0, 1, "ID_AA64MMFR1_EL1", "AArch64 Memory Model Feature Register 1", mfr1_el1 },
    { HV_SYS_REG_ID_AA64MMFR2_EL1, 0, 0, 1, "ID_AA64MMFR2_EL1", "AArch64 Memory Model Feature Register 2", mfr2_el1 },
    { HV_SYS_REG_SCTLR_EL1, 0, 0, 1, "SCTLR_EL1", "", .formatter = sctlr_el1 },
    { HV_SYS_REG_CPACR_EL1, 0, 0, 1, "CPACR_EL1", "", NULL },
    { HV_SYS_REG_TTBR0_EL1, 0, 0, 1, "TTBR0_EL1", "Translation Table Base Register 0 (EL1)", NULL },
    { HV_SYS_REG_TTBR1_EL1, 0, 0, 1, "TTBR1_EL1", "", NULL },
    { HV_SYS_REG_TCR_EL1, 0, 0, 1, "TCR_EL1", "", tcr_el1 },
    { HV_SYS_REG_APIAKEYLO_EL1, 0, 0, 1, "APIAKEYLO_EL1", "", NULL },
    { HV_SYS_REG_APIAKEYHI_EL1, 0, 0, 1, "APIAKEYHI_EL1", "", NULL },
    { HV_SYS_REG_APIBKEYLO_EL1, 0, 0, 1, "APIBKEYLO_EL1", "", NULL },
    { HV_SYS_REG_APIBKEYHI_EL1, 0, 0, 1, "APIBKEYHI_EL1", "", NULL },
    { HV_SYS_REG_APDAKEYLO_EL1, 0, 0, 1, "APDAKEYLO_EL1", "", NULL },
    { HV_SYS_REG_APDAKEYHI_EL1, 0, 0, 1, "APDAKEYHI_EL1", "", NULL },
    { HV_SYS_REG_APDBKEYLO_EL1, 0, 0, 1, "APDBKEYLO_EL1", "", NULL },
    { HV_SYS_REG_APDBKEYHI_EL1, 0, 0, 1, "APDBKEYHI_EL1", "", NULL },
    { HV_SYS_REG_APGAKEYLO_EL1, 0, 0, 1, "APGAKEYLO_EL1", "", NULL },
    { HV_SYS_REG_APGAKEYHI_EL1, 0, 0, 1, "APGAKEYHI_EL1", "", NULL },
    { HV_SYS_REG_SPSR_EL1, 0, 0, 1, "SPSR_EL1", "", NULL },
    { HV_SYS_REG_ELR_EL1, 0, 0, 1, "ELR_EL1", "", NULL },
    { HV_SYS_REG_SP_EL0, 0, 0, 0, "SP_EL0", "", NULL },
    { HV_SYS_REG_AFSR0_EL1, 0, 0, 1, "AFSR0_EL1", "", NULL },
    { HV_SYS_REG_AFSR1_EL1, 0, 0, 1, "AFSR1_EL1", "", NULL },
    { HV_SYS_REG_ESR_EL1, 0, 0, 1, "ESR_EL1", "Exception Syndrome Register (EL1)", esr_el1 },
    { HV_SYS_REG_FAR_EL1, 0, 0, 1, "FAR_EL1", "", NULL },
    { HV_SYS_REG_PAR_EL1, 0, 0, 1, "PAR_EL1", "", NULL },
    { HV_SYS_REG_MAIR_EL1, 0, 0, 1, "MAIR_EL1", "", .formatter = MAIR_EL1 },
    { HV_SYS_REG_AMAIR_EL1, 0, 0, 1, "AMAIR_EL1", "", NULL },
    { HV_SYS_REG_VBAR_EL1, 0, 0, 1, "VBAR_EL1", "", NULL , VBAR_EL1_read, VBAR_EL1_write},
    { HV_SYS_REG_CONTEXTIDR_EL1, 0, 0, 1, "CONTEXTIDR_EL1", "", NULL },
    { HV_SYS_REG_TPIDR_EL1, 0, 0, 1, "TPIDR_EL1", "", NULL },
    { HV_SYS_REG_CNTKCTL_EL1, 0, 0, 1, "CNTKCTL_EL1", "", NULL },
    { HV_SYS_REG_CSSELR_EL1, 0, 0, 1, "CSSELR_EL1", "", NULL },
    { HV_SYS_REG_TPIDR_EL0, 0, 0, 0, "TPIDR_EL0", "", NULL },
    { HV_SYS_REG_TPIDRRO_EL0, 0, 0, 0, "TPIDRRO_EL0", "", NULL },
    { HV_SYS_REG_CNTV_CTL_EL0, 0, 0, 0, "CNTV_CTL_EL0", "", NULL },
    { HV_SYS_REG_CNTV_CVAL_EL0, 0, 0, 0, "CNTV_CVAL_EL0", "", NULL },
    { HV_SYS_REG_SP_EL1, 0, 0, 1, "SP_EL1", "", NULL, .read = SP_EL1_read, .write = SP_EL1_write},
    
    // ADDED REGISTERS HVF DOES NOT GIVE ACCESS TO THEM
    {0, 0, 0, 0, NULL, NULL}, // marker to say the following are not part of HVF
    
    { SYS_REG_ESR_EL2, 0, 0, 2, "ESR_EL2", "Exception Syndrome Register (EL2)", esr_el2 },
    { CNTPCT_EL0, 0, 0, 0, "CNTPCT_EL0", "Counter-timer Physical Count register", NULL , CNTPCT_EL0_read, NULL},
    { SYS_REG_ID_AA64ISAR2_EL1, 0, 0, 1, "ID_AA64ISAR2_EL1", "AArch64 Instruction Set Attribute Register 2", NULL , ID_AA64ISAR2_EL1_read, NULL},
    { SYS_REG_ID_AA64ZFR0_EL1, 0, 0, 1, "ID_AA64ZFR0_EL1", "AArch64 SVE Feature ID register 0", NULL },
    { SYS_REG_ID_AA64SMFR0_EL1, 0, 0, 1, "ID_AA64SMFR0_EL1", "AArch64 SME Feature ID register 0", NULL , ID_AA64SMFR0_EL1_read, NULL},
    
    // GIC REGISTERS
    { SYS_REG_ICC_CTLR_EL1, 0, 0, 1, "ICC_CTLR_EL1", "GIC CPUIF Control Register", NULL , gic_icc_ctlr_read, gic_icc_ctlr_write},
    { SYS_REG_ICC_PMR_EL1, 0, 0, 1, "ICC_PMR_EL1", "GIC CPUIF Priority Mask Register", NULL , gic_icc_pmr_read, gic_icc_pmr_write},
    { SYS_REG_ICC_BPR1_EL1, 0, 0, 1, "ICC_BPR1_EL1", "GIC CPUIF Binary Point Register", NULL , gic_icc_bpr_read, gic_icc_bpr_write},
    { SYS_REG_ICC_IGRPEN1_EL1, 0, 0, 1, "ICC_IGRPEN1_EL1", "GIC CPUIF  Interrupt Group 1 Enable Register", NULL , gic_icc_igrpen1_read, gic_icc_igrpen1_write},
    { SYS_REG_ICC_IAR1_EL1, 0, 0, 1, "ICC_IAR1_EL1 - Interrupt Controller Interrupt Acknowledge Register for Group 1 IRQs", .formatter = NULL,
        .read = gic_icc_iar1_el1_read, .write=gic_icc_iar1_el1_write},
    { SYS_REG_ICC_EOIR1_EL1, 0, 0, 1, "ICC_EOIR1_EL1 - Interrupt Controller End Of Interrupt Register for Group 1 IRQs", .formatter = NULL,
        .read = gic_icc_eoir1_el1_read, .write=gic_icc_eoir1_el1_write},

    { SYS_REG_OSDLR_EL1, 0, 0, 1, "OSDLR_EL1", "OS Double Lock Register", NULL , IGNORE_read, IGNORE_write},
    { SYS_REG_OSLAR_EL1, 0, 0, 1, "OSLAR_EL1", "OS Lock Access Register", NULL , IGNORE_read, IGNORE_write},
    
    { SYS_REG_PMCR_EL0, 0, 0, 0, "PMCR_EL0", "Performance Monitors Control Register", NULL , IGNORE_read, IGNORE_write},
    
    // More details at: https://elixir.bootlin.com/arm-trusted-firmware/latest/source/include/lib/cpus/aarch64/cortex_a72.h#L34
    { SYS_REG_CPUACTLR_EL1, 0, 0, 1, "CPUACTLR_EL1", "CPU Auxiliary Control register", .formatter = NULL , IGNORE_read, IGNORE_write},
    { SYS_REG_ECTLR_EL1, 0, 0, 1, "ECTLR_EL1", "CPU Extended Control register", .formatter = NULL , IGNORE_read, IGNORE_write},

    { SYS_REG_SCTLR_EL3, 0, 0, 3, "SCTLR_EL3", "System Control Register (EL3)", .formatter = sctlr_el3 , .read = SCTLR_EL3_read, .write = SCTLR_EL3_write},
    { SYS_REG_SCR_EL3, 0, 0, 3, "SCR_EL3", "Secure Configuration Register (EL3)", .formatter = scr_el3 , .read = SCR_EL3_read, .write = SCR_EL3_write},
    { SYS_REG_TTBR0_EL3, 0, 0, 3, "TTBR0_EL3", "Translation Table Base Register 0 (EL3)", NULL,  .read = TTBR0_EL3_read, .write = TTBR0_EL3_write},
    { SYS_REG_TCR_EL3, 0, 0, 3, "TCR_EL3", "", .formatter = tcr_el3,  .read = TCR_EL3_read, .write = TCR_EL3_write},
    { SYS_REG_VBAR_EL3, 0, 0, 3, "VBAR_EL3", "Vector Base Address Register (EL3)", .formatter = NULL , .read = VBAR_EL3_read, .write = VBAR_EL3_write},
    { SYS_REG_MAIR_EL3, 0, 0, 3, "MAIR_EL3", "Memory Attribute Indirection Register (EL3)", .formatter = MAIR_EL1 , .read = MAIR_EL3_read, .write = MAIR_EL3_write},
    { SYS_REG_CPTR_EL3, 0, 0, 3, "CPTR_EL3", "Architectural Feature Trap Register (EL3)", .formatter = NULL , .read = CPTR_EL3_read, .write = CPTR_EL3_write},
    
};

int vcore_get_sys_reg_count(void)
{
    return sizeof(sys_regs_metadata) / sizeof(sys_reg_info_t);
}

int get_index(hv_sys_reg_t reg)
{
    int i;
    int register_count = vcore_get_sys_reg_count();
    for(i = 0; i < register_count; i++) {
        if (sys_regs_metadata[i].id == reg) return i;
    }
    return -EINVAL;
}

void for_each_sysreg(vcore_t* vcore, sysreg_callback callback)
{
    int i;
    hv_vcpu_t vcpu;
    hv_vcpu_config_t config;
    hv_vcpu_exit_t* cpu_exit;
    
    if (vcore == NULL) {
        config = hv_vcpu_config_create();
        
        if (hv_vcpu_create(&vcpu, &cpu_exit,  config) != HV_SUCCESS) {
            printf("Could not create transient vcpu\n");
            return ;
        }
    }
    else {
        vcpu = vcore->vcpu_handle;
    }
    
    int register_count = vcore_get_sys_reg_count();
    for(i = 0; i < register_count; i++) {
        uint64_t value;
        hv_vcpu_get_sys_reg(vcpu, sys_regs_metadata[i].id, &value);
        callback(sys_regs_metadata[i].id, value);
    }
        
    if (vcore == NULL) {
        hv_vcpu_destroy(vcpu);
    }
}

int vcore_reset_sys_reg(hv_sys_reg_t reg, uint64_t value)
{
    int i = get_index(reg);
    if (i<0) return -EINVAL;
    sys_regs_metadata[i].reset_value = value;
    return ERR_SUCCESS;
}

vmm_action_t vcore_invoke_getter(vmm_context_t* context, vcore_t* vcore, hv_reg_t reg, hv_sys_reg_t key)
{
    int i = get_index(key);
    if (i<0) return VMM_ABORT_REQUESTED;
    if (sys_regs_metadata[i].read != NULL)
        sys_regs_metadata[i].read(context, vcore, reg, &sys_regs_metadata[i]);
    else
        return VMM_ABORT_REQUESTED;
    return VMM_CONTINUE;
}

vmm_action_t vcore_invoke_setter(vmm_context_t* context, vcore_t* vcore,  hv_sys_reg_t key, hv_reg_t reg)
{
    int i = get_index(key);
    if (i<0) return VMM_ABORT_REQUESTED;
    if (sys_regs_metadata[i].write != NULL)
        sys_regs_metadata[i].write(context, vcore,  &sys_regs_metadata[i], reg);
    else
        return VMM_ABORT_REQUESTED;
    return VMM_CONTINUE;
}

void signal_sink(int unused)
{
    
}

int vcore_init(vmm_context_t* context, vcore_t* vcore)
{

    hv_vcpu_t vcpu = vcore->vcpu_handle;
    
    // a valid start up address is 0 so just make sure that there is no
    // confusion between a 0 startup and those conditions:
    vcore->skip_until = POISON_ADDRESS;
    vcore->irq_enter = POISON_ADDRESS;
    vcore->emulation_breakpoint_for_post_done = POISON_ADDRESS;
    
    hv_vcpu_set_reg(vcpu, HV_REG_LR, LR_POISION); // poison the last return
    hv_vcpu_set_reg(vcpu, HV_REG_FP, 0);
    hv_vcpu_set_reg(vcpu, HV_REG_PC, 0);
    TRACE_BEGIN(VERBOSE_STARTUP) {
        vcore_print_sys_regs(vcore, 0, FULL | NONZERO);
    } TRACE_END


    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64PFR0_EL1, 0x1122); // Supports EL3, EL2, EL1 (54 + 32 bits), EL0 (64+32 bits)
    // https://elixir.bootlin.com/qemu/v7.0.0/source/target/arm/hvf/hvf.c#L523
    uint64_t sctlr_el1;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &sctlr_el1);
    sctlr_el1 |= 0x30900180;
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, sctlr_el1);
        
    // pretend it is a Cortex-A72
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MIDR_EL1, 0x410fd083);

    uint64_t mmfr2;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR2_EL1, &mmfr2);
    mmfr2 &= ~0xF; // disable CNP ,sharing page tables
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR2_EL1, mmfr2);

    
    hv_vcpu_set_vtimer_mask(vcpu, true);
    // sets 36 bits physical addressing
    /* address space is limited to 36 bits on Apple M1 with Macos 12.5 (TCR_EL1 of the guest is set to this */
    uint64_t tcr_el1;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, &tcr_el1);
    tcr_el1 &= ~0x700000000;
    tcr_el1 |= 2ULL << 32;
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_el1);
    
    // we only do HOST DEBUGING
    if (hv_vcpu_set_trap_debug_exceptions(vcpu, true) != HV_SUCCESS) {
        printf("Could not route exceptions to Host!\n");
    };
    hv_vcpu_set_trap_debug_reg_accesses(vcpu, true);

    uint64_t cpsr;
    hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr);
    // mode MUST be set.
    // default value reads 0x3c5 which would mean EL1H but behavior is EL0
    // setting the mode to either EL1T (0x3c4) or EL1H (0x3c5) gets the proper effect.
    cpsr &= ~0xF; // clears M bits
    cpsr |= PSR_EL1H;
	
    //cpsr |= PSR_DEBUG_EXCEPTION_MASK; // Mask Debug
    cpsr &= ~PSR_DEBUG_EXCEPTION_MASK;  // do not mask debug exceptions
	
    cpsr |= 1 << 8; // Mask SError
    cpsr |= 1 << 7; // Mask IRQ
    cpsr |= 1 << 6; // Mask FIQ
    hv_vcpu_set_reg(vcpu, HV_REG_CPSR, cpsr);
    
    vcore->cpsr = (cpsr & ~0xF) | (hvftool_config.enable_simulation ?  PSR_EL3H : PSR_EL1H);
	
    uint64_t mdscr;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_MDSCR_EL1, &mdscr);
    mdscr |= DBG_MDSCR_MDE;
    mdscr |= DBG_MDSCR_KDE;
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MDSCR_EL1, mdscr);

    if (hvftool_config.ss_mode == SINGLE_BATCH) {
        vcore_enable_single_step(vcore);
    }

    // set breakpoint address
    if (hvftool_config.breakpoint != 0) {
        //TODO translate/adapt breakpopint address to VA when paging is enabled...
        // For the moment, assume paging is disabled or paging is identity
        gva_t target = hvftool_config.breakpoint;
        if (target == 1) {
            // When you enter the VM, GPA = GVA.
            target = hvftool_config.effective_reset_address;
        }
        else if (target == 2) {
            target = loader_symbol_address(hvftool_config.breakpoint_symbol);
            if (target == -1) {
                printf("Could not resolve symbol %s\n", hvftool_config.breakpoint_symbol);
            }
        }
        
        if (target != -1) {
            hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR0_EL1, (uint64_t)target);
            // program the control part
            hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR0_EL1, BPCR_EXEC_EL1_0);
        }

    }
    struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = signal_sink;
    sigaction(SIG_IPI, &sigact, NULL);
    pthread_sigmask(SIG_BLOCK, NULL, &vcore->wfi_mask);
    sigdelset(&vcore->wfi_mask, SIG_IPI);

    pthread_cond_init(&vcore->wfi_cond, NULL);
    pthread_mutex_init(&vcore->wfi_mutex, NULL);

    asm volatile("mrs %0, cntfrq_el0" : "=r"(vcore->cntfrq_hz));

    //printf("cntfrq=%lld\n", vcore->cntfrq_hz);
    hv_vcpu_get_vtimer_offset(vcore->vcpu_handle, &vcore->vtimer_offset);
    
    return ERR_SUCCESS;

}

int vcore_get_current_el(struct vcore* vcore)
{
	return (vcore->cpsr >> 2) & 0x3;
}

int vcore_get_sys_reg_value(vcore_t* vcore,  hv_sys_reg_t key, uint64_t* value)
{
    int i = get_index(key);
    if (i<0) return VMM_ABORT_REQUESTED;
    *value = sys_regs_metadata[i].value;
    return VMM_CONTINUE;
}
