/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#ifndef cpuinfo_h
#define cpuinfo_h

#include <Hypervisor/Hypervisor.h>

#include "vcore.h"



struct vcore;

int dbg_cr(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int dfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int dfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int esr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int esr_el2(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int isar0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int isar1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int mfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int mfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int mfr2_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int pfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int pfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int tcr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int tcr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int scr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int sctlr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int sctlr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int MAIR_EL1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);

int vcore_print_sys_reg(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail);
int vcore_print_sys_regs(struct vcore* vcore, int spacing, detail_t detail);
int vcore_print_general_regs(struct vcore* vcore, int spacing);
char* vcore_get_sys_reg_name(hv_sys_reg_t reg);
char* vcore_get_sys_reg_desc(hv_sys_reg_t reg);

#endif /* cpuinfo_h */
