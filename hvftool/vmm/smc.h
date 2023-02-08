/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef smc_h
#define smc_h

#include <stdio.h>

#include <Hypervisor/Hypervisor.h>

#include "vmm.h"


struct vmm_context;
struct vcore;
struct arm_hv_vcpu_exit;
struct devivce;

struct smc_range;
typedef int (*smc_handler_f)(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, struct smc_range* range);

typedef struct smc_range {
    gpa_t start;
    gpa_t end;
    smc_handler_f handler;
    struct vobject* vobj;
} smc_range_t;

smc_range_t* smc_lookup(gpa_t address);
smc_range_t* smc_assign_at(gpa_t address, size_t range_size);

#endif /* smc_h */
