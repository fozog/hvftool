/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef mmio_h
#define mmio_h

#include <stdio.h>

#include <Hypervisor/Hypervisor.h>

#include "vmm.h"

#define IPA_MMIO_END   (IPA_SIZE)
#define IPA_MMIO_START (IPA_MMIO_END   - 2 * GIGABYTE)

#define MMIO_ALLOCATE ((uint64_t)-1)


struct vmm_context;
struct vcore;
struct arm_hv_vcpu_exit;
struct devivce;

struct mmio_range;
typedef vmm_action_t (*mmio_handler_f)(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, struct mmio_range* range);

typedef struct mmio_range {
    gpa_t start;
    gpa_t end;
    mmio_handler_f handler;
    struct vobject* vobj;
} mmio_range_t;


void mmio_range_free(mmio_range_t* range);
mmio_range_t* mmio_lookup(gpa_t address);
mmio_range_t* mmio_assign_at(gpa_t address, size_t range_size);


#endif /* mmio_h */
