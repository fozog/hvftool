//
/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef vcore_emulate_h
#define vcore_emulate_h

#include "hvftool.h"

struct vmm_context;
struct vcore;

typedef enum emulation_action {
    EMULATION_NONE,         // just eret to the normal path
    EMULATION_ERET,         // just eret to the normal path
    EMULATION_CUSTOM,       // special action before eret (located in eumlation_execption_table_code)
    EMULATION_POST_DONE,    // eret to custom action, then branch back to normal path (located in eumlation_execption_table_code)
    EMULATION_POST_HOST     // eret back to normal path with hardware breakpoint set and host custom action
} emulation_action_t;


typedef void (*emulation_post_host_action)(struct vmm_context* context, struct vcore* vcore);

emulation_action_t vcore_emulte_el2(struct vmm_context* context, struct vcore* vcore, gva_t gva, gva_t* custom);
emulation_action_t vcore_emulte_el3(struct vmm_context* context, struct vcore* vcore, gva_t gva, gva_t* custom);

#endif /* vcore_emulate_h */
