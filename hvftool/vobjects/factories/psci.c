/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <stdlib.h>

#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "vobjects.h"
#include "backends.h"
#include "loader.h"
#include "smc.h"

#include "libfdt.h"

#define REGISTER_SIZE 0x1000

typedef struct {
    vobject_t _;
} psci_vobject_t;


static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);

//static vobject_factory_t psci_factory = { "PSCI", "PSCI", "psci", NULL, sizeof(psci_vobject_t), create_vobject, NULL, NULL, NULL, fdt_generator};

static vobject_factory_t psci_factory = {
    "PSCI",                                 // matching key for vobj selection
    "Power and System Coordination Interface",                // description
    "psci",                                 // default name for FDT
    TWO_FDT_STRING("arm,psci-0.2", "arm,psci"),                 // default FDT compatiblee
    sizeof(psci_vobject_t),                 // size of the associated vobject
    initialize,                         // ctrate vobject
    NULL,                                   // MMIO handler
    NULL,                                   // SMC handler
    NULL,                                   // object terminator
    fdt_generator                           // FDT generator
};

#define _FDT(exp)                                                                       \
    do {                                                                                \
        int ret = (exp);                                                                \
        if (ret < 0) {                                                                  \
            printf("Error creating device tree: %s: %s\n", #exp, fdt_strerror(ret));    \
            goto exit_return;                                                           \
        }                                                                               \
} while (0)


/* passing x0 here is a performance driven, we don't know the cost of calling get_reg */
static int smc_handler(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, struct smc_range* range)
{
    int i;
    uint64_t registers[9];
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    
    vmm_action_t action = VMM_ABORT_REQUESTED;
    
    for(i=0; i<9; i++)
        hv_vcpu_get_reg(vcpu, i, &registers[i]);
    
    TRACE(DEBUG_PSCI, "PSCI call(%llx)\n", registers[0]);
    if (registers[0] == PSCI_0_2_FN_PSCI_VERSION) {
        registers[0] = 2;
        action = VMM_CONTINUE;
    }
    else if (registers[0] == PSCI_0_2_FN_CPU_OFF) {
        //TODO: implement
    }
    else if (registers[0] == PSCI_0_2_FN_SYSTEM_RESET) {
        //TODO implement reset
        printf("RESET requested, poweroff in progress.\n");
        action =  VMM_EXIT_REQUESTED;
    }
    else if (registers[0] == PSCI_0_2_FN_MIGRATE_INFO_TYPE) {
        registers[0] = 2;
        /* this means
         Trusted OS is either not present or does not require migration. A system of this type does not require the caller to use the MIGRATE function. MIGRATE function calls return NOT_SUPPORTED.
         */
        action = VMM_CONTINUE;
    }
    else if (registers[0] == PSCI_0_2_FN_SYSTEM_OFF) {
        action = VMM_EXIT_REQUESTED;
    }
    else {
        // ignore other calls
        printf("PSCI: unsupported function %llx\n", registers[0]);
        action = VMM_ABORT_REQUESTED;
    }

    if (action == VMM_CONTINUE) {
        for(i=0; i<9; i++)
            hv_vcpu_set_reg(vcpu, i, registers[i]);
    }
    
    return action;
}


static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj)
{

    if (vobj == NULL) return NULL;
    
    psci_vobject_t* pscivobj = (psci_vobject_t*)vobj;
    
    VOBJECT_CAST(pscivobj)->smc_range = smc_assign_at(0x84000000, 16);
    if (VOBJECT_CAST(pscivobj)->smc_range == NULL) {
        free(pscivobj);
        return NULL;
    }
    VOBJECT_CAST(pscivobj)->smc_range->handler = smc_handler;
    VOBJECT_CAST(pscivobj)->smc_range->vobj = vobj;

    return vobj;
}

static void fdt_generator(struct vobject* vobj, void* fdt)
{
    /*
        psci {
                migrate = <0x84000005>;
                cpu_on = <0x84000003>;
                cpu_off = <0x84000002>;
                cpu_suspend = <0x84000001>;
                method = "smc";
                compatible = "arm,psci-0.2\0arm,psci";
        };
      */
        _FDT(fdt_begin_node(fdt, "psci"));
        _FDT(fdt_property_fdtstring(fdt, "compatible", &(FACTORY_CAST(vobj)->compatible)));
        _FDT(fdt_property_string(fdt, "method", "smc"));
        _FDT(fdt_property_u32(fdt, "cpu_on", 0x84000003));
        _FDT(fdt_property_u32(fdt, "cpu_off", 0x84000002));
        _FDT(fdt_end_node(fdt));

exit_return:; // this is for _FDT

}

int psci_init(void)
{
    return vobjtype_register(&psci_factory);
}
