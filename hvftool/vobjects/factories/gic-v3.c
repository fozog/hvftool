/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <stdlib.h>

#include <pthread.h>

#include "hvftool.h"
#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "vobjects.h"

#include "libfdt.h"

/* ----------------------------------------- */
// interrupt metadata


/* ----------------------------------------- */
// GIC Distributor Interface


#define GIC_DIST_CTLR               0x000
#define GIC_DIST_TYPER              0x004
#define GIC_DIST_IIDR               0x008
#define GIC_DIST_TYPER2             0x00C
#define GIC_DIST_IGROUP             0x080
#define GICD_ISENABLER              0x100
#define GICD_ICENABLER              0x180
#define GIC_DIST_PENDING_SET        0x200
#define GIC_DIST_PENDING_CLEAR      0x280
#define GIC_DIST_ACTIVE_SET         0x300
#define GICD_ICACTIVER              0x380
#define GIC_DIST_IPRIORITYR         0x400
#define GIC_DIST_TARGET             0x800
#define GIC_DIST_CFGR               0xc00
#define GIC_DIST_SOFTINT            0xf00
#define GIC_DIST_SGI_PENDING_CLEAR  0xf10
#define GIC_DIST_SGI_PENDING_SET    0xf20
#define GIC_DIST_IROUTER            0x6000
#define GIC_DIST_IDREGS             0xFFD0

/* CoreSight PIDR0 values for ARM GICv3 implementations */
#define GICV3_PIDR0_DIST            0x92
#define GICV3_PIDR0_REDIST          0x93
#define GICV3_PIDR0_ITS             0x94

#define DIST_CTRL_ENABLEGRP0        0x1
#define DIST_CTRL_ENABLEGRP1NS      0x2
#define DIST_CTRL_ENABLEGRP1S       0x4
#define DIST_CTRL_ENABLEGRP1        0x1 // banked access from NS state to DIST_CTRL_ENABLEGRP1NS
#define DIST_CTRL_ENABLEGRP1A       0x2 // banked access from NS state to DIST_CTRL_ENABLEGRP1NS

#define GICD_INT_ACTLOW_LVLTRIG     0x0
#define GICD_INT_EN_CLR_X32         0xffffffff
#define GICD_INT_EN_SET_SGI         0x0000ffff
#define GICD_INT_EN_CLR_PPI         0xffff0000

#define GICD_IIDR_IMPLEMENTER_SHIFT 0
#define GICD_IIDR_IMPLEMENTER_MASK  (0xfff << GICD_IIDR_IMPLEMENTER_SHIFT)
#define GICD_IIDR_REVISION_SHIFT    12
#define GICD_IIDR_REVISION_MASK     (0xf << GICD_IIDR_REVISION_SHIFT)
#define GICD_IIDR_VARIANT_SHIFT     16
#define GICD_IIDR_VARIANT_MASK      (0xf << GICD_IIDR_VARIANT_SHIFT)
#define GICD_IIDR_PRODUCT_ID_SHIFT  24
#define GICD_IIDR_PRODUCT_ID_MASK   (0xff << GICD_IIDR_PRODUCT_ID_SHIFT)


/* ----------------------------------------- */
// GIC Redistributor Interface

#define GIC_REDIST_CTLR                 GIC_DIST_CTLR
#define GIC_REDIST_IIDR                 0x0004
#define GIC_REDIST_TYPER                0x0008
#define GIC_REDIST_STATUSR              GIC_DIST_STATUSR
#define GIC_REDIST_WAKER                0x0014
#define GIC_REDIST_SETLPIR              0x0040
#define GIC_REDIST_CLRLPIR              0x0048
#define GIC_REDIST_PROPBASER            0x0070
#define GIC_REDIST_PENDBASER            0x0078
#define GIC_REDIST_INVLPIR              0x00A0
#define GIC_REDIST_INVALLR              0x00B0
#define GIC_REDIST_SYNCR                0x00C0
#define GIC_REDIST_IDREGS               GIC_DIST_IDREGS
#define GIC_REDIST_PIDR2                GIC_DIST_PIDR2

#define GIC_REDIST_TYPER_LAST           (1U << 4)

#define GICR_ISENABLER0                 0x10100
#define GICR_IGROUPR0                   0x10080
#define GICR_ICENABLER0                 0x10180
#define GICR_ICACTIVER0                 0x10380
#define GICR_IPRIORITYR                 0x10400
#define GICR_ISENABLER0                 0x10100
#define GICR_ICFGR1                     0x10c04


static parameter_t parameters[] = {
    {
        .name = "name",
        .type = PARAM_CSTRING,
        .description = "name of the object for reference",
        .is_mandatory = false,
        .cstring_value = "gic"
    },
    {
        .name = "root",
        .type = PARAM_BOOL,
        .description = "Is this GIC the one that is directly to the processor clusters?",
        .is_mandatory = false,
        .bool_value = true
    }
};



// we assume a GIV v3, Two security states, disable security (GICD->CTRL.DS) is always false
typedef struct {
    vobject_t _;
    mmio_range_t* gic_dist_mmio;            // GIC Distributor registers
    mmio_range_t* gic_redist_mmio;          // GIC Redistributor registers
    struct {
        uint16_t is_enabled    :1;
        uint16_t e1nwf         :1;     //Enable 1 of N Wakeup Functionality.
        uint16_t ds            :1;     // disable security
        uint16_t are_s         :1;     // Affinity Routing Enable, Secure statre
        uint16_t are_ns        :1;     // Affinity Routing Enable, Non Secure statre
        uint16_t enableGrp1S   :1;
        uint16_t enableGrp1NS  :1;
        uint16_t enableGrp0    :1;
        uint16_t rwp           :1;     // register_write_inprogress
    } dist_info;
    struct {
        uint16_t eoimodeNS          :1;
        uint16_t eoimodeS           :1;
        uint16_t irq_bypassGrp1     :1;
        uint16_t fiq_bypassGrp1     :1;
        uint16_t irq_bypassGrp0     :1;
        uint16_t fiq_bypassGrp0     :1;
        uint16_t cbpr               :1;
        uint16_t fiq_enable         :1;
        uint16_t enable_grp1        :1;
        uint16_t enable_grp0        :1;
        uint8_t pmr;
        uint8_t bpr;
    } cpu_info;
    struct {
        uint16_t children_sleep     :1;
        uint16_t processor_sleep    :1;
    } redist_info;
    int irqs_factor;                        // total number of IRQs supported is (irq_factor + 1) * 32 - 1
    mach_port_t wfi_ports[MAX_CPUS];

} gic_vobject_t;

static gic_vobject_t* _gic;

static const uint8_t gicd_ids[] = {
       0x44, 0x00, 0x00, 0x00, 0x92, 0xB4, 0x0B, 0x00, 0x0D, 0xF0, 0x05, 0xB1
   };

/* ---------------- */
// IRQ stuff

struct vcore;

typedef enum {
    SECURE_GROUP0=0,
    SECURE_GROUP1=1,
    NON_SECURE_GROUP1=2
} irq_group_t ;

static char* irq_group_name[] = {
    "0 (Secure group 0)",
    "1 (Secure group 1)",
    "2 (Non-Secure group 1)"
};

typedef struct irq {
    vobject_t* owner;
    irq_group_t group;
    uint8_t config; // edge sensitive or level triggered
    uint8_t priority;
    uint8_t active:1;
    uint8_t pending:1;
    uint8_t enabled:1;
    uint8_t broadcast:1; // if 1, the affinity value is not used and the IRQ is delivered to all nodes
    uint32_t affinity;
    irq_eoi_handler_f eoi_handler;
    struct vcore* vcore;
} irq_t;

static char* irq_config[4] = {
    "0 (level sensitive)",
    "1 (invalid)",
    "2 (edge-triggered",
    "3 (invalid)"
};

#define NCPUS               1
#define MAX_SPIS            32*1        // need to be a multiple of 32
#define MAX_IRQS            (NCPUS * 32 + MAX_SPIS)
static irq_t irqs[MAX_IRQS];


/* ---------------- */

static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);


int gic_signal(int irq)
{
    irqs[irq].pending = true;
    return 0;
}

/* ---------------- */
// vobject factory stuff

static vobject_factory_t gic_factory = {
    .key = "GIC",                                  // matching key for vobj selection
    .description = "Generie Interrupt Controller",         // description
    .fdt_default_name = "interrupt-controller",                 // default name for FDT
    .compatible = ONE_FDT_STRING("arm,gic-v3"),           // default FDT compatiblee
    .size = sizeof(gic_vobject_t),                  // size of the associated vobject
    .initialize = initialize,                         // ctrate vobject
    .mmio_handler = NULL,                                   // MMIO handler
    .generate_fdt = fdt_generator,                          // FDT generator
    .parameters =       parameters,
    .parameter_count =  sizeof(parameters) / sizeof(parameter_t),
};



#define GIC_ONE_SECURITY_STATE  0
#define GIC_TWO_SECURITY_STATE  1

static vmm_action_t gic_dist_mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    gic_vobject_t* gicvobj = (gic_vobject_t*) range->vobj;
    
    gva_t pc;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_PC, &pc);
    
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_write = (iss >> 6) & 1;
    uint32_t srt = (iss >> 16) & 0x1f;
    uint32_t sas = (iss >> 22) & 3;
    uint32_t len = 1 << sas;
    int gicd_offset = (int)(cpu_exit->exception.physical_address - range->start);
    
    if ((gicd_offset >= GIC_DIST_IROUTER && gicd_offset < 0x7FD8 && len !=8) || ((gicd_offset < GIC_DIST_IROUTER || gicd_offset > 0x7FD8) && len != 4 )) {
        TRACE(DEBUG_GIC, "invalid size access GIC-DIST on register offset %d\n", gicd_offset);
        vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
    }

    //TRACE(DEBUG_GIC, "----GIC DIST %s %d %x\n", is_write ? "write" : "read", len, gicd_offset);
    
    switch(gicd_offset) {
        
        case GIC_DIST_CTLR:
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                bool enable_grp0=gicvobj->dist_info.enableGrp0;
                bool enable_grp1ns=gicvobj->dist_info.enableGrp1NS;
                bool enable_grp1s=gicvobj->dist_info.enableGrp1S;
                if (vcore->is_secure_state) {
                    enable_grp0 = (value & DIST_CTRL_ENABLEGRP0) != 0;
                    enable_grp1ns = (value & DIST_CTRL_ENABLEGRP1NS) != 0;
                    enable_grp1s = (value & DIST_CTRL_ENABLEGRP1S) != 0;
                    //RO because of implementation: gicvobj->dist_info.are_s = ((value >> 4) & 1) != 0;
                    //RO because of implementation: gicvobj->dist_info.are_ns = ((value >> 5) & 1) != 0;
                    gicvobj->dist_info.ds = ((value >> 6) & 1) != 0;
                    gicvobj->dist_info.e1nwf = ((value >> 7) & 1) != 0;
                }
                else {
                    enable_grp1ns = (value & (gicvobj->dist_info.are_ns ? DIST_CTRL_ENABLEGRP1A : DIST_CTRL_ENABLEGRP1)) != 0;
                    //RO: gicvobj->dist_info.are_ns = ((value >> 4) & 1) != 0;
                    TRACE(DEBUG_GIC, "----GIC DIST.CTLR = x%d (%llx: are_ns=ignored grp1ns=%s)\n", srt, value, enable_grp1ns ? "enabled": "disabled");
                }
                
                if (gicvobj->dist_info.enableGrp0 != enable_grp0) {
                    // change occurred
                    if (enable_grp0) {
                        TRACE(DEBUG_GIC, "----GIC     enable GRP0 from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                    else {
                        TRACE(DEBUG_GIC, "----GIC     disable GRP0 from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                }
                gicvobj->dist_info.enableGrp0 = enable_grp0;
                
                if (gicvobj->dist_info.enableGrp1NS != enable_grp1ns) {
                    // change occurred
                    if (enable_grp1ns) {
                        TRACE(DEBUG_GIC, "----GIC     enable GRP1-NS from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                    else {
                        TRACE(DEBUG_GIC, "----GIC     disable GRP1-NS from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                }
                gicvobj->dist_info.enableGrp1NS = enable_grp1ns;

                if (gicvobj->dist_info.enableGrp1S != enable_grp1s) {
                    // change occurred
                    if (enable_grp1s) {
                        TRACE(DEBUG_GIC, "----GIC     enable GRP1-S from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                    else {
                        TRACE(DEBUG_GIC, "----GIC     disable GRP1-S from %ssecure state\n", vcore->is_secure_state ? "" : "non ");
                    }
                }
                gicvobj->dist_info.enableGrp1S = enable_grp1s;

            } // end of CTLR write
            else { // CTLR read
                uint32_t value;
                if (vcore->is_secure_state)
                {
                    value = gicvobj->dist_info.rwp << 31;
                    value |= gicvobj->dist_info.ds << 6;
                    value |= gicvobj->dist_info.are_ns << 5;
                    value |= gicvobj->dist_info.are_s << 4;
                    value |= gicvobj->dist_info.enableGrp1S << 2;
                    value |= gicvobj->dist_info.enableGrp1NS << 1;
                    value |= gicvobj->dist_info.enableGrp0 << 0;
                    TRACE(DEBUG_GIC, "----GIC secure x%d = DIST.CTLR (%x: rwp=%d ds=%d, are_ns=%d, are_s=%d, enableGPR1S=%d, enableGRP1NS=%d enableGRP0=%d)\n", srt, value,
                           gicvobj->dist_info.rwp,
                           gicvobj->dist_info.ds,
                           gicvobj->dist_info.are_ns,
                           gicvobj->dist_info.are_s,
                           gicvobj->dist_info.enableGrp1S,
                           gicvobj->dist_info.enableGrp1NS,
                           gicvobj->dist_info.enableGrp0
                    );
                }
                else
                {
                    value = gicvobj->dist_info.rwp << 31;
                    value |= gicvobj->dist_info.are_ns << 4;
                    value |= gicvobj->dist_info.enableGrp1NS << 1; // ARE_NS is wired to 1 so we set this bit only
                    TRACE(DEBUG_GIC, "----GIC x%d = DIST.CTLR (%x: rwp=%d are_ns=%d enableGPR1A=%d, enableGRP1=0)\n", srt, value, gicvobj->dist_info.rwp, gicvobj->dist_info.are_ns, gicvobj->dist_info.enableGrp1NS);
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                
            }
            break;

        case GIC_DIST_TYPER:
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                // the value to write to the virtual GIC is now ready
                TRACE(DEBUG_GIC, "----GIC DIST.TYPER = x%d (%llx) -- IGNORED\n", srt, value);
            }
            else {
                uint32_t value;
                value =  (gicvobj->irqs_factor << 0);
                value |= ((NCPUS - 1) << 5);
                value |= (GIC_TWO_SECURITY_STATE << 10); 
                value |= (0 << 17); // Supports LPI
                value |= (0xF << 19); // 15 ID bits
                value |= (0x1 << 24); // supports Affinity level 3
                value |= (0x1 << 25); // 1 of N SPI interrupts are supported.
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC %d = DIST.TYPER (%x: num_intline=%d, num_cpus=%d LPIs=%s)\n", srt, value,
                       (gicvobj->irqs_factor + 1)*32,
                       NCPUS,
                       "unsupported"
                );
            }
            break;

        case GIC_DIST_IIDR:
            if (is_write) {
                TRACE(DEBUG_GIC, "----GIC !!!! Write to GIC_DIST_IIDR IGNORED!!!\n");
            }
            else {
                uint32_t value;
                /* Return the Implementer Identification Register value
                 * for the emulated GICv3, as reported in GICD_IIDR and GIC_REDIST_IIDR.
                 *
                 * We claim to be an ARM r0p0 with a zero ProductID.
                 * This is the same as an r0p0 GIC-500.
                 */
                value = 0x43b;
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = DIST.IIDR (%x)\n", srt, value);
            }
            break;

        case GIC_DIST_TYPER2:
            if (is_write) {
                TRACE(DEBUG_GIC, "----GIC GIC DIST !!!! Write to TYPER2 IGNORED!!!\n");
            }
            else {
                // only exists for GICv4p1, otherwise RES0
                uint32_t value;
                value =  0;
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = DIST.TYPER (%x)\n", srt, value);
            }
            break;

            
        case GIC_DIST_IGROUP ... (GIC_DIST_IGROUP+0x7C):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = ((gicd_offset - GIC_DIST_IGROUP) / sizeof(uint32_t))*32;
                int irq;
                TRACE(DEBUG_GIC, "----GIC DIST.IRQ[%d-%d].GROUP =  x%d (%llx)\n", base_irq, base_irq+32, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t group =  (value >> irq) & 1;
                    irqs[base_irq+irq].group = group == 0 ? SECURE_GROUP0 : NON_SECURE_GROUP1;
                    TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d].group = %s\n", base_irq + irq, irq_group_name[irqs[base_irq+irq].group]);
                }
            }
            else {
                int base_irq = ((gicd_offset - GIC_DIST_IGROUP) / sizeof(uint32_t))*32;
                uint32_t value = 0;
                int irq;
                for (irq = 0 ; irq < 32; irq++) {
                    value |= (irqs[base_irq+irq].group == SECURE_GROUP0 ? 0 : 1) << irq;
                }
                TRACE(DEBUG_GIC, "----GIC x%d = DIST.IRQ[%d-%d].GROUP (%x)\n", srt, base_irq, base_irq+32, value);
                for (irq = 0 ; irq < 32; irq++) {
                    TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d].group = %s\n", base_irq + irq, irq_group_name[irqs[base_irq+irq].group]);
                }
            }
            break;

            
        // CPU targets handling
        case GIC_DIST_TARGET ... (GIC_DIST_TARGET+0x1C):
            if (is_write) {
                //Error, this is read only
                TRACE(DEBUG_GIC, "----GIC GIC DIST !!! Write to GIC_DIST_TARGET\n");
            }
            else {
                uint32_t value;
                value = 0x11111111; // only one CPU
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_TARGET READ\n");
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
            }
            break;
        case (GIC_DIST_TARGET+0x20) ... (GIC_DIST_TARGET+0x3FC):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_TARGET WRITE (2)\n");

            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_TARGET READ (2)\n");
            }
            break;
            
        // deal with the configuration
        // Linux initially sets this to GICD_INT_ACTLOW_LVLTRIG (level triggered, active low).
        // https://elixir.bootlin.com/linux/v5.19/source/drivers/irqchip/irq-gic-common.c#L95
        case (GIC_DIST_CFGR) ... (GIC_DIST_CFGR+0xFC):
        {
            int reg_index = (gicd_offset - GIC_DIST_CFGR) / sizeof(uint32_t);
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq =reg_index * 16;
                int irq;
                TRACE(DEBUG_GIC, "----GIC DIST.IRQ[%d-%d].CONFIG =  x%d (%llx)\n", base_irq, base_irq+16, srt, value);
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  (value >> (irq*2)) & 3;
                    irqs[base_irq+irq].config = config;
                    TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d].CONFIG = %s\n", base_irq + irq, irq_config[config]);
                }
            }
            else {
                uint64_t value = 0;
                int base_irq = reg_index * 16;
                int irq;
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  irqs[base_irq+irq].config << (irq*2);
                    value |= config;
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = DIST.GIC_DIST_CFGR%d (%llx)\n", srt, reg_index, value);
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  irqs[base_irq+irq].config << (irq*2);
                    TRACE(DEBUG_GIC, "----GIC     IRQ[%d].CONFIG = %s\n", base_irq + irq, irq_config[config]);
                }
            }
        }
            break;

        case GICD_ISENABLER ... GICD_ISENABLER + 0x7C:
        {
            int reg_index = (gicd_offset - GICD_ISENABLER) / sizeof(uint32_t);
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = reg_index * 32;
                int irq;
                TRACE(DEBUG_GIC, "----GIC GICD_ISENABLER%d =  x%d (%llx)\n", reg_index, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_enabled =  (value >> irq) & 1;
                    if (to_be_enabled) {
                        irqs[base_irq+irq].enabled = 1;
                        TRACE(DEBUG_GIC, "----GIC     IRQ[%d] enabled\n", base_irq + irq);
                    }
                }
            }
            else {
                uint64_t value = 0;
                int base_irq = reg_index * 32;
                int irq;
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t enabled =  irqs[base_irq+irq].enabled << irq;
                    value |= enabled;
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = GICD_ISENABLERR%d (%llx)\n", srt, reg_index, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t enabled =  irqs[base_irq+irq].enabled << irq;
                    if (enabled)
                        TRACE(DEBUG_GIC, "----GIC     IRQ[%d].ENABLED = %d\n", base_irq + irq, enabled);
                }
            }
        }
            break;
        // handle priorities
        // Linux initially sets all to GICD_INT_DEF_PRI_X4
        // https://elixir.bootlin.com/linux/v5.19/source/drivers/irqchip/irq-gic-common.c#L102
        case (GIC_DIST_IPRIORITYR) ... (GIC_DIST_IPRIORITYR+0x3FC):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = ((gicd_offset - GIC_DIST_IPRIORITYR) / sizeof(uint32_t))*4;
                int irq;
                TRACE(DEBUG_GIC, "----GIC DIST.IRQ[%d-%d].PRIO =  x%d (%llx)\n", base_irq, base_irq+4, srt, value);
                for (irq = 0 ; irq < 4; irq++) {
                    uint8_t priority =  (value >> (irq*8)) & 0xFF;
                    irqs[base_irq+irq].priority = priority;
                    TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d].PRIO = %d\n", base_irq + irq, priority);
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_IPRIORITYR READ\n");
            }
            break;
            
        case (GICD_ICENABLER) ... (GICD_ICENABLER+0x7C):
        {
            int reg_index = (gicd_offset - GICD_ICENABLER) / sizeof(uint32_t);
            int base_irq = reg_index * 32;
            uint64_t value = 0;
            int irq;
            if (is_write) {
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                TRACE(DEBUG_GIC, "----GIC GICD_ICENABLER%d =  x%d (%llx)\n", reg_index, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_cleared =  (value >> irq) & 1;
                    if (to_be_cleared) {
                        irqs[base_irq+irq].enabled = 0;
                        TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d] disabled\n", base_irq + irq);
                    }
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_ICENABLER READ\n");
            }
        }
            break;
            
        case (GICD_ICACTIVER) ... (GICD_ICACTIVER+0x7C):
        {
            int reg_index = (gicd_offset - GICD_ICACTIVER) / sizeof(uint32_t);
            int base_irq = reg_index * 32;
            uint64_t value = 0;
            int irq;
            if (is_write) {
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                TRACE(DEBUG_GIC, "----GIC GICD_ICACTIVER%d =  x%d (%llx)\n", reg_index, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_cleared =  (value >> irq) & 1;
                    if (to_be_cleared) {
                        irqs[base_irq+irq].active = 0;
                        TRACE(DEBUG_GIC, "----GIC     DIST.IRQ[%d] clear active\n", base_irq + irq);
                    }
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_ICENABLER READ\n");
            }
        }
            break;
    
        case (GIC_DIST_IDREGS) ... (GIC_DIST_IDREGS+0x2F):
            if (is_write) {
                // just ignore
                uint64_t value;
                hv_vcpu_get_reg(vcore->vcpu_handle,srt, &value);
                TRACE(DEBUG_GIC, "----GIC REDIST.ID[%d] = x%d (%llx)\n", gicd_offset - GIC_REDIST_IDREGS, srt, value & 0xFFFFFFFF);
            }
            else {
                uint32_t id;
                int position = gicd_offset - GIC_DIST_IDREGS;
                int idx = position / sizeof(uint32_t);
                if (idx == 4) id =GICV3_PIDR0_DIST;
                else id = gicd_ids[idx];
                if (idx == 6)
                    id |= 3 << 4;/* GIC v3 */
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, id);
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.ID[%d] (%x)\n", srt, gicd_offset - GIC_REDIST_IDREGS, id);
            }
            break;

        case (GIC_DIST_IROUTER) ... (GIC_DIST_IROUTER+0x1ED8):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = ((gicd_offset - GIC_DIST_IROUTER) / sizeof(uint64_t));
                bool is_broadcast = value & (1ULL << 31);
                uint32_t affinity = ~0;
                if (!is_broadcast) affinity = (value & 0xFFFFFF) | ((value >> 8) & 0xFF000000);
                char buffer[16];
                sprintf(buffer,"%02x.%02x.%02x.%02x", (affinity >> 24) & 0xFF, (affinity >> 16) & 0xFF, (affinity >> 8) & 0xFF, (affinity >> 0) & 0xFF);
                TRACE(DEBUG_GIC, "----GIC DIST.IRQ[%d].ROUTER =  x%d (0x%llx affinity=%s)\n", base_irq, srt, value, is_broadcast ? "broadcast": buffer);
                if (is_broadcast) {
                    irqs[base_irq].broadcast = true;
                    irqs[base_irq].affinity = ~0; // not valid
                }
                else {
                    irqs[base_irq].affinity = affinity;
                    irqs[base_irq].vcore = vmm_lookup_vcore_byaffinity(context, affinity);
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GIC_DIST_IROUTER READ\n");
            }
            break;

            
        default:
            TRACE(DEBUG_GIC, "----GIC  Unsupported GIC-DIST register access: %s %d bytes at %x\n", is_write ? "Write" : "Read", len, gicd_offset);
            hv_vcpu_set_reg(vcore->vcpu_handle, srt, 0);
            //vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            break;
    }
    
    hv_vcpu_set_reg(vcore->vcpu_handle, HV_REG_PC, pc+4);

    return VMM_CONTINUE;
}

static vmm_action_t gic_redist_mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    gic_vobject_t* gicvobj = (gic_vobject_t*) range->vobj;
    
    gva_t pc;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_PC, &pc);
    
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_write = (iss >> 6) & 1;
    uint32_t srt = (iss >> 16) & 0x1f;
    uint32_t sas = (iss >> 22) & 3;
    uint32_t len = 1 << sas;
    int gicd_offset = (int)(cpu_exit->exception.physical_address - range->start);

    if ((gicd_offset == GIC_REDIST_TYPER && len !=8) || (gicd_offset != GIC_REDIST_TYPER && len != 4 )) {
        TRACE(DEBUG_GIC, "invalid read size of GIC-REDIST\n");
        vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
    }

    //TRACE(DEBUG_GIC, "----GIC REDIST %s %d %x\n", is_write ? "write" : "read", len, gicd_offset);
    
    switch(gicd_offset)
    {
            
        case (GIC_REDIST_CTLR):
            if (is_write) {
                uint64_t value;
                hv_vcpu_get_reg(vcore->vcpu_handle,srt, &value);
                TRACE(DEBUG_GIC, "---- GIC REDIST.CTLR = x%d (%llx)\n", srt,  value);
            }
            else {
                uint32_t  value=1 << 1; // Clear Enable Supported (read only bit: this is how the implementation works
                TRACE(DEBUG_GIC, "---- x%d = GIC REDIST.CTLR (%x)\n", srt,  value);
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
            }
            break;

        case (GIC_REDIST_TYPER):
            if (is_write) {
                // just ignore
                uint64_t value;
                hv_vcpu_get_reg(vcore->vcpu_handle,srt, &value);
                TRACE(DEBUG_GIC, "----GIC REDIST.TYPER = x%d (%llx) -- IGNORED\n", srt,  value);
            }
            else {
                uint64_t type=0;;
                if (len !=8) {
                    TRACE(DEBUG_GIC, "----GIC invalid read of GIC-REDIST.TYPER GIC-REDIST should be an 8 byte read\n");
                    vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
                }
                else {
                    //TODO: get the value from MPIDR
                    uint32_t affinity = 0; // cpu0
                    type = (uint64_t)affinity << 32;
                    type |= 1 << 24; //All Redistributors with the same Aff3 value must share an LPI Configuration table.
                    type |= 1 << 0; //The implementation supports physical LPIs.
                    type |= GIC_REDIST_TYPER_LAST;
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, type);
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.TYPER (%llx)\n", srt,  type);

            }
            break;
            
        case (GIC_REDIST_WAKER):
            // this field is RAZ/WI is DisableSecurity is not asserted and accessed from non secure mode
            if (is_write) {
                // https://elixir.bootlin.com/linux/v5.19/source/drivers/irqchip/irq-gic-v3.c#L258
                //TODO: implement the logic
                // for now, just make the whole thing up
                if (!gicvobj->dist_info.ds) {
                    TRACE(DEBUG_GIC, "----GIC GIC_REDIST_WAKER = x%d IGNORED (RAZ/WI from non secure mode)\n", srt);
                    break ;
                }
                gicvobj->redist_info.processor_sleep  = false;
                gicvobj->redist_info.children_sleep = false;
                uint64_t value;
                hv_vcpu_get_reg(vcore->vcpu_handle,srt, &value);
                TRACE(DEBUG_GIC, "----GIC GIC_REDIST_WAKER = x%d (%llx: processor_sleep=%d children_sleep=%d)\n", srt,  value, gicvobj->redist_info.processor_sleep, gicvobj->redist_info.children_sleep);
            }
            else {
                uint64_t value = 0;
                if (gicvobj->dist_info.ds) {
                    value = gicvobj->redist_info.processor_sleep << 1;
                    value |= gicvobj->redist_info.children_sleep << 2;
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.WAKER (%llx: processor_sleep=%d children_sleep=%d)\n", srt,  value, gicvobj->redist_info.processor_sleep, gicvobj->redist_info.children_sleep);
            }
            break;

        case (GIC_REDIST_IDREGS) ... (GIC_REDIST_IDREGS+0x2F):
            if (is_write) {
                // just ignore
                uint64_t value;
                hv_vcpu_get_reg(vcore->vcpu_handle,srt, &value);
                TRACE(DEBUG_GIC, "----GIC REDIST.ID[%d] = x%d (%llx)\n", gicd_offset - GIC_REDIST_IDREGS, srt, value & 0xFFFFFFFF);
            }
            else {
                uint32_t id;
                int position = gicd_offset - GIC_DIST_IDREGS;
                int idx = position / sizeof(uint32_t);
                if (idx == 4) id =GICV3_PIDR0_REDIST;
                else id = gicd_ids[idx];
                if (idx == 6)
                    id |= 3 << 4;/* GIC v3 */
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, id);
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.ID[%d] (%x)\n", srt, gicd_offset - GIC_REDIST_IDREGS, id);
            }
            break;

        case GICR_ISENABLER0:
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = 0;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].GICR_ISENABLER0 =  x%d (%llx)\n", base_irq, base_irq+32, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_enabled =  (value >> irq) & 1;
                    if (to_be_enabled) {
                        irqs[base_irq+irq].enabled = 1;
                        TRACE(DEBUG_GIC, "----GIC     IRQ[%d] enabled\n", base_irq + irq);
                    }
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GICR_ISENABLER0 READ\n");
            }
            
        case GICR_IGROUPR0:
            if (is_write) {
                uint64_t value = 0;
                if (!gicvobj->dist_info.ds) {
                    TRACE(DEBUG_GIC, "----GIC GICR_IGROUPR0 = x%d IGNORED (RAZ/WI from non secure mode)\n", srt);
                    break ;
                }
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = 0;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].GROUP =  x%d (%llx)\n", base_irq, base_irq+32, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t group =  (value >> irq) & 1;
                    irqs[base_irq+irq].group = group == 0 ? SECURE_GROUP0 : NON_SECURE_GROUP1;
                    TRACE(DEBUG_GIC, "----GIC     IRQ[%d].group = %s\n", base_irq + irq, irq_group_name[irqs[base_irq+irq].group]);
                }
            }
            else {
                int base_irq = 0;
                uint32_t value = 0;
                if (gicvobj->dist_info.ds) {
                    int irq;
                    for (irq = 0 ; irq < 32; irq++) {
                        value |= (irqs[base_irq+irq].group == SECURE_GROUP0 ? 0 : 1) << irq;
                    }
                }
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.IRQ[%d-%d].GROUP (%x)\n", srt, base_irq, base_irq+32, value);
                if (gicvobj->dist_info.ds) {
                    int irq;
                    for (irq = 0 ; irq < 32; irq++) {
                        TRACE(DEBUG_GIC, "----GIC    IRQ[%d].group = %s\n", base_irq + irq, irq_group_name[irqs[base_irq+irq].group]);
                    }
                }
            }
            break;
            
        case (GICR_ICENABLER0):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = 0;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].CLEAR_ENABLE =  x%d (%llx)\n", base_irq, base_irq+32, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_cleared =  (value >> irq) & 1;
                    if (to_be_cleared) {
                        irqs[base_irq+irq].enabled = 0;
                        TRACE(DEBUG_GIC, "----GIC     RQ[%d] disabled\n", base_irq + irq);
                    }
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GICR_ICENABLER0 READ\n");
            }
            break;

        case (GICR_ICACTIVER0):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = gicd_offset - GICR_ICACTIVER0;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].CLEAR_ACTIVE =  x%d (%llx)\n", base_irq, base_irq+32, srt, value);
                for (irq = 0 ; irq < 32; irq++) {
                    uint8_t to_be_cleared =  (value >> irq) & 1;
                    if (to_be_cleared) {
                        irqs[base_irq+irq].active = 0;
                        TRACE(DEBUG_GIC, "----GIC     REDIST.IRQ[%d] clear active\n", base_irq + irq);
                    }
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GICR_ICACTIVER0 READ\n");
            }
            break;

        case (GICR_IPRIORITYR) ... (GICR_IPRIORITYR+0x1C):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = ((gicd_offset - GICR_IPRIORITYR) / sizeof(uint32_t))*4;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].PRIO =  x%d (%llx)\n", base_irq, base_irq+4, srt, value);
                for (irq = 0 ; irq < 4; irq++) {
                    uint8_t priority =  (value >> (irq*8)) & 0xFF;
                    irqs[base_irq+irq].priority = priority;
                    TRACE(DEBUG_GIC, "----GIC     IRQ[%d].PRIO = %d\n", base_irq + irq, priority);
                }
            }
            else {
                TRACE(DEBUG_GIC, "----GIC TO DO  GICR_IPRIORITYR READ\n");
            }
            break;
            
        case (GICR_ICFGR1):
            if (is_write) {
                uint64_t value = 0;
                if (srt!=31) hv_vcpu_get_reg(vcore->vcpu_handle, srt, &value);
                int base_irq = ((gicd_offset - GICR_ICFGR1) / sizeof(uint32_t))*16;
                int irq;
                TRACE(DEBUG_GIC, "----GIC REDIST.IRQ[%d-%d].CONFIG =  x%d (%llx)\n", base_irq, base_irq+16, srt, value);
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  (value >> (irq*2)) & 3;
                    irqs[base_irq+irq].config = config;
                    TRACE(DEBUG_GIC, "----GIC     IRQ[%d].CONFIG = %s\n", base_irq + irq, irq_config[config]);
                }
            }
            else {
                uint64_t value = 0;
                int base_irq = ((gicd_offset - GICR_ICFGR1) / sizeof(uint32_t))*16;
                int irq;
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  irqs[base_irq+irq].config << (irq*2);
                    value |= config;
                }
                hv_vcpu_set_reg(vcore->vcpu_handle, srt, value);
                TRACE(DEBUG_GIC, "----GIC x%d = REDIST.GICR_ICFGR1 (%llx)\n", srt, value);
                for (irq = 0 ; irq < 16; irq++) {
                    uint8_t config =  irqs[base_irq+irq].config << (irq*2);
                    TRACE(DEBUG_GIC, "----GIC     IRQ[%d].CONFIG = %s\n", base_irq + irq, irq_config[config]);
                }
            }
            break;
            
        default:
            TRACE(DEBUG_GIC, "        Unsupported GIC-REDIST register access: %s %d bytes at %x\n", is_write ? "Write" : "Read", len, gicd_offset);
            hv_vcpu_set_reg(vcore->vcpu_handle, srt, 0);
            //vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            break;
    }
    
    hv_vcpu_set_reg(vcore->vcpu_handle, HV_REG_PC, pc+4);

    return VMM_CONTINUE;
}

/* -------------------------------------------- */
// ICC_BPR all exception levels

vmm_action_t gic_icc_bpr_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg)
{
    gic_vobject_t* gicvobj = _gic;

    uint64_t value=0;
    if (vcore->is_secure_state)
    {
    }
    else
    {
        value = gicvobj->cpu_info.bpr;
    }
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    TRACE(DEBUG_GIC, "----GIC x%d = CPU gic_icc_bpr_read (%lld)\n", reg, value);
    return VMM_CONTINUE;
}

vmm_action_t gic_icc_bpr_write(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg)
{
    gic_vobject_t* gicvobj = _gic;

    uint64_t value = 0;
    if (reg!=31) hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    if (vcore->is_secure_state)
    {
    }
    else
    {
        gicvobj->cpu_info.bpr = value & 3;
    }
    TRACE(DEBUG_GIC, "----GIC CPU gic_icc_bpr_write %lld\n", value);
    return VMM_CONTINUE;
}


/* -------------------------------------------- */
// ICC_CTLR all exception levels

vmm_action_t gic_icc_ctlr_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    gic_vobject_t* gicvobj = _gic;

    uint64_t value =  1 << 15; // A3V
    value |= 8 << 8; //8 priority bits meaning 256 priority levels
    if (vcore->is_secure_state)
    {
    }
    else
    {
    }
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    TRACE(DEBUG_GIC, "----GIC x%d = gic_icc_ctlr_read (%lld)\n", reg, value);
    return VMM_CONTINUE;
}

vmm_action_t gic_icc_ctlr_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    gic_vobject_t* gicvobj = _gic;
    uint64_t value = 0;
    if (reg!=31) hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    if (vcore->is_secure_state)
    {
    }
    else
    {
    }
    TRACE(DEBUG_GIC, "----GIC gic_icc_ctlr_write %lld -- ignored\n", value);
    return VMM_CONTINUE;
}

/* -------------------------------------------- */
// ICC_IAR1_EL1 IInterrupt Controller End Of Interrupt Register 1

vmm_action_t gic_icc_eoir1_el1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    return VMM_CONTINUE;
}

vmm_action_t gic_icc_eoir1_el1_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    uint64_t value=0;
    hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    if (vcore->is_secure_state)
    {
    }
    else
    {
        if (value >= 1020) {
            vcore_disassemble_one(context, vcore, "EOI");
            vcore->pending_irq = false;
        }
        else {
            irqs[value].pending = false;
            vcore->pending_irq = false;
            if (irqs[value].eoi_handler != NULL) irqs[value].eoi_handler(context, irqs[value].owner, vcore);
        }
    }
    TRACE(DEBUG_GIC_FULL, "----GIC gic_icc_eoir1_el1_write = x%d (%lld)\n", reg, value);
    return VMM_CONTINUE;

}

/* -------------------------------------------- */
// ICC_IAR1_EL1 Interrupt Controller Interrupt Acknowledge Register 1

vmm_action_t gic_icc_iar1_el1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    //gic_vobject_t* gicvobj = _gic;

    int64_t value=-1;
    if (vcore->is_secure_state)
    {
    }
    else
    {
        int irq;
        for(irq = 64; irq > 0; irq--)
        {
            if (irqs[irq].pending) {
                value = irq;
                break;
            }
        }
    }
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    TRACE(DEBUG_GIC_FULL, "----GIC x%d = gic_icc_iar1_read %lld\n", reg, value);
    return VMM_CONTINUE;

}

vmm_action_t gic_icc_iar1_el1_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    // ignore, makes no sense
    return VMM_CONTINUE;
}

/* -------------------------------------------- */
// ICC_EGRPEN1 all exception levels

vmm_action_t gic_icc_igrpen1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    gic_vobject_t* gicvobj = _gic;

    uint64_t value=0;
    if (vcore->is_secure_state)
    {
    }
    else
    {
    }
    value = gicvobj->cpu_info.enable_grp1;
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    TRACE(DEBUG_GIC, "----GIC x%d = gic_icc_igrpen1_read %lld\n", reg, value);
    return VMM_CONTINUE;
}

vmm_action_t gic_icc_igrpen1_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    gic_vobject_t* gicvobj = _gic;
    uint64_t value = 0;

    if (reg!=31) hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    if (vcore->is_secure_state)
    {
    }
    else
    {
    }
    gicvobj->cpu_info.enable_grp1 = value & 1;
    TRACE(DEBUG_GIC, "----GIC gic_icc_igrpen1_write %lld\n", value);
    return VMM_CONTINUE;
}

/* -------------------------------------------- */
// ICC_PMR

vmm_action_t gic_icc_pmr_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    gic_vobject_t* gicvobj = _gic;
    
    uint64_t value=0;
    if (vcore->is_secure_state)
    {
    }
    else
    {
        value = gicvobj->cpu_info.pmr;
    }
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    TRACE(DEBUG_GIC, "----GIC x%d = CPU gic_icc_pmr_read (%lld)\n", reg, value);
    return VMM_CONTINUE;
}

vmm_action_t gic_icc_pmr_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    gic_vobject_t* gicvobj = _gic;
    uint64_t value = 0;
    if (reg!=31) hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    if (vcore->is_secure_state)
    {
    }
    else
    {
        gicvobj->cpu_info.pmr = value;
    }
    TRACE(DEBUG_GIC, "----GIC CPU gic_icc_pmr_write %lld\n", value);
    return VMM_CONTINUE;
}


int gic_inject_irq_for(struct vobject* gicvobject, struct vobject* vobj)
{
    int intid;
    gic_vobject_t* gicvobj = (gic_vobject_t*)gicvobject;
    for(intid = 0; intid < MAX_IRQS; intid++)
    {
        if (irqs[intid].owner == vobj) {
            if (irqs[intid].vcore != NULL) {
                vcore_t* vcore = irqs[intid].vcore;
                irqs[intid].pending = true;
                vcore->pending_irq = true;
                
                // make sure it happens now
                hv_vcpus_exit(&vcore->vcpu_handle, 1);
                
                // or make sure the vcore exits the WFI wait
                //pthread_cond_signal(&irqs[intid].vcore->wfi_cond);
                
                
            }
            else {
                printf("Cannot forward interrupt as vcore is not known yet\n");
            }
            break;
        }
    }
    return EXIT_SUCCESS;
}

int gic_register_interrupt(vmm_context_t* context, vobject_t* gic, struct vobject* vobj, irq_type_e type, uint64_t info, irq_eoi_handler_f eoi_handler, int* intidp)
{
    if (type == IRQ_SPI) {
        *intidp = IRQ_SPI_BASE + (int)info;
        irqs[IRQ_SPI_BASE + info].owner = vobj;
        irqs[IRQ_SPI_BASE + info].eoi_handler = eoi_handler;
    }
    else if (type == IRQ_PPI) {
        *intidp = IRQ_PPI_BASE + (int)info;
        irqs[IRQ_PPI_BASE + info].owner = vobj;
        irqs[IRQ_PPI_BASE + info].eoi_handler = eoi_handler;
    }
    else {
        printf("gic_register_interrupt: to be implemented\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}




static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj)
{
    gic_vobject_t* gicvobj = (gic_vobject_t*)vobj;
    gicvobj->gic_dist_mmio = vobject_register_mmio(vobj, MMIO_ALLOCATE, KILOBYTE*64);
    if (gicvobj->gic_dist_mmio == NULL) {
        free(gicvobj->gic_dist_mmio);
        return NULL;
    }
    gicvobj->gic_redist_mmio = vobject_register_mmio(vobj, MMIO_ALLOCATE, KILOBYTE*64*2);
    if (gicvobj->gic_redist_mmio == NULL) {
        free(gicvobj->gic_dist_mmio);
        free(gicvobj->gic_redist_mmio);
        return NULL;
    }

    gicvobj->gic_dist_mmio->handler = gic_dist_mmio_handler;
    gicvobj->gic_redist_mmio->handler = gic_redist_mmio_handler;
    
    /*
     As per the spec:
     For the INTID range 32 to 1019, indicates the maximum SPI supported.
     If the value of this field is N, the maximum SPI INTID is 32(N+1) minus 1. For example, 00011 specifies that the maximum SPI INTID in is 127.
     Based on the defines in this code, SPI_INTID is 32+MAX_SPIS-1.
     so N+1 = (32+MAX_SPIS-1 + 1) / 32
     and N = (32 + MAX_SPIS) / 32 - 1
     */
    gicvobj->irqs_factor = (32 + MAX_SPIS) / 32 - 1;
    
    gicvobj->dist_info.is_enabled = false;
    gicvobj->dist_info.are_ns = true; // force use of Affinity Routing
    gicvobj->dist_info.are_s = true; // force use of Affinity Routing
    gicvobj->redist_info.children_sleep=true;
    gicvobj->redist_info.processor_sleep=true;
    
    
    parameter_t* param = parameter_lookup(vobj->parameters, vobj->parameters_count, "root");
    if (param->bool_value) {
        vmm_register_interrupt_controller(context, (vobject_t*)gicvobj);
    }
    
    _gic = gicvobj;
    
    return vobj;
}

static void fdt_generator(struct vobject* vobj, void* fdt)
{
    /*
     intc@8000000 {
             phandle = <0x8002>;
             reg = <0x00 0x8000000 0x00 0x10000 0x00 0x8010000 0x00 0x10000>;
             compatible = "arm,cortex-a15-gic";
             ranges;
             #size-cells = <0x02>;
             #address-cells = <0x02>;
             interrupt-controller;
             #interrupt-cells = <0x03>;

             v2m@8020000 {
                     phandle = <0x8003>;
                     reg = <0x00 0x8020000 0x00 0x1000>;
                     msi-controller;
                     compatible = "arm,gic-v2m-frame";
             };
     };

      */

    gic_vobject_t* gicvobj = (gic_vobject_t*)vobj;
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s@%llx", FACTORY_CAST(gicvobj)->fdt_default_name, gicvobj->gic_dist_mmio->start);

    _FDT(fdt_begin_node(fdt, buffer));
    _FDT(fdt_property_cell(fdt, "phandle", vobj->phandle));
    _FDT(fdt_property_fdtstring(fdt, "compatible", &(FACTORY_CAST(vobj)->compatible)));
    _FDT(fdt_property_cell(fdt, "#address-cells", 0x2));
    _FDT(fdt_property_cell(fdt, "#size-cells", 0x2));
    _FDT(fdt_property_cell(fdt, "#interrupt-cells", 0x3));

    uint64_t mmio_reg_prop[]    = {
        cpu_to_fdt64(gicvobj->gic_dist_mmio->start), cpu_to_fdt64(gicvobj->gic_dist_mmio->end - gicvobj->gic_dist_mmio->start),
        cpu_to_fdt64(gicvobj->gic_redist_mmio->start), cpu_to_fdt64(gicvobj->gic_redist_mmio->end - gicvobj->gic_redist_mmio->start),
    };
    _FDT(fdt_property(fdt, "reg", mmio_reg_prop, sizeof(mmio_reg_prop)));

    _FDT(fdt_property(fdt, "ranges", NULL, 0));
    _FDT(fdt_property(fdt, "interrupt-controller", NULL, 0));

    _FDT(fdt_end_node(fdt));
    

    
exit_return:; // this is for _FDT

}

int gic_init(void)
{
    return vobjtype_register(&gic_factory);
}
