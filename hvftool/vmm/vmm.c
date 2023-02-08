/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc/_malloc.h>
#include <string.h>

#include <Hypervisor/Hypervisor.h>

#include "bit_operations.h"

#include "libfdt.h"

#if defined(__arm64__)
#define HV_VM_DEFAULT 0
#endif

#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "mmio.h"
#include "smc.h"
#include "vobjects.h"
#include "backends.h"
#include "sysinfo.h"



// make sure devices are always 64KB aligned to allow page sharing in all granule size possible
// this is for device passing from EL1 to EL0 (DPDK)
// or for device assignment in case of nested virtualization


memory_map_t macho_memory_map = {
    // NO ROM
    .rom_start      = 0,
    .rom_end        = 0,
    // just a personal taste...
    .mmio_start     = PHYSICAL_ADDRESS_SPACE - 2*GIGABYTE,
    .mmio_top       = PHYSICAL_ADDRESS_SPACE - 2*GIGABYTE,
    .mmio_end       = (PHYSICAL_ADDRESS_SPACE - 2*GIGABYTE) + 1*GIGABYTE,
    // dictated by default target address of mach-o, don't change the default when creating the mach-o or adapt the following
    .ram_start      = 4*GIGABYTE,
    .ram_bottom     = 4*GIGABYTE,
    .ram_end        = PHYSICAL_ADDRESS_SPACE, // this is nop the allocated memory, but the memory "map"; see vmm_context.top_memory for top of the allocated RAM
    // FDT passed as x0 so no need for a fixed location
    .fdt_start      = 0,
    .fdt_end        = 0,
    .reset_address  = INVALID_PC
};

memory_map_t qemu_memory_map = {
    // as per https://elixir.bootlin.com/qemu/v7.0.0/source/hw/arm/virt.c#L132
    .rom_start      = 0,                        // need to install a nor-flash device with cfi driver
    .rom_end        = 0x8000000,
    
    .mmio_start     = 0,
    .mmio_top       = 0x08000000,
    .mmio_end       = 1*GIGABYTE,
    // dictated by default target address of mach-o
    .ram_start      = 0x40000000,
    .ram_bottom     = 0x40000000+2*MEGABYTE,    // this is where load will place files
    .ram_end        = PHYSICAL_ADDRESS_SPACE,   // this is nop the allocated memory, but the memory "map"; see vmm_context.top_memory for top of the allocated RAM
    //
    .fdt_start      = 0x40000000,               // CONFIG_SYS_SDRAM_BASE which is ram_start
    .fdt_end        = 0x40000000+2*MEGABYTE,    // fake size to say it is present, the size will be retrieved from the actual DTB
    .reset_address  = 0                         // i.e. at the ROM start.
};

struct vobject;

typedef struct {
    gpa_t start;
    gpa_t end;
    void* memory;
    vobject_t* device;
} memory_range_t;


#define MAX_MEMORY_RANGE_COUNT 16
static memory_range_t memory_ranges[MAX_MEMORY_RANGE_COUNT] = {0};
static int memory_range_count = 0;


void* vmm_get_hostpointer_for(gpa_t address)
{
    int i;
    for (i = 0; i < memory_range_count; i++) {
        if (address >= memory_ranges[i].start && address < memory_ranges[i].end) {
            size_t offset = address - memory_ranges[i].start;
            return memory_ranges[i].memory + offset;
        }
    }
    return NULL;
}

int vmm_add_memory_range(gpa_t address, gpa_t end, void* memory, vobject_t* dev)
{
    if (memory_range_count >= MAX_MEMORY_RANGE_COUNT - 1) return -ENOENT;
    memory_range_t* range = &memory_ranges[memory_range_count++];
    range->start = address;
    range->end = end;
    range->memory = memory;
    range->device = dev;
    return ERR_SUCCESS;
}

int vmm_set_memory_map(const char* name)
{
    memory_map_t* selected = NULL;
    if (strcmp(name, "mach-o") == 0) selected = &macho_memory_map;
    else if (strcmp(name, "default") == 0) selected = &macho_memory_map;
    else if (strcmp(name, "qemu") == 0) selected = &qemu_memory_map;
    if (selected == NULL) return -1;
    hvftool_config.memory_map = selected;
    return ERR_SUCCESS;
}



/*
 In theory we don't do fancy addressing (ldp x10, x11, [x1], #16) on MMIO areas.
 BUT
 U-Boot is executing from a NOR that implements CFI.
 CFI method is such that you always have a write before reading registers.
 Just in case, prepare for other cases where we would trap reads also
 In other words need to implement some fancy read methods based on instruction decoding
 This is not usefull currently but leave it here for experimentation and learning
 */
int vmm_do_mmio_read(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit)
{
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_valid = (iss >> 24) & 1; // checks whether bits 23-14 of syndrome are valid. bits 13-0 are always valid
    uint32_t sas = (iss >> 22) & 3;
    uint32_t len = 1 << sas;
    uint32_t srt = (iss >> 16) & 0x1f;
    uint64_t val = 0;
    
    hv_vcpu_t vcpu = vcore->vcpu_handle;

    void* location = (uint32_t*)vmm_gpa_to_hva(context, cpu_exit->exception.physical_address);;
    
    if (!is_valid) {
        if (len != 1) return -1;
        gva_t PC;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &PC);
        uint32_t* instructionp = (uint32_t*)vmm_gpa_to_hva(context, PC);
        uint32_t inst = *instructionp;
        int ldp64 = (inst >> 22) & 0x3ff;
        if (ldp64 == 0b1010100011 || ldp64 == 0b1010100101) {
            int rt = inst & 0x1F;
            inst >>= 5;
            int rn = inst & 0x1f;
            inst >>= 5;
            int rt2 = inst & 0x1f;
            inst >>= 5;
            int imm7 = inst & 0x7f;
            //printf("CFI: LDP  x%d , x%d , [x%d], #%d\n",  rt, rt2, rn, imm7*8);
            //vcore_disassemble_one(context, vcore, "D-trace");
            //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            uint64_t register_base;
            hv_vcpu_get_reg(vcpu, rn, &register_base);
            uint64_t* where = (uint64_t*)vmm_gva_to_hva(vcore, register_base);
            uint64_t val1 = *where++;
            uint64_t val2 = *where;
            hv_vcpu_set_reg(vcpu, rt, val1);
            hv_vcpu_set_reg(vcpu, rt2, val2);
            //TODO deal with signed offset
            hv_vcpu_set_reg(vcpu, rn, register_base + imm7 * 8);
            return ERR_SUCCESS;
        }
        else {
            printf("MMIO: unsupported complex load instruction: %x\n", inst);
            vcore_disassemble_one(context, vcore, "D-trace");
            vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
            return -1;
        }

    }
    else {
        if (len == 8) {
            uint64_t* data = (uint64_t*)location;
            val = *data;
            //printf("MMIO: read uint64_t x%d from %llx (=%llx)\n", srt, cpu_exit->exception.physical_address - range->start, val);
            //vcore_print_general_regs(vcore, 4);
            //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            hv_vcpu_set_reg(vcpu, srt, val);
            return ERR_SUCCESS;
        }
        else if (len == 4) {
            uint32_t* data = (uint32_t*)location;
            val = *data;// sign extension load
            //printf("MMIO: read uint32_t x%d from %llx (=%llx)\n", srt, cpu_exit->exception.physical_address - range->start, val);
            //vcore_print_general_regs(vcore, 4);
            //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            hv_vcpu_set_reg(vcpu, srt, val);
            return ERR_SUCCESS;
        }
        else if (len == 2) {
            uint16_t* data = (uint16_t*)location;
            val = *data;// sign extension load
            //printf("MMIO: read uint16_t x%d from %llx (=%llx)\n", srt, cpu_exit->exception.physical_address - range->start, val);
            //vcore_print_general_regs(vcore, 4);
            //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            hv_vcpu_set_reg(vcpu, srt, val);
            return ERR_SUCCESS;
        }
        //vcore_disassemble_one(context, vcore, "D-trace");
        //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
        uint8_t* data = (uint8_t*)location;
        val = *data; // sign extension load
        hv_vcpu_set_reg(vcpu, srt, val);
    }
    return ERR_SUCCESS;
}

int vmm_mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit)
{
    mmio_range_t* range = mmio_lookup(cpu_exit->exception.physical_address);
    if (range != NULL) {
        return range->handler(context, vcore, cpu_exit, range);
    }
    else {
        hv_vcpu_t vcpu = vcore->vcpu_handle;
	bool is_iss_valid = cpu_exit->exception.syndrome & (1 << 24);
	gva_t pc;
	hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
	if (is_iss_valid) {
	    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
	    uint32_t sas = (iss >> 22) & 3;
	    uint32_t len = 1 << sas;
	    bool is_write = (iss >> 6) & 1;
	    printf("MMIO %s %d bytes on unknown device at %llx\n", is_write ? "write" : "read", len, cpu_exit->exception.physical_address);
	}
	else {
	    printf("MMIO on unknown device at %llx with no valid syndrome: using not MMIO friendly instructions?\n", cpu_exit->exception.physical_address);
	}
        vcore_disassemble_one(context, vcore, "MMIOAbort");
        vcore_print_general_regs(vcore, 4);
        vmm_action_t action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
        
        return action;
    }
    return VMM_ABORT_REQUESTED;
}

int vmm_smc_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit)
{
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    
    uint64_t smc;
    hv_vcpu_get_reg(vcpu, HV_REG_X0, &smc);
    vmm_action_t action = VMM_ABORT_REQUESTED;

    smc_range_t* range = smc_lookup(smc);
    if (range != NULL) {
         action = range->handler(context, vcore, cpu_exit, range);
    }
    else {
        hv_vcpu_t vcpu = vcore->vcpu_handle;
        gva_t pc;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
        printf("SMC: no handler for %llx @%llx\n", smc, pc);
        vcore_disassemble_one(context, vcore, "SMCAbort");
        vcore_print_general_regs(vcore, 4);
        action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
    }
    if (action == VMM_CONTINUE) {
        uint64_t PC;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &PC);
        hv_vcpu_set_reg(vcpu, HV_REG_PC, PC+4);
    }
    return action;
}




int vmm_run(vmm_context_t* context)
{
    int result = 0;
    
    //make sure we point to the executable entry point
    if (context->vcore[0]->config == NULL) {
        printf("No valid core to execute on.\n");
        return -EINVAL;
    }
    
    /* ABI : X0 = FDT*/
    hv_vcpu_set_reg(context->vcore[0]->vcpu_handle, HV_REG_PC, hvftool_config.effective_reset_address);
    hv_vcpu_set_reg(context->vcore[0]->vcpu_handle, HV_REG_X0, hvftool_config.memory_map->fdt_start);
    
    TRACE_BEGIN(DEBUG_PREPARE_VM | DEBUG_PREPARE_PROGRAM) {
        vcore_disassemble_one(context, context->vcore[0], "ENTRY");
    } TRACE_END
    
    // POWERUP THE BOOT CORE
    result = vcore_run(context, context->vcore[0]);
    
    return result;
}


int bits_per_level[5] = {
    9,
    9,
    9,
    9,
    12
};

int bits_at_level[5] = {
/* 0 */    9+9+9+9+12,
/* 1 */    9+9+9+12,
/* 2 */    9+9+12,
/* 3 */    9+12,
/* 4 */    12
};

static char* SPACER = "                                          ";


char shareable[4] = "-?OI";

// very crude paging dumper, only 4KB granule...
static void dump_paging_level(vmm_context_t* context, gpa_t table_pa, uint64_t base,  int level, int tsz, int spacing)
{
    int bits = bits_at_level[level];
    uint64_t size = 1ULL << bits;
    uint64_t* pg = (uint64_t*)vmm_gpa_to_hva(context, table_pa);
    if (level >=5) return;
    int count = 1 << (tsz - bits);
    if (count > 512) count = 512;
    int i;
    for (i=0; i < count; i++) {
        uint64_t start = base + size * i;
        uint64_t end = start + size -1;
        if (is_bit(pg[i], 0))
        {
            if (bits > 12 && is_bit(pg[i], 1)) {
                uint64_t target = pg[i] & ~((0xFFFFULL<<48) | 0xFFF);
                printf("%.*spg[%x] %08llx-%08llx -> table at %08llx\n", spacing, SPACER, i, start, end, target);
                dump_paging_level(context, target, start,  level+1, tsz, spacing+4);
            }
            else {
                uint64_t block_mask = (1ULL << bits_at_level[level + 1]) -1;
                uint64_t mask = bits > 12 ? block_mask : 0xFFF;
                uint64_t target = pg[i] & ~((0xFFFFULL<<48) | mask);
                printf("%.*spg[%x] %08llx-%08llx -> %s at %08llx (%llx, %c/%c%c%c%c%c MAIR[%lld])\n",
                    spacing, SPACER,
                    i, start, end, bits > 12 ? "block" : "page", target,
                        pg[i] & 0xFFF,
                        bits > 12 ? (is_bit(pg[i], 16) ? 'T': 't'): '.', // only valid for block
                        is_bit(pg[i], 11) ? 'G': 'g',
                        is_bit(pg[i], 10) ? 'a': 'A',
                        shareable[get_bits(pg[i], 8, 2)],
                        is_bit(pg[i], 7) ? 'o': 'W',
                        is_bit(pg[i], 5) ? 's': 'S',
                        (pg[i] >> 2 ) & 0b111
                    );
            }
        }
        else {
            //printf("%.*spg[%x] %08llx-%08llx -> not mapped\n", spacing, SPACER, i, start, end);
        }
    }
}

void vmm_dump_paging_level(vmm_context_t* context, gpa_t table_pa, uint64_t base,  int level, int tsz)
{
    dump_paging_level(context, table_pa, base,  level, tsz, 0);
}


#define TRANSLATION_5_LEVELS    0
#define TRANSLATION_4_LEVELS    1
#define TRANSLATION_3_LEVELS    2
#define TRANSLATION_2_LEVELS    3
#define TRANSLATION_1_LEVEL     4

struct {
    int min;
    int max;
    int start_level;
} txsz[6];

gpa_t walk_4k(vcore_t* vcore, gva_t va, gpa_t table, int start_level)
{
    bool is_block;
    bool is_valid;
    gpa_t current = table;
    int level = start_level;
    do {
        //TODO deal with 52 bits: bits 48-51 are not contiguous in the descriptor
        uint64_t* pg = (uint64_t*)vmm_gpa_to_hva(vcore->context, current);
        int index = (va >> (bits_at_level[level])) & 0x1FF;
        //TODO: check mask calculation for 52 bite VA and level 0
        current = pg[index] & ~(0xFFFFULL << 48 | 0xFFF);
        is_block = (pg[index] & 0x3 ) == 1;
        is_valid = (pg[index] & 0x1 ) == 1;
        if (!is_valid) return (uint64_t)POISON_ADDRESS;
        uint64_t mask = (1ULL << bits_at_level[level]) -1;
        if (is_block) return current  + (va & mask);
        level++;
    } while (level < 5);
    return current + (va & 0xFFF);
}

gpa_t translate_4k(vcore_t* vcore, gva_t va, int txsz, gpa_t table)
{
    if (txsz >= 12 && txsz <= 15) {
        return walk_4k(vcore, va, table, TRANSLATION_5_LEVELS);
    }
    else if (txsz >= 16 && txsz <= 24) {
        return walk_4k(vcore, va, table, TRANSLATION_4_LEVELS);
    }
    else if (txsz >= 25 && txsz <= 33) {
        return walk_4k(vcore, va, table, TRANSLATION_3_LEVELS);
    }
    else if (txsz >= 34 && txsz <= 39) {
        return walk_4k(vcore, va, table, TRANSLATION_2_LEVELS);
    }
    else if (txsz >= 40 && txsz <= 42) { /* and FEATURE_TTFT supported */
        return walk_4k(vcore, va, table, TRANSLATION_2_LEVELS);
    }
    else if (txsz >= 43 && txsz <= 48) { /* and FEATURE_TTFT supported */
        return walk_4k(vcore, va, table, TRANSLATION_1_LEVEL);
    }
    else {
        return (gpa_t)POISON_ADDRESS; // unsupported by this code or invalid
    }
}

//TODO do something to support more than no paging and identity mapping and EL1 only...pl011_mmio_handler
gpa_t vmm_gva_to_gpa(vcore_t* vcore, gva_t va)
{
    uint64_t sctlr_el1, tcr_el1;
    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SCTLR_EL1, &sctlr_el1);
    bool is_MMU_ON = (sctlr_el1 & 1) != 0;
    if (is_MMU_ON) {
        //TODO Handle FEAT_TTST for small translation tables
        hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TCR_EL1, &tcr_el1);
        if (va >= (0xFFULL << 52)) {
            uint64_t TTBR1;
            int t1sz = (tcr_el1 >> 16) & 0x3F;
            int granule = (tcr_el1 >> 30) & 0x3;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TTBR1_EL1, &TTBR1);
            
            TTBR1 &= ~((0xFFFFULL<<48) | 0xFFF); // just keep the gpa of the page
            if (granule == 2) {
                return translate_4k(vcore, va, t1sz, TTBR1);
            }
            // unsupported for the moment
            return (gpa_t)POISON_ADDRESS;
        } // end TTBR1 case
        else { // TTBR0
            // there is a corner case to handle:
            // there is need of a jump after setting MMU bit in SCTLR to get the paging operational
            // lets not switch until we see high address bits as all 1s
            // during this time, the granule for TTBR0 is set to 0, not a valid value.
            // so let's use that to detect this situation
            int t0sz = (tcr_el1 >> 0) & 0x3F;
            uint64_t TTBR0;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TTBR1_EL1, &TTBR0);
            int granule = (tcr_el1 >> 14) & 0x3;
            if (granule == 0) {
                // PA=VA between the MMU setup and the activating jump
                return (gpa_t)va;
            }
            else if (granule == 2){
                return translate_4k(vcore, va, t0sz, TTBR0);
            }
            else {
                return (gpa_t)POISON_ADDRESS;
            }
            return va;
        }
    } // end TTBR0 case
    else { // No paging
        return (gpa_t)va;
    }
}


hva_t vmm_gpa_to_hva(vmm_context_t* context, gpa_t gpa)
{
    void* ram = vmm_get_hostpointer_for(gpa);
    
    return ram != NULL ? (hva_t)ram : POISON_ADDRESS;
}

hva_t vmm_gva_to_hva(vcore_t* vcore, gva_t gva)
{
    gpa_t gpa = vmm_gva_to_gpa( vcore, gva);
   
    return vmm_gpa_to_hva(vcore->context, gpa);
}

/* ----------------------------------- */
/* IRQ STUFF*/


int gic_inject_irq_for(struct vobject* gicvobj, struct vobject* vobj);
int vmm_inject_irq_for(vmm_context_t* context, struct vobject* vobj)
{
    gic_inject_irq_for(context->interrupt_parent, vobj);
    return EXIT_SUCCESS;
}

int vmm_register_interrupt_controller(vmm_context_t* context, struct vobject* vobj)
{
    context->interrupt_parent = vobj;
    return EXIT_SUCCESS;
}

int gic_register_interrupt(vmm_context_t* context, struct vobject* gic, struct vobject* vobj, irq_type_e type, uint64_t info, irq_eoi_handler_f eoi_handler, int* intidp);
int vmm_register_interrupt(vmm_context_t* context, struct vobject* vobj, irq_type_e type, uint64_t info, irq_eoi_handler_f eoi_handler, int* intidp)
{
    if (context->interrupt_parent == NULL) {
        printf("No root GIC declared\n");
        return -ENODEV;
    }
    gic_register_interrupt(context, context->interrupt_parent, vobj, type, info, eoi_handler, intidp);
    return EXIT_SUCCESS;
}

static bool reset_values_recorded = false;

vcore_t* vmm_lookup_vcore_byaffinity(vmm_context_t* context, uint32_t affinity)
{
    //TODO: really lookup!
    return context->vcore[0];
}


int vmm_vcore_create(vmm_context_t* context, vcore_t** vcorep)
{
    vcore_t* vcore;
    vcore = malloc(sizeof(vcore_t));
    memset(vcore, 0, sizeof(vcore_t));
    *vcorep = vcore;
    vcore->config = hv_vcpu_config_create();
    
    if (hv_vcpu_create(&vcore->vcpu_handle, &vcore->cpu_exit,  vcore->config) != HV_SUCCESS) {
        printf("Could not create vcpu\n");
        return -EINVAL;
    };
    
    // hack to get access to internal vcpu_zone and tweak HCR_EL2
    {
        uint64_t dummy;
        uint64_t value;
        hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_ELR_EL1, &dummy);
        asm("mov %0,x9": "=r"(value));
        vcore->hvf_guest_context = (arm_guest_context_t*)value;
        if (vcore->hvf_guest_context->ro.ver == kHvVcpuMagic)
        {
            vcore->hvf_guest_context->rw.vncr.hcr_el2 |= 1ULL << 18;
            // trap writes on SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, ESR_EL1, FAR_EL1, AFSR0_EL1, AFSR1_EL1, MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1.
            vcore->hvf_guest_context->rw.vncr.hcr_el2 |= 1ULL << 26;
            // trap reads on SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, ESR_EL1, FAR_EL1, AFSR0_EL1, AFSR1_EL1, MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1.
            vcore->hvf_guest_context->rw.vncr.hcr_el2 |= 1ULL << 30;
            // trap access to VBAR
            vcore->hvf_guest_context->rw.vncr.hcr_el2 |= 1ULL << 43;
            vcore->hvf_guest_context->rw.state_dirty |= 0x4;
            printf("Apple internet guest context captured at %p\n", vcore->hvf_guest_context);
            printf("    HCR EL2 = %llx\n", vcore->hvf_guest_context->rw.vncr.hcr_el2);
        }
    }
    if (!reset_values_recorded) {
        //@TODO RECORD THE VALUES
        reset_values_recorded = true;
    }
    vcore->context = context;
    //TODO: deal with MAXCPUs
    vcore->index = context->vcore_count++;
    context->vcore[vcore->index] = vcore;
    
    return ERR_SUCCESS;
    
}

// let's try to keep this private in the vcore domain
extern sys_reg_info_t sys_regs_metadata[];

static void prepare_syreg(hv_sys_reg_t sysreg, uint64_t value)
{
    //TODO make this clean
    int i = get_index(sysreg);
    sys_regs_metadata[i].reset_value = value;
    if (hvftool_config.dump_reset_sysregs ) vcore_print_sys_reg( sysreg, value, 0, hvftool_config.reset_sysregs_detail);
}

void* vmm_inject_fdt(vmm_context_t* context, void* fdt)
{
    void* vm_fdt = NULL;
    uint32_t aligned_fdt_size = (fdt_totalsize(fdt) + getpagesize() - 1) & ~(getpagesize() -1);
    
    if (hvftool_config.memory_map->fdt_start == 0) {
        // alocate space from the top
        hvftool_config.memory_map->ram_top_free -= aligned_fdt_size;
        hvftool_config.memory_map->fdt_start = hvftool_config.memory_map->ram_top_free;
    }
    vm_fdt =  (void*)vmm_gpa_to_hva(context, hvftool_config.memory_map->fdt_start);
    if (vm_fdt == NULL) {
        printf("Could not translate GPA for FDT: may be a start address issue of -vobj RAM...\n");
        return NULL;
    }
    fdt_open_into(fdt, vm_fdt, aligned_fdt_size);
    fdt_pack(vm_fdt);
    hvftool_config.memory_map->fdt_top = hvftool_config.memory_map->fdt_start + fdt_totalsize(vm_fdt);
    hvftool_config.memory_map->fdt_end = hvftool_config.memory_map->fdt_start + aligned_fdt_size;
    return vm_fdt;
}

int vmm_create(vmm_context_t* context) {

    if (!is_hvf_supported()) return -ENOTSUP;
    
    // MacOS 13 hv_vm_config_t* vmconfig = OS_hv_vm_config();

    if (hv_vm_create(HV_VM_DEFAULT) != HV_SUCCESS) {
        printf("Could not create VM\n");
        return -EIO;
    }
    
    context->memory_pointer = NULL;
    context->page_size = getpagesize();
    
    for_each_sysreg(NULL, prepare_syreg);
    
    return ERR_SUCCESS;
    
}

