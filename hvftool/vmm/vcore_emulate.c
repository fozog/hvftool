/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */



#include "vmm.h"

#include "vcore_emulate.h"
#include "vcore_info.h"
#include "bit_operations.h"

#define MSR	    (0xd51 << 20)
#define MRS	    (0xd53 << 20)
#define TLBI_   (0b110101010000 << 20)

// CPTR --------------

vmm_action_t CPTR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;
        //TODO: emulation?
    }
    return VMM_CONTINUE;
}

vmm_action_t CPTR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// MAIR --------------

vmm_action_t MAIR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;
        
        vcore_print_sys_reg(sys_reg->id, sys_reg->value, 4, FULL);
        
        printf("    ->\n");

        hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_MAIR_EL1, value);
        vcore_print_sys_reg(HV_SYS_REG_MAIR_EL1, sys_reg->value, 8, FULL);
    }
    return VMM_CONTINUE;
}

vmm_action_t MAIR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// SCR --------------

vmm_action_t SCR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        
        vcore_print_sys_reg(sys_reg->id, sys_reg->value, 4, FULL);
        
        sys_reg->value = value;
    }
    return VMM_CONTINUE;
}

vmm_action_t SCR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// SCTLR --------------

void context_break_on_any_exception(vmm_context_t* context);

void SCTLR_EL1_sync_from_SCTLR_EL3(struct vmm_context* context, struct vcore* vcore)
{
    uint64_t sctrl_el3;
    
    vcore_get_sys_reg_value(vcore, SYS_REG_SCTLR_EL3, &sctrl_el3);

    // now report the first 4 bits in SCTLR_EL1
    uint64_t sctrl_el1;
    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SCTLR_EL1, &sctrl_el1);
    sctrl_el1 = copy_bits(sctrl_el3, 0, sctrl_el1, 0, 4);
    sctrl_el1 = copy_bits(sctrl_el3, 12, sctrl_el1, 12, 1);
    hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SCTLR_EL1, sctrl_el1);
    
    printf("    ->\n");
    vcore_print_sys_reg(HV_SYS_REG_SCTLR_EL1, sctrl_el1, 8, FULL);

    if ((sctrl_el1 & 1) != 0) {
        //context_break_on_any_exception(context);
        //vcore_interactive_debug(context, vcore, vcore->cpu_exit, VMM_ABORT_REQUESTED);
    }
}

vmm_action_t SCTLR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;
        
        vcore_print_sys_reg(sys_reg->id, sys_reg->value, 4, FULL);

        vcore->finish_emulation_at = (uint64_t)SCTLR_EL1_sync_from_SCTLR_EL3;
        vcore->finish_action = EMULATION_POST_HOST;
        
    }
    return VMM_CONTINUE;
}

vmm_action_t SCTLR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// SP_EL1 --------------

// MRS instructions in EL3 for this register cause an synchornous exception
// so we need to execute it
vmm_action_t SP_EL1_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;
        hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, value);
    }
    return VMM_CONTINUE;
}

vmm_action_t SP_EL1_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// TCR --------------

vmm_action_t TCR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t tcr_el3;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &tcr_el3);
        sys_reg->value = tcr_el3;
        
        vcore_print_sys_reg(sys_reg->id, tcr_el3, 4, FULL);
        
        uint64_t tcr_el1;
        hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TCR_EL1, &tcr_el1);
        tcr_el1 = copy_bits(tcr_el3, 0, tcr_el1, 0, 6); // copies T0SZ
        tcr_el1 = copy_bits(tcr_el3, 8, tcr_el1, 8, 8); // copies IRGN0, ORGN0, SH0, TG0
        tcr_el1 = copy_bits(tcr_el3, 16, tcr_el1, 32, 3); // copies PS
        hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TCR_EL1, tcr_el1);
        
        printf("    ->\n");
        vcore_print_sys_reg(HV_SYS_REG_TCR_EL1, tcr_el1, 8, FULL);
        

    }
    return VMM_CONTINUE;
}

vmm_action_t TCR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// TTBR0 --------------

// from vcore_run.c
void populate_emulation_code(void* address);

vmm_action_t TTBR0_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;

        vcore_print_sys_reg(SYS_REG_TTBR0_EL3, value, 4, FULL);
        
        // injects a page that says the end of memory is mapped
        // this covers EMULATION_VBAR_ADDRESS and UNTRAPPED_VBAR_ADDRESS
        uint64_t* pg = (uint64_t*)vmm_gpa_to_hva(vcore->context, sys_reg->value);
        pg[3] = 0xc0000000 | 0b1 << 10| 0b11 << 8 | 0b11 << 6 | 0x1;
        
        if (hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TTBR0_EL1, sys_reg->value) != HV_SUCCESS)
            printf("could not set TBBR0_EL1 for emulation!\n");

        printf("    ->\n");
        vcore_print_sys_reg(HV_SYS_REG_TTBR0_EL1, value, 8, FULL);

        //vmm_dump_paging_level( context, sys_reg->value & ~1, 0, 2 ,32);

    }
    return VMM_CONTINUE;
}

vmm_action_t TTBR0_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}

// VBAR --------------

vmm_action_t VBAR_EL3_write(struct vmm_context* context, struct vcore* vcore, sys_reg_info_t* sys_reg, hv_reg_t reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
        sys_reg->value = value;
    }
    return VMM_CONTINUE;
}

vmm_action_t VBAR_EL3_read(struct vmm_context* context, struct vcore* vcore, hv_reg_t reg, sys_reg_info_t* sys_reg)
{
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
        uint64_t value;
        value = sys_reg->value;
        hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }
    return VMM_CONTINUE;
}



emulation_action_t vcore_emulte_el2(struct vmm_context* context, struct vcore* vcore, gva_t gva, gva_t* custom)
{
	return EMULATION_ERET;
}


emulation_action_t vcore_emulte_el3(struct vmm_context* context, struct vcore* vcore, gva_t gva, gva_t* custom)
{
    uint32_t* instruction = (uint32_t*)(vmm_gva_to_hva(vcore, gva));
    //*instruction = 0xd518c000;  // msr vbar_el1, x0
    uint32_t bits_12_instructions = *instruction & 0xFFF00000;
    
    vcore->vm_emulation++;
    
    vcore->finish_action = EMULATION_ERET;
    vcore->finish_emulation_at = 0;
    
    switch(bits_12_instructions) {
            
        case MSR:
        {
            hv_reg_t reg = *instruction & 0x1F;
            hv_sys_reg_t key = (((*instruction) >> 5 ) & 0x7FFF) | 0x8000;
            //printf("    Key=%04x\n", key);
            vcore_invoke_setter(context, vcore, key, reg);
        }
            break;
            
        case MRS:
        {
            hv_reg_t reg = *instruction & 0x1F;
            hv_sys_reg_t key = (((*instruction) >> 5 ) & 0x7FFF) | 0x8000;
            //printf("    Key=%04x\n", key);
            vcore_invoke_getter(context, vcore, reg, key);
        }
            break;
            
        case TLBI_:
        {
            // this may be other instructions
            uint32_t tlbi_mask = 0xFFF8F000;
            if ((*instruction & tlbi_mask) == 0xd5088000) {
                vcore->finish_emulation_at = INJECTION_VBAR_ADDRESS + (EMULATION_TLBI_INDEX * sizeof(uint32_t));
                vcore->finish_action = EMULATION_CUSTOM;
            }
        }
            break;
            
        default:
        {
            printf("!!!!!!!!!!!!\nUNKNOWN INSTRUCTION %08x...\n!!!!!!!!!!!!\n", *instruction);
            vcore_interactive_debug(context, vcore, vcore->cpu_exit, VMM_ABORT_REQUESTED);
        }
    }
    
    if (vcore->finish_emulation_at != 0) {
        if (custom != NULL)
            *custom = vcore->finish_emulation_at;
    }
    
    return vcore->finish_action;
    
}
