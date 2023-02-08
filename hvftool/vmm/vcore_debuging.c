/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdlib.h>

#include "vcore.h"
#include "vmm.h"
#include "vcore_info.h"
#include "loader.h"

char* trap_descriptions[] = {
    "Synchonous trap at, Current EL with SP0 (0x0000)",
    "IRQ trap at, Current EL with SP0 (0x0080)",
    "FIQ trap at, Current EL with SP0 (0x0100)",
    "SError trap at, Current EL with SP0 (0x0180)",

    "Synchonous trap at, Current EL with SPx (0x0200)",
    "IRQ trap at, Current EL with SPx (0x0280)",
    "FIQ trap at, Current EL with SPx (0x0300)",
    "SError trap at, Current EL with SPx (0x0380)",

    "Synchonous trap at, Lower EL with AARCH64 (0x0400)",
    "IRQ trap at, Lower EL with AARCH64 (0x0480)",
    "FIQ trap at, Lower EL with AARCH64 (0x0500)",
    "SError trap at, Lower EL with AARCH64 (0x0580)",

    "Synchonous trap at, Lower EL with AARCH32 (0x0600)",
    "IRQ trap at, Lower EL with AARCH32 (0x0680)",
    "FIQ trap at, Lower EL with AARCH32 (0x0700)",
    "SError trap at, Lower EL with AARCH32 (0x0780)",
};

void vcore_disassemble_at(vmm_context_t* context, vcore_t* vcore, const char* prefix, gva_t gva) {
    char* symbolic_location;
    if (IS_IN_EMULATION_TABLE(gva)) {
        int trap = (int)((gva-EMULATION_VBAR_ADDRESS)/0x80);
        printf("Emulation starts on %s\n", trap_descriptions[trap]);
        return;
    }
    else if (IS_IN_UNTRAPPED_TABLE(gva)) {
        gva_t elr_el1;
        hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_ELR_EL1, &elr_el1);
        printf("Instruction abort while VBAR_EL1 not defined!\n");
        printf("Original instruction that caused the synchronous exception:\n");
        vcore_disassemble_at(context, vcore, "<I-Abort", elr_el1);
        vcore_print_general_regs(vcore, 4);
    }
    else if (IS_IN_INJECTION_TABLE(gva)) {
        //if ((gva & 0x7F ) == 0) printf("End of Emulation\n");
        uint32_t* instruction = (uint32_t*)(vmm_gva_to_hva(vcore, gva));
        printf("%d>%-14s@PC=0x%012llx   %08x\n", vcore_get_current_el(vcore), "Injection", gva, *instruction);
        //vcore_interactive_debug(context, vcore, vcore->cpu_exit, VMM_CONTINUE);
    }
    else {
        uint32_t* instruction = (uint32_t*)(vmm_gva_to_hva(vcore, gva));
        char* dis = loader_disassemble_at(vcore, gva, &symbolic_location);
        if (instruction != (uint32_t*)POISON_ADDRESS)
            printf("%d>%-14s@PC=0x%012llx   %08x   %-36s ; %s\n", vcore_get_current_el(vcore), prefix, gva, *instruction, dis, symbolic_location);
        else
            printf("%d>%-14s@PC=0x%012llx   #N/A       %-36s ; %s\n", vcore_get_current_el(vcore), prefix, gva, dis, symbolic_location);
        free(symbolic_location);
    }
}

void vcore_disassemble_one(vmm_context_t* context, vcore_t* vcore, const char* prefix)
{
    gva_t pc;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_PC, &pc);
    vcore_disassemble_at(context, vcore, prefix, pc);
}

void vcore_disassemble_caller(vmm_context_t* context, vcore_t* vcore, const char* prefix)
{
    gva_t sp_el1;
    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, &sp_el1);
    gva_t fp;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_FP, &fp);
    gva_t lr;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_LR, &lr);
    uint64_t* framep = (uint64_t*)vmm_gva_to_hva(vcore, fp);
    if (framep == (uint64_t*)POISON_ADDRESS || framep == (uint64_t*)-4) {
        printf("Cannot walk back the stack\n");
    }
    else {
	vcore_disassemble_at(context, vcore, prefix, lr - 4);
    }
}

int vcore_enable_single_step(vcore_t* vcore)
{
    uint64_t cpsr;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_CPSR, &cpsr);
    cpsr |= PSR_SINGLE_STEP;
    hv_vcpu_set_reg(vcore->vcpu_handle, HV_REG_CPSR, cpsr);
    
    uint64_t mdscr;
    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_MDSCR_EL1, &mdscr);
    mdscr |= DBG_MDSCR_SS;
    hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_MDSCR_EL1, mdscr);

    vcore->is_single_stepping = true;
    
    return ERR_SUCCESS;
}

int vcore_disable_single_step(vcore_t* vcore)
{
    uint64_t cpsr;
    hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_CPSR, &cpsr);
    cpsr &= ~PSR_SINGLE_STEP;
    hv_vcpu_set_reg(vcore->vcpu_handle, HV_REG_CPSR, cpsr);
    
    uint64_t mdscr;
    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_MDSCR_EL1, &mdscr);
    mdscr &= ~DBG_MDSCR_SS;
    hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_MDSCR_EL1, mdscr);
    vcore->is_single_stepping = false;
    return ERR_SUCCESS;
}


vmm_action_t vcore_interactive_debug(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, vmm_action_t action_for_quit)
{
    char c;    //TODO: offer to toggle brekapoints or set breakpoints...
#if 0
    printf("ticks=%llx, hcr_el2=%llx, dirty=%ll x\n",
           vcore->hvf_guest_context->rw.guest_tick_count,
           vcore->hvf_guest_context->rw.vncr.hcr_el2,
           vcore->hvf_guest_context->rw.state_dirty
           );
#endif
    // when we hit a breakpoint, the instruction ABOUT TO be executed is displayed.
    // 'r' will give the registers before the instruction is executed
    // ' ' will advance and execute this instruction
    // a subsequent 'r' will display the (may be) modified registers
    printf("debug>");
    do {
        fread(&c, 1, 1, stdin);
        if (c == ' ') {
            hvftool_config.ss_mode = SINGLE_INTERACTIVE;
            vcore_enable_single_step(vcore);
        }
        else if (c == '>') {
            hvftool_config.ss_mode = SINGLE_INTERACTIVE_TO_BATCH;
            vcore_enable_single_step(vcore);
        }
        else if (c == '?') {
            hvftool_config.ss_mode = SINGLE_SILENT;
            vcore_enable_single_step(vcore);
        }
        else if (c == 'g') {
            hvftool_config.ss_mode = SINGLE_NONE;
            vcore_disable_single_step(vcore);
        }
        else if (c == 'p') {
            
            uint64_t ttbr0;
            gpa_t base;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_TTBR0_EL1, &ttbr0);
            base = (ttbr0 & ~1); 
            vmm_dump_paging_level( context, base, 0, 2 ,32);
        }
        else if (c == 'r') {
            vcore_print_general_regs(vcore, 4);
        }
        else if (c == 's') {
            vcore_print_sys_regs(vcore, 4, SHORT  | NONZERO);
        }
        else if (c == 'S') {
            vcore_print_sys_regs(vcore, 4, FULL | NONZERO);
        }
        else if (c == 'e') {
            uint64_t esr_el1;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_ESR_EL1, &esr_el1);
	    vcore_print_sys_reg(SYS_REG_ESR_EL2, cpu_exit->exception.syndrome, 4, FULL);
	    vcore_print_sys_reg(HV_SYS_REG_ESR_EL1, esr_el1, 4, FULL);
        }
        else if (c == 'f') {
            // prints the current stack frame
            //TODO selects the right one based on exception level
            gva_t sp_el1;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, &sp_el1);
            gva_t fp;
            hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_FP, &fp);
            printf("SP=%llx, FP=%llx\n", sp_el1, fp);
            uint64_t* frame_top = (uint64_t*)vmm_gva_to_hva(vcore, fp);
            frame_top--;
            fp-=8;
            uint64_t* frame_bottom = (uint64_t*)vmm_gva_to_hva(vcore, sp_el1);
            while(frame_top > frame_bottom-1) {
                printf("%llx %llx\n", fp, *frame_top--);
                fp -= 8;
            }
        }
        else if (c == 'T') {

            // prints the current stack frame
            //TODO selects the right one based on exception level
            gva_t sp_el1;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, &sp_el1);
            //TOFO how to get the stack top? probably by walking the frames first.
            gva_t stackp = 0x40200000;
            printf("HACK: Stack top set at %llx SP=%llx\n", stackp, sp_el1);
            uint64_t* current = (uint64_t*)vmm_gva_to_hva(vcore, stackp);
            current--;
            stackp -= 8;
            while(stackp > sp_el1-8) {
                printf("%llx %llx\n", stackp, *current);
                current--;
                stackp -= 8;
            }
        }
        else if (c == 'C') {
            // prints the current stack frame
            //TODO selects the right one based on exception level
            gva_t sp_el1;
            hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, &sp_el1);
            gva_t fp;
            hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_FP, &fp);
            gva_t lr;
            hv_vcpu_get_reg(vcore->vcpu_handle, HV_REG_LR, &lr);
            printf("SP=%llx, FP=%llx, LR=%llx\n", sp_el1, fp, lr);
            uint64_t* framep = (uint64_t*)vmm_gva_to_hva(vcore, fp);
            if (framep == (uint64_t*)-8 || framep == (uint64_t*)-4) {
                printf("Cannot walk back the stack\n");
            }
            else {
                while (lr != LR_POISION && lr !=0 && (int64_t)framep > 0) {
                    char* symbolic_location;
                    loader_disassemble_at(vcore, lr, &symbolic_location);
                    printf("%llx ; %s\n", lr, symbolic_location == NULL ? "invalid location" : symbolic_location);
                    if (symbolic_location != NULL) free(symbolic_location);
                    if ((int64_t)framep > 0) {
                        lr = *(framep+1);
                        framep = (uint64_t*)vmm_gva_to_hva(vcore, *framep);
                    }
                }
            }
        }
        else if (c == 'A') {
            // just exit debugging
            return VMM_ABORT_REQUESTED;
        }
        else if (c == 'Q') {
            // just exit debugging
            return action_for_quit;
        }
        else if (c == 'I') {
            vcore->pending_irq = true;
        }
        else if (c == '=') {
            printf("Instructions = %lld\n", vcore->stepped_instructions);
            printf("Exit-MMIO = %lld\n", vcore->vm_exits_mmio);
            printf("Exits-Emulation = %lld\n", vcore->vm_emulation);
            printf("Other Exits = %lld\n", vcore->vm_exits - vcore->stepped_instructions - vcore->vm_exits_mmio - vcore->vm_emulation);
        }
        else {
            printf("unknown command %c. \n", c);
            printf("    ' ' continue as singlestep interactive.\n");
            printf("    '>' continue as singlestep batch.\n");
            printf("    'A' quits interactive debugging and triggers an Abort.\n");
            printf("    'C' Call stack.\n");
            printf("    'e' dumps exception information.\n");
            printf("    'f' stack frames.\n");
            printf("    'g' continue running without tracing instructions.\n");
            printf("    'Q' quits interactive debugging (typically when debugging an abort: will also abort the VM).\n");
            printf("    'r' dumps general registers.\n");
            printf("    's' dumps non zero system registers.\n");
            printf("    'S' dumps details on non zero system registers.\n");
            printf("    'T' Stack dump.\n");
        }
    } while (c != ' ' && c != '>' && c != 'g' && c != 'I' && c != '?');
    //printf("continue...\n");
    return VMM_CONTINUE;
    
}
