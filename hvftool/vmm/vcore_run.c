/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include <mach/mach_time.h>

#include "hvftool.h"
#include "trace.h"
#include "vcore.h"
#include "vmm.h"
#include "vcore_info.h"
#include "mmio.h"
#include "loader.h"
#include "vobjects.h"
#include "vcore_emulate.h"

int gic_signal(int irq);

// THE MAIN LOOP...


/*
 SingleStep    @PC=0xffffffc0082b1178   885f7e60   ldxr w0, [x19]                   ; kernel_init_freeable+0200
 SingleStep    @PC=0xffffffc0082b117c   11000401   add w1, w0, #1                   ; kernel_init_freeable+0204
 SingleStep    @PC=0xffffffc0082b1180   88027e61   stxr w2, w1, [x19]               ; kernel_init_freeable+0208
 SingleStep    @PC=0xffffffc0082b1184   35ffffa2   cbnz w2, 0xffffffc0082b1178 <kernel_init_freeable+0x200> ; kernel_init_freeable+020c
 
SingleStep @PC=0xffffffc008056854   c85f7c60   ldxr x0, [x3]                    ; prb_record_text_space+0010
SingleStep @PC=0xffffffc008056858   ca010004   eor x4, x0, x1                   ; prb_record_text_space+0014
SingleStep @PC=0xffffffc00805685c   b5000084   cbnz x4, 0xffffffc00805686c <prb_record_text_space+0x28> ; prb_record_text_space+0018
SingleStep @PC=0xffffffc008056860   c804fc62   stlxr w4, x2, [x3]               ; prb_record_text_space+001c
SingleStep @PC=0xffffffc008056864   35ffff84   cbnz w4, 0xffffffc008056854 <prb_record_text_space+0x10> ; prb_record_text_space+0020
 
SingleStep    @PC=0xffffffc00805056c   885ffc61   ldaxr w1, [x3]                   ; up+0064
SingleStep    @PC=0xffffffc008050570   4a000024   eor w4, w1, w0                   ; up+0068
SingleStep    @PC=0xffffffc008050574   35000064   cbnz w4, 0xffffffc008050580 <up+0x78> ; up+006c
SingleStep    @PC=0xffffffc008050578   88047c62   stxr w4, w2, [x3]                ; up+0070
SingleStep    @PC=0xffffffc00805057c   35ffff84   cbnz w4, 0xffffffc00805056c <up+0x64> ; up+0074
 
 SingleStep    @PC=0xffffffc0080501f4   c85ffc60   ldaxr x0, [x3]                   ; atomic_dec_and_mutex_lock+00b8
 SingleStep    @PC=0xffffffc0080501f8   ca010004   eor x4, x0, x1                   ; atomic_dec_and_mutex_lock+00bc
 SingleStep    @PC=0xffffffc0080501fc   b5000064   cbnz x4, 0xffffffc008050208 <atomic_dec_and_mutex_lock+0xcc> ; atomic_dec_and_mutex_lock+00c0
 SingleStep    @PC=0xffffffc008050200   c8047c62   stxr w4, x2, [x3]                ; atomic_dec_and_mutex_lock+00c4
 SingleStep    @PC=0xffffffc008050204   35ffff84   cbnz w4, 0xffffffc0080501f4 <atomic_dec_and_mutex_lock+0xb8> ; atomic_dec_and_mutex_lock+00c8
 
 SingleStep    @PC=0xffffffc00808dd58   085f7c60   ldxrb w0, [x3]                   ; quiet_vmstat+0074
 SingleStep    @PC=0xffffffc00808dd5c   4a010004   eor w4, w0, w1                   ; quiet_vmstat+0078
 SingleStep    @PC=0xffffffc00808dd60   35000064   cbnz w4, 0xffffffc00808dd6c <quiet_vmstat+0x88> ; quiet_vmstat+007c
 SingleStep    @PC=0xffffffc00808dd64   08047c62   stxrb w4, w2, [x3]               ; quiet_vmstat+0080
 SingleStep    @PC=0xffffffc00808dd68   35ffff84   cbnz w4, 0xffffffc00808dd58 <quiet_vmstat+0x74> ; quiet_vmstat+0084
 
 */



/* =======================
    Smart SingleStepping: goes pver critical section transparently.
 SStep of "Load Aqcuire" exclusive with "Store Release" logic is not possible.
 Execution has to go in one step from LA to ST instructions
 
 */

static bool is_load_exclusive(uint32_t* instruction)
{
    bool result = false;
    
    if ((*instruction & ~0x400003FF) == 0x885f7c00)
        return true; // LDXR

    if ((*instruction & ~0x3FF) == 0x885ffc00)
        return true; // LDAXR LDAXRB LDAXRH

    if ((*instruction & ~0x3FF) == 0xC85ffc00)
        return true; // LDAXR LDAXRB LDAXRH

    if ((*instruction & ~0x3FF) == 0x085f7c00)
        return true; // LDAXR LDAXRB LDAXRH
    return result;
}

hva_t target_cbnz(uint32_t* instruction)
{
    uint32_t opcode = *instruction;
    uint32_t inst = (opcode & ~(0x80FFFFFF));
    if ( inst == (0x35 << 24)) {
        // this is a cbnz
        int32_t displacement = ((*instruction >> 5) & 0x7FFFF)*4;
        if (displacement & 0x40000) {
            // sign extend
            displacement |= 0xFFF80000;
        }
        int64_t target = (hva_t)((hva_t)instruction + displacement);
        return target;
    }
    return (hva_t)INVALID_ADDRESS;
}

static hva_t find_matching_cbnz(uint32_t* instruction)
{
    uint32_t* current = instruction;
    int i;
    ++current; // skip the load exclusive that triggered the search
    for (i=0; i<10; i++) // don't try to find a loop after 10 instructions
    {
        if (target_cbnz(current) == (hva_t)instruction) return (hva_t)current;
        current++;
    }
    return (hva_t)INVALID_ADDRESS;
}

/* =========================
 */

uint64_t now_host;
uint64_t now_guest;

bool is_instruction_of_interest(uint32_t instruction)
{
#if 0
    //MRS
    if ((instruction >> 20) == 0b110101010011) {
        //VBAR_EL1
        if ((instruction >> 5) && 0x7FFF == 0b100011000000000) {
            return true;
        }
    }
    //MRS
    else if ((instruction >> 20) == 0b110101010001) {
        //VBAR_EL1
        if (((instruction >> 5) & 0x7FFF) == 0b100011000000000) {
            return true;
        }
    }
#endif
#if 0
    //mrs x1, TTBR0_EL3
    if (instruction == 0xd53e2001)
        return true;
    
#endif
    
	return false;
}


/* =========================
 */

int handle_pc_in_exception_table(vmm_context_t* context, vcore_t* vcore, uint64_t elr_el1)
{
    int action = VMM_ABORT_REQUESTED;
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    int current_el = vcore_get_current_el(vcore);
    gva_t custom = 0;
    emulation_action_t emulation_action = EMULATION_ERET;
    
    if (!vcore->is_single_stepping)
        vcore_disassemble_at(context, vcore, "Emul", elr_el1);
    
    if (current_el == 3) {
        emulation_action = vcore_emulte_el3(context, vcore, elr_el1, &custom);
        
    } else if (current_el == 2) {
        vcore_emulte_el2(context, vcore, elr_el1, &custom);
    }
    else {
        printf("Invalid level in handle_pc_in_exception_table\n");
        return VMM_ABORT_REQUESTED;
    }
    
    if (emulation_action == EMULATION_ERET) {
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, elr_el1+4);
        hv_vcpu_set_reg(vcpu, HV_REG_PC, INJECTION_VBAR_ADDRESS);
        vcore->finish_action = EMULATION_NONE;
    }
    else if (emulation_action == EMULATION_CUSTOM) {
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, elr_el1+4);
        hv_vcpu_set_reg(vcpu, HV_REG_PC, custom);
        vcore->finish_action = EMULATION_NONE;
    }
    else if (emulation_action == EMULATION_POST_DONE) {
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_FAR_EL1, elr_el1+4);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, custom);
        hv_vcpu_set_reg(vcpu, HV_REG_PC, INJECTION_VBAR_ADDRESS);
        vcore->finish_action = EMULATION_NONE;
    }
    else if (emulation_action == EMULATION_POST_HOST) {
        // return to normal path but just hit a harware breakpoint to execute the custom action
        vcore->emulation_breakpoint_for_post_done = elr_el1 + 4;
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR4_EL1, vcore->emulation_breakpoint_for_post_done);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR4_EL1, BPCR_EXEC_EL1_0);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, elr_el1 + 4);
        hv_vcpu_set_reg(vcpu, HV_REG_PC, INJECTION_VBAR_ADDRESS);
    }
    // continue single stepping if necessary
    if (vcore->is_single_stepping)
        vcore_enable_single_step(vcore);
    
    action = VMM_CONTINUE;
    
    return action;
    
}

/* ============================
 Emulation code injected in the VM
 objdump -d hvftool -j emulation
 
 0000000100138000 <_eumlation_execption_table_code_start>:
 100138000: 20 00 20 d4     brk    #0x1

 0000000100138004 <_eumlation_execption_table_code>:
 100138004: e0 03 9f d6     eret
 100138008: e0 03 9f d6     eret
 10013800c: 20 00 20 d4     brk    #0x1
 100138010: 20 00 20 d4     brk    #0x1

 0000000100138014 <_eumlation_execption_table_code_end>:
 100138014: 20 00 20 d4     brk    #0x1

 */


__attribute__((naked)) __attribute__ ((section ("text, emulation"))) __attribute__ ((used))
void eumlation_execption_table_code_start(void)
{
}

__attribute__((naked)) __attribute__ ((section ("text, emulation")))  __attribute__ ((used))
void eumlation_execption_table_code(void)
{
    //+0
    __asm volatile ("eret" ::: "memory");

#define __EMULATION_TLBI  1
    //__asm volatile ("tlbi alle1" ::: "memory");
    __asm volatile ("eret" ::: "memory");
    
#define __EMULATION_BRK  2
    __asm volatile ("hvc #1" ::: "memory");

}
__attribute__((naked)) __attribute__ ((section ("text,emulation"))) __attribute__ ((used))
void eumlation_execption_table_code_end(void)
{
}


gva_t EMULATION_TLBI_INDEX = __EMULATION_TLBI;
gva_t EMULATION_BRK_INDEX = __EMULATION_BRK;

/* ============================
 */


void populate_emulation_code(void* address)
{
    int i;
    uint32_t* target = (uint32_t*)address;
    uint32_t* code = (uint32_t*)eumlation_execption_table_code;
    uint64_t s = (eumlation_execption_table_code_end - eumlation_execption_table_code_start - 4 - 4) /4;
    for( i = 0; i < (int)s; i++) {
        target[i] = code[i];
    }
}

void context_break_on_any_exception(vmm_context_t* context)
{
    int i;
    uint32_t* target = (uint32_t*)context->exception_table;
    uint32_t* code = (uint32_t*)eumlation_execption_table_code;
    for( i = 0; i < 16*128; i++) {
        target[i] = code[EMULATION_BRK_INDEX];
    }
}


int vcore_run(vmm_context_t* context, vcore_t* vcore)
{
    vmm_action_t action = VMM_CONTINUE;
    
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    
    hv_vcpu_set_vtimer_mask(vcpu, false);
    
	// Control VBAR_EL1 in guest to allow either emulation of exception levels or
    // normal exception level 1 only
    if (hvftool_config.enable_simulation == false) {
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, UNTRAPPED_VBAR_ADDRESS);
    }
    else {

        // inject exception table to emulate stuff
#if 0
        if (posix_memalign((void**)&context->exception_table, getpagesize(), getpagesize()) <0) return -1;
        if (hv_vm_map(context->exception_table, INJECTION_VBAR_ADDRESS, getpagesize(), HV_MEMORY_READ | HV_MEMORY_WRITE |HV_MEMORY_EXEC) != HV_SUCCESS) {
            printf("cannot install execption table :%s\n", strerror(errno));
        };
        vmm_add_memory_range(INJECTION_VBAR_ADDRESS, INJECTION_VBAR_ADDRESS+getpagesize(), context->exception_table, (vobject_t*)vcore);
#else
        context->exception_table = (uint32_t*)vmm_gpa_to_hva(vcore->context, INJECTION_VBAR_ADDRESS);
#endif
        populate_emulation_code(context->exception_table);
        
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, EMULATION_VBAR_ADDRESS);
    }

    //vcore->irq_enter = 0xffffffc008010800 + 0x280; // 0xffffffc008010800   0x0000000100005000
    //hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR3_EL1, vcore->irq_enter);
    //hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR3_EL1, BPCR_EXEC_EL1_0);
    //hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR3_EL1, 0xf00000200);

#if 0
    hvftool_config.ss_mode = SINGLE_SILENT;
    vcore_enable_single_step(vcore);
#endif
    
    do {
        
        gva_t pc;
        hv_return_t result;
        
        TRACE_BEGIN(DEBUG_EXIT) {
            hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
            printf("VM Enter@0x%llx...", pc);
        } TRACE_END
        
        /********************************
                    This is the VM entry
         */
                
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
        
        if (vcore->pending_irq) {
            // keep injecting this until the IRQ trigger, otherwise it is not seen!
            hv_vcpu_set_pending_interrupt(vcore->vcpu_handle, HV_INTERRUPT_TYPE_IRQ, true);
        }
        
        if ((result=hv_vcpu_run(vcpu)) != HV_SUCCESS) {
            action = VMM_ABORT_REQUESTED;
            printf("hv_vcpu_run returned an error %x\n", result);
            continue;
        }

        hv_vcpu_exit_t* cpu_exit = vcore->cpu_exit;

        gva_t elr_el1;
        uint64_t esr_el1;
        int exception_class;
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, &elr_el1);
        hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ESR_EL1, &esr_el1);
        exception_class = (cpu_exit->exception.syndrome >> 26 ) &0x3F;
        hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);

        vcore->vm_exits++;
        
        TRACE(DEBUG_EXIT, "Exit: reason>class=%d/%x @%llx/%llx pc=%llx elr_el1=%llx\n",
               cpu_exit->reason, exception_class,
               cpu_exit->exception.virtual_address , cpu_exit->exception.physical_address,
               pc, elr_el1
               );
        
        if (cpu_exit->reason == HV_EXIT_REASON_EXCEPTION) {
            
            uint64_t syndrome = cpu_exit->exception.syndrome;
            
            TRACE_BEGIN(DEBUG_EXCEPTION) {
                vcore_print_sys_reg(SYS_REG_ESR_EL2, syndrome, 4, FULL);
                vcore_print_sys_reg(HV_SYS_REG_ESR_EL1, esr_el1, 4, FULL);
                vcore_print_general_regs(vcore, 4);
            } TRACE_END
            
            
            if (exception_class == DATA_ABORT_EXCEPTION) {
                // isv just states bits 23-14 are valid or not
                if (cpu_exit->exception.physical_address >= hvftool_config.memory_map->mmio_start && cpu_exit->exception.physical_address < hvftool_config.memory_map->mmio_end) {
                    // we don't know if the MMIO zone exists but at least it is in the right range
                    /*
                     Untill I add watch points, this is a way to debug some MMIO situations
                     if (cpu_exit->exception.physical_address == 0x4000000) {
                        action = VMM_CONTINUE;
                    }
                     */
                    if (hvftool_config.ss_mode == SINGLE_BATCH || hvftool_config.ss_mode == SINGLE_INTERACTIVE_TO_BATCH ) {
                        vcore_disassemble_one(context, vcore, "D-Abort");
                        vcore_enable_single_step(vcore);
                    }
                    action = vmm_mmio_handler(context, vcore, cpu_exit);
                    vcore->vm_exits_mmio++;
                    
                }
                else {
                    printf("Accessing unkown memory @ %llx\n", cpu_exit->exception.physical_address);
                    vcore_disassemble_one(context, vcore, "D-Abort");
                    vcore_print_general_regs(vcore, 4);
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                }
            }
            
            
            else if (exception_class == INSTRUCTION_ABORT_EXCEPTION) {
                
                if (IS_IN_EMULATION_TABLE(pc)) {
                    action = handle_pc_in_exception_table(context, vcore, elr_el1);
                }
                else if (IS_IN_UNTRAPPED_TABLE(pc)) {
                    /* the target do not handle exceptions at this moment
                     * lets document what we know about the original reason
                     * of the trap.
                     */
                    printf("Instruction abort while VBAR_EL1 not defined!\n");
                    printf("Original instruction that caused the synchronous exception:\n");
                    vcore_disassemble_at(context, vcore, "<I-Abort", elr_el1);
                    vcore_print_general_regs(vcore, 4);
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                }
                else {
                    printf("Instruction abort @%llx\n", cpu_exit->exception.physical_address);
                    vcore_disassemble_one(context, vcore, "I-Abort");
                    printf("Caller:\n");
                    vcore_disassemble_caller(context, vcore, "I-Abort");
                    vcore_print_general_regs(vcore, 4);
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                }
            }
          
            
            else if (exception_class == HVC_EXCEPTION) {
                uint64_t vbar_el1;
                hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, &vbar_el1);
                uint16_t hvc_id = cpu_exit->exception.syndrome & 0xFFFF;
                if (hvc_id == 1 && vbar_el1 == 0xF00000000) {
                    vcore_disassemble_at(context, vcore, "HVC!", pc);
                }
                action = VMM_ABORT_REQUESTED;
            }
            
            
            else if (exception_class == MRS_EXCPETION) {
                // see section C6.2.228 MRS for key calculation...
                hv_reg_t reg = (syndrome >> 5) & 0x1F;
                int crm = (syndrome >> 1) & 0xF;
                int crn = (syndrome >> 10) & 0xF;
                int op0 = (syndrome >> 20) & 0x3;
                int op1 = (syndrome >> 14) & 0x7;
                int op2 = (syndrome >> 17) & 0x7;
                bool is_read = (syndrome & 1) != 0;
                uint32_t key = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
                if (is_read) {
                    action = vcore_invoke_getter(context, vcore, reg, key);
                    //if (action != VMM_CONTINUE)
                    {
                        //vcore_disassemble_one(context, vcore, "MRSExcep");
                        //printf("MRS_EXCEPTION: MRS x%d, %s (key= %x, %s)\n", reg, vcore_get_sys_reg_name(key), key, vcore_get_sys_reg_desc(key));
                        //action = vcore_interactive_debug(context, vcore, cpu_exit, action);
                    }
                }
                else {
                    action = vcore_invoke_setter(context, vcore, key, reg);
                    //if (action != VMM_CONTINUE)
                    {
                        uint64_t value=0;
                        hv_vcpu_get_reg(vcpu, reg, &value);
                        //vcore_disassemble_one(context, vcore, "MRSExcep");
                        //printf("MRS_EXCEPTION: MSR %s, x%d (=0x%llx)   - %x %s\n", vcore_get_sys_reg_name(key), reg, value, key, vcore_get_sys_reg_desc(key));
                        //action = vcore_interactive_debug(context, vcore, cpu_exit, action);
                    }
                }
                if (action == VMM_CONTINUE) {
                    hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
                    if (hvftool_config.ss_mode == SINGLE_BATCH || hvftool_config.ss_mode == SINGLE_INTERACTIVE_TO_BATCH ) {
                        vcore_enable_single_step(vcore);
                    }
                }
                else {
                    printf("MRS resulted in abort requested by getter or setter!\n");
                    vcore_print_general_regs(vcore, 4);
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                }
            }
            
            
            else if (exception_class == SMC_EXCEPTION) {
                action = vmm_smc_handler(context, vcore, cpu_exit);
                if (hvftool_config.ss_mode == SINGLE_BATCH || hvftool_config.ss_mode == SINGLE_INTERACTIVE_TO_BATCH ) {
                    vcore_disassemble_one(context, vcore, "SMC");
                    vcore_enable_single_step(vcore);
                }
            }
            
            
            else if (exception_class == BRK_EXCEPTION) {
                vcore_disassemble_one(context, vcore, "SW Break");
                vcore_print_general_regs(vcore, 4);
                action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                // pass the breakpoint
                hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
                action = VMM_CONTINUE;
            }
            
            
            else if (exception_class == BREAKPOINT_EXCEPTION) {
                if (pc == vcore->skip_until) {
                    // resume single stepping
                    vcore_enable_single_step(vcore);
                    //vcore_disassemble_one(context, vcore, "HW Break");
                    vcore->skip_until = POISON_ADDRESS;
                    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR2_EL1, 0);
                }
                else if (pc == vcore->irq_enter) {
                    // we made it here
                    vcore_disassemble_one(context, vcore, "HW Break");
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
                    vcore->pending_irq = false;
                    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR3_EL1, 0);
                }
                else if (pc == vcore->emulation_breakpoint_for_post_done) {
                    emulation_post_host_action emulation_action = (emulation_post_host_action)vcore->finish_emulation_at;
                    vcore->emulation_breakpoint_for_post_done = POISON_ADDRESS;
                    vcore->finish_emulation_at = 0;
                    vcore->finish_action = EMULATION_NONE;
                    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR4_EL1, 0);
                    emulation_action(context, vcore);
                }
                else {
                    vcore_disassemble_one(context, vcore, "HW Break");
                    action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
                    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR0_EL1, 0); // disable the breakpoint
                }
            }
            
            
            else if (exception_class == SOFTWARE_STEP_EXCEPTION) {
                
                uint32_t* instruction;
                int offset = hvftool_config.ss_mode == SINGLE_BATCH ? 4 : 0;
                uint64_t adjusted_pc = pc - offset;
                instruction = (uint32_t*)(vmm_gva_to_hva(vcore, adjusted_pc));
                
                if (hvftool_config.ss_mode != SINGLE_SILENT)
                    vcore_disassemble_one(context, vcore, "SingleStep");

                vcore->stepped_instructions++;
                
                if (instruction != (uint32_t*)POISON_ADDRESS && is_instruction_of_interest(*instruction)) {
                    //printf("Found instruction after %lld instructions\n", vcore->stepped_instructions);
                    uint64_t ttbr0_el3;
                    vcore_get_sys_reg_value(vcore, SYS_REG_TTBR0_EL3, &ttbr0_el3);
                    hv_vcpu_set_reg(vcore->vcpu_handle, 1, ttbr0_el3);
                    hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
                    action = VMM_CONTINUE;
                    vcore_enable_single_step(vcore);
                }
                else
                if (instruction != (uint32_t*)POISON_ADDRESS && is_load_exclusive(instruction)) {
                    // Look for a cbnz that points back to this instruction
                    if ( hvftool_config.ss_mode != SINGLE_SILENT)
                        printf("<Exclusive> mode, disabling singlestep until end of critical section\n");
                        hva_t matching_cbnz = find_matching_cbnz(instruction);
                        if (matching_cbnz != (hva_t)INVALID_ADDRESS) {
                            // lets skip execution until this cbnz
                            vcore->exclusive_sections++;
                            vcore_disable_single_step(vcore);
                            vcore->skip_until = pc + (matching_cbnz - (hva_t)instruction);
                            hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBVR2_EL1, (uint64_t)vcore->skip_until);
                            hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_DBGBCR2_EL1, BPCR_EXEC_EL1_0);
                            gva_t current = pc +4;
                            int i=1;
                            vcore->skipped_instructions += (vcore->skip_until - pc) / sizeof(uint32_t);
                            while(current != vcore->skip_until) {
                                char* skipped;
                                char* dis = loader_disassemble_at(vcore, current, &skipped);
                                if ( hvftool_config.ss_mode != SINGLE_SILENT)
                                    printf("%-14s@PC=0x%012llx   %012x   %-36s ; %s\n",
                                           current != vcore->skip_until-4 ? "   |" : "</Exclusive>",
                                           current, instruction[i++], dis, skipped
                                           );
                                current += 4;
                                free(skipped);
                            }
                            action = VMM_CONTINUE;
                        }
                    else {
                        printf("Could not find end of exclusive crtiical area");
                        action = VMM_ABORT_REQUESTED;
                    }
                }
                else {
                    vcore_enable_single_step(vcore);
                    if ( hvftool_config.ss_mode == SINGLE_INTERACTIVE) {
                        action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
                    }
                }
            }

            
            else if (exception_class == WF_EXCEPTION) {
                // reach WFI WFE or something
                if (!vcore->pending_irq) {
                    uint64_t end;
                    uint64_t now_host = mach_absolute_time() - vcore->vtimer_offset;
                    hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_CNTV_CVAL_EL0, &end);
                    uint64_t ns_sleep = ((__int128_t)(end - now_host)) * 1000000000ULL / vcore->cntfrq_hz;
                    ns_sleep = ns_sleep * 9 / 10; // gets 90% so that we will be busy looping for the vtimer to fire as ontime as possible
                    //printf("CNTP_CVAL_EL0=%lld, sleep ns = %lld\n", end, ns_sleep);
                    // if we have to sleep less than 0.5ms just busy wait
                    if (ns_sleep > 2000000) {
                        struct timespec ts;
                        //clock_gettime(CLOCK_REALTIME, &ts);
                        ts.tv_sec = 0;
                        ts.tv_nsec = ns_sleep;
                        if (ts.tv_nsec > 100000000) ts.tv_nsec = 100000000; // make sure we don't go over POSIX max value
                        //struct timespec in;
                        //clock_gettime(CLOCK_REALTIME, &in);
                        //int res = pthread_cond_timedwait(&vcore->wfi_cond, &vcore->wfi_mutex, &ts);
                        //int res = pselect(0, 0, 0, 0, &ts, &vcore->wfi_mask);
                        //struct timespec out;
                        //clock_gettime(CLOCK_REALTIME, &out);

                        //printf("res=%d, sleep=%ld\n", res, (out.tv_sec - in.tv_sec)*1000000000+ out.tv_nsec - in.tv_nsec);
                    }
                }
                hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
                action = VMM_CONTINUE;
                //vcore_disassemble_one(context, vcore, "WFI");
                //action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_CONTINUE);
            }
            
            
            else {
                printf("Unhandled Exception (%x) @PC=%p!\n", exception_class, (void*)pc);
                //vcore_disassemble_one(context, vcore, "Exception?");
                vcore_print_general_regs(vcore, 4);
                action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
            }
        }
        else if (cpu_exit->reason ==HV_EXIT_REASON_VTIMER_ACTIVATED) {
            gic_signal(PPI_TO_INTID(PPI_HYP_PHYS));
            vcore->pending_irq = true;
            action = VMM_CONTINUE;
        }
        else if (cpu_exit->reason == 0) {
            // probably a request to inject IRQ with hv_cpu_exit()
            action = VMM_CONTINUE;
        }
        else {
            printf("Unhandled reason=%x @PC=%p!\n", cpu_exit->reason, (void*)pc);
            vcore_disassemble_one(context, vcore, "Reason?");
            vcore_print_general_regs(vcore, 4);
            action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
        }
        
    } while (action == VMM_CONTINUE);

    if (action == VMM_ABORT_REQUESTED) return 1;
    else if (action == VMM_EXIT_REQUESTED) return ERR_SUCCESS;
    else return -1;
    
}
