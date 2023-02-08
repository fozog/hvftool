/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <mach-o/arch.h>

#include <Hypervisor/Hypervisor.h>

#include "hvftool.h"
#include "vcore_info.h"
#include "trace.h"
#include "loader.h"
#include "vmm.h"
#include "vcore.h"
#include "vobjects.h"
#include "backends.h"
#include "sysinfo.h"

#include <libfdt.h>

vmm_context_t vmm_context = {0};

char* fin_vmm[] = {
    "Error",
    "PSCI Poweroff",
    "Aborted"
};

hvftool_config_t hvftool_config = {0};


// from the device specs accumulated by command line options
/*
-vobj RAM,"Main RAM",0x40000000=hostmem:256
-vobj CPU,"core0"=cluster:P,id:1
-vobj CPU,"core1"=cluster:E,id:2
-vobj PL011,"console",0x09000000=pipe:/tmp/hvftool
-vobj PL011,"console",0x09000000=socket:tcp:1234
-vobj PL011,"console"=pipe:/tmp/hvftool // default address in the object type
-vobj fixed-clock,"apb_clk"=clock-frequency:0x16e3600,clock-output-names:clk24mhz
-vobj CFI,"Code",0x0=mapped-file:/Users/ff/Documents/hvftool/u-boot.flash
-vobj CFI,"Data",0x4000000=mapped-file:/Users/ff/Documents/hvftool/u-boot.env
-vobj virtio-console,"console"=virtio-mmio
-vobj virtio-pci,pci1
-vobj virtio-serial,"console"=virtio-pci:pci1

-vobj PSCI,"PSCI"
-vobj PSCI,"PSCI"=psci-1.0
 
-vobj virtio-scmi,"SCMI"
-vobj SCMI,"SCMI"=scp:scmi-1.0

 -vobj tpmv2,"tpmv2"=process:/opt/softwaretpm/stpm -param1 -param2="yyy"
 
 // assuming we create the console as PL011
 -vobj PL011,"console",0x09000000=pipe:/tmp/hvftool
-routing "console".clock(apb_clk)-"apb_clk"
-routing "console".clock(uart_clk)-"apb_clk"

 -load optee#path=<filepath>,secure=true,address=0xe1000000,selfmove=0xF00000000000
 
*/



int fdt_add_spec(char* spec)
{
    hvftool_config.fdt_spec[hvftool_config.fdtspec_count++] = spec;
    return ERR_SUCCESS;
}

static int parse_options(int argc, const char * argv[]) {
    int result = 0;
    if (argc < 2) return -EINVAL;
    int i;
    // default values...
    hvftool_config.ss_mode = SINGLE_NONE;
    for (i = 1; i < argc -1 && result == 0; i++ ) {
        // alphabetically ordered

        if (strcmp(argv[i], "-debug-breakpoint") == 0) {
            if (i >= argc -1) return -EINVAL;
            if (argv[i+1][0]>='0' && argv[i+1][0]<='9') {
                if (sscanf(argv[i+1], "%llx", &hvftool_config.breakpoint) == 1) {
                    printf("Debug breakpoint set at %llx\n", hvftool_config.breakpoint );
                }
                else return -EINVAL;
            }
            else {
                char symbol[64];
                if (sscanf(argv[i+1], "%s", symbol) == 1) {
                    hvftool_config.breakpoint_symbol = strdup(symbol);
                    hvftool_config.breakpoint = 2;
                }
                else return -EINVAL;
            }
            i++;
        }
        else if (strcmp(argv[i], "-debug-single-step") == 0) {
            hvftool_config.ss_mode = SINGLE_BATCH;
        }
        else if (strcmp(argv[i], "-dump-reset-sysregs") == 0) {
            if (i >= argc -1) return -EINVAL;
            const char* detail = argv[i+1];
            if (strcmp(detail, "long") == 0) {
                hvftool_config.reset_sysregs_detail = LONG;
            }
            else if (strcmp(detail, "detailed") == 0) {
                hvftool_config.reset_sysregs_detail = DETAILED;
            }
            else if (strcmp(detail, "full") == 0) {
                hvftool_config.reset_sysregs_detail = FULL;
            }
            hvftool_config.reset_sysregs_detail |= NONZERO;
            hvftool_config.dump_reset_sysregs = true;
            i++;
        }
        else if (strcmp(argv[i], "-dump-fdt") == 0) {
            if (i >= argc -1) return -EINVAL;
            const char* path = argv[i+1];
            hvftool_config.fdt_path = path;
        }
        else if (strcmp(argv[i], "-enable-simulation") == 0) {
            hvftool_config.enable_simulation = true;
            i++;
        }
        else if (strcmp(argv[i], "-extra-symbols") == 0) {
            if (i >= argc -1) return -EINVAL;
            char path[256];
            if (sscanf(argv[i+1], "%s", path) != 1) return -EINVAL;
            hvftool_config.extra_symbols = strdup(path);
            i++;
        }
        else if (strcmp(argv[i], "-fdt") == 0) {
            if (i >= argc -1) return -EINVAL;
            fdt_add_spec((char*)argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "-memory-layout") == 0) {
            char name[17];
            if (i >= argc -1) return -EINVAL;
            if( sscanf(argv[i+1], "%16s", name) != 1) return -EINVAL;
            if (vmm_set_memory_map(name) < 0) return -EINVAL;
            i++;
        }
        else if (strcmp(argv[i], "-load") == 0) {
            if (i >= argc -1) return -EINVAL;
            const char* path = argv[i+1];
            loader_add_spec((char*)path);
            i++;
        }
        else if (strcmp(argv[i], "-reset-address") == 0) {
            if (i >= argc -1) return -EINVAL;
            result = sscanf(argv[i+1], "%llx", &hvftool_config.effective_reset_address) == 1  ? 0 : -EINVAL;
            i++;
        }
        else if (strcmp(argv[i], "-self-move") == 0) {
            // ROM programs tend to move themselves to another location
            // for U-Boot, an easy way to know this location for the particular memory configuration:
            // change the following debug into a printf
            // https://elixir.bootlin.com/u-boot/latest/source/common/board_r.c#L287
            if (i >= argc -1) return -EINVAL;
            result = sscanf(argv[i+1], "%llx", &hvftool_config.self_move) == 1 ? 0 : -EINVAL;
            i++;
        }
        else if (strcmp(argv[i], "-trace-bitmap") == 0) {
            if (i >= argc -1) return -EINVAL;
            result = sscanf(argv[i+1], "%llx", &hvftool_config.trace_bitmap) == 1 ? 0 : -EINVAL;
            i++;
        }
        else if (strcmp(argv[i], "-vobj") == 0) {
            if (i >= argc -1) return -EINVAL;
            const char* vobj_spec = argv[i+1];
            vobjects_add_spec(vobj_spec);
            if (result < 0) return result;
            i++;
        }
    }
    if (result < 0) return result;
    // check if there is a payload
    if (i < argc) {
        hvftool_config.program_path = argv[argc - 1];
    }

    return result;
}



void dump_fdt(void* fdt, const char* path)
{
    int fd;
    size_t count;

    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (fd < 0)
        printf("Failed to write dtb to %s\n", path);
    
    count = write(fd, fdt,fdt_totalsize(fdt));
    if (count < 0)
        printf("Failed to dump dtb\n");

   TRACE(DEBUG_FDT, "Wrote %ld bytes to dtb %s\n", count, path);
    
    close(fd);

}

void fdt_patch(void* fdt)
{
#if 1
    _FDT(fdt_begin_node(fdt, "chosen"));
    vobject_t* console = vobjects_find_byname("stdout-path");
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), "/%s", console->fdt_name);
    _FDT(fdt_property_string(fdt, "stdout-path", buffer));
    snprintf(buffer, sizeof(buffer), "earlycon=pl011,0x%llx,115200 console=ttyAMA0 root=/dev/ram0 rw loglevel=10", console->mmio_range->start);
    _FDT(fdt_property_string(fdt, "bootargs", buffer)); //earlycon=pl011,0x9000000,115200
    _FDT(fdt_property_u64(fdt, "linux,initrd-start", 0x50000000));
    _FDT(fdt_property_u64(fdt, "linux,initrd-end", 0x50000000 + 8388608));
    _FDT(fdt_end_node(fdt));
#else
    int i;
    for(i = 0; i < hvftool_config.fdtspec_count; i++) {
        char node_path[128];
        char property_spec[128];
        sscanf(hvftool_config.fdt_spec[i], "%128[^:]:%128s", node_path, property_spec);
        char property_name[64];
        char property_value[64];
        sscanf(property_spec, "%64[^=]=%64s", property_name, property_value);
        //TODO lets be more flexible...
        int nodeoffset;
        if ((nodeoffset=fdt_path_offset(fdt, node_path)) < 0) {
            _FDT(fdt_begin_node(fdt, node_path));
            _FDT(fdt_property_string(fdt, property_name, property_value));
            _FDT(fdt_end_node(fdt));
        }
        else {
            _FDT(fdt_setprop(fdt, nodeoffset, property_name, property_value, (int)strlen(property_value)));
        }
    }
#endif
exit_return:;
}

void* generate_fdt(vmm_context_t* context)
{
    hvftool_config.fdt = malloc(128*KILOBYTE);
    void* fdt = hvftool_config.fdt;
        //_FDT is defined just above
    _FDT(fdt_create(fdt, 128*KILOBYTE));
    _FDT(fdt_finish_reservemap(fdt));
    
    // <Begin FDT Node />
    _FDT(fdt_begin_node(fdt, ""));
    _FDT(fdt_property_cell(fdt, "interrupt-parent", context->interrupt_parent->phandle)); //this needs to be on top otherwise Linux does not find it when looking the value from childs
    
    _FDT(fdt_property_string(fdt, "compatible", "linux,dummy-virt"));
    _FDT(fdt_property_cell(fdt, "#address-cells", 0x2));
    _FDT(fdt_property_cell(fdt, "#size-cells", 0x2));
   
    
    vobjects_populate_fdt(fdt);
    
    fdt_patch(fdt);
    
    // </Begin FDT Node />
    _FDT(fdt_end_node(fdt));

    _FDT(fdt_finish(fdt));

exit_return:
    return fdt;
}

#define processor_read_sr(r) ({ \
        volatile unsigned long long __val; \
        __asm__ volatile("mrs %0, " #r "; isb": "=r" (__val)); \
        __val; \
        })

int main(int argc, const char * argv[]) {
    
    int result = 0;

    printf("HVF Tool sarts\n");
    
    hvftool_config.effective_reset_address = INVALID_PC;
    
    cpuinfo_prepare();
    
    vmm_set_memory_map("default");
    
    if (parse_options(argc, argv) < 0) {
        printf("Usage: hv-test [-mem <size_in_megabytes>] [-vobj <emulator>,<name>,<backend>]* [-debug-single-step] [-breakpoint_el1 <virtual_address>] [-breakpoint_el0 <virtual_address>] <program>\n");
        result = -EINVAL;
        goto exit_return;
    }
    
    //hvftool_config.trace_bitmap = DEBUG_RAM | DEBUG_PREPARE_VM;
    
    // --------
    // prepare vobjects and backend infrastructure
    
    result = vobjtypes_init();
    if (result < 0) {
        printf("Could not initialize emulators.\n");
        goto exit_return;
    }

    result = backends_init();
    if (result < 0) {
        printf("Could not initialize backends.\n");
        goto exit_return;
    }
    
    // --------
    // VM and its devices
    
    result = vmm_create(&vmm_context);
    if (result < 0) goto exit_return;
    
    
    vobjects_create_all(&vmm_context);

    void* fdt = generate_fdt(&vmm_context);
    
    void* vm_fdt = vmm_inject_fdt(&vmm_context, fdt);
    
    if (hvftool_config.fdt_path != NULL)
        dump_fdt(vm_fdt, hvftool_config.fdt_path);
    
    
    // --------
    // load payload into VM and calculate effective reset_address
    // this does not include ROM or flash as those have been added as devices previously
    /*
    if (hvftool_config.rom_path != NULL) {
        loader_load_rom(&vmm_context, hvftool_config.rom_path);
    }
    */
    // the following installs the executable file at the very end of allocated memory for the guest
    if (hvftool_config.program_path != NULL) {
        result = loader_load_program(&vmm_context, hvftool_config.program_path);
        if (result != 0) goto exit_destroy_vm;
        
        // the following parses the mach-o file and copies __TEXT and __DATA sections in the intended guest memory
        // we assume that byte 0 of allocated memory is byte 0 of the first section (__TEXT)
        result = loader_parse_macho_into_vm(&vmm_context);
        //if (result != 0) goto exit_destroy_vm;
        if (result < 0) result = loader_parse_coff_into_vm(&vmm_context);
        //if (result < 0) result = copy_bin_into_vm(&vmm_context); // need an argument for load address
    }
    
    loader_load_all();
    
    if (hvftool_config.extra_symbols != NULL) {
        loader_parse_symbols(&vmm_context, hvftool_config.extra_symbols);
    }

    static char* origin = "INVALID";
    if (hvftool_config.effective_reset_address == INVALID_PC) {
        if (vmm_context.entry != INVALID_PC) {
            origin = "payload";
            hvftool_config.effective_reset_address = vmm_context.entry;
        }
        else {
            origin = "memory map";
            hvftool_config.effective_reset_address = hvftool_config.memory_map->reset_address;
        }
    }
    else {
        origin = "command line";
    }
    
    
    TRACE(DEBUG_PREPARE_VM | DEBUG_PREPARE_PROGRAM, "Using entry point from %s: @%llx\n", origin, hvftool_config.effective_reset_address);


    // --------
    // VM cores
    
    // prepapre a core with all default values to run at EL1
    vcore_t* vcore;
    vmm_vcore_create(&vmm_context, &vcore);
    
    vcore_init(&vmm_context, vcore);
    
    vobjects_postprocess_all(&vmm_context);
    
    // make sure the characters are red 1 by 1, no buffering.
    // may require adaptation if done on a pipe...
    system("stty -icanon -echo");
    
    // --------
    // THE MAIN JOB

    result = vmm_run(&vmm_context);
    
    // --------
    // returns back to normal on the TTY

    system("stty icanon echo");
    
    printf("---------------\n");
    printf("VMM end: %s\n\n", fin_vmm[result + 1]);
    
exit_destroy_vm:
    //TODO a lot more to do...
    vobjects_terminate_all();
    hv_vm_destroy();
    
exit_return:
    //TODO: cleanup of everything...
    
    return result;
    
}
