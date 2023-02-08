/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <stdlib.h>
#include <errno.h>

#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "vobjects.h"
#include "backends.h"
#include "loader.h"

#include "libfdt.h"

// https://developer.arm.com/documentation/ddi0183/g/programmers-model/summary-of-registers
#define REGISTER_SIZE 0x1000

typedef struct {
    vobject_t _;
    int intid;
    bool is_in_fifo;
    uint32_t speed;
    uint32_t control_register;
    bool is_rxirq_in_progress;
} pl011_vobject_t;

#define UART_PL01x_FR_TXFE              0x80
#define UART_PL01x_FR_RXFF              0x40
#define UART_PL01x_FR_TXFF              0x20
#define UART_PL01x_FR_RXFE              0x10
#define UART_PL01x_FR_BUSY              0x08


// adds a PL011 device with -device PL011,"console",pipe:/tmp/hvftool for instance

static vmm_action_t mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range);
static vobject_t* initialize(struct vmm_context* context, struct vobject* vobject);
static int post_process(struct vmm_context* context, struct vobject* vobject);
static void fdt_generator(struct vobject* vobj, void* fdt);



static parameter_t parameters[] = {
    {
        .name = "name",
        .type = PARAM_CSTRING,
        .description = "name of the object for reference",
        .is_mandatory = false,
    },
    {
        .name = "address",
        .type = PARAM_UINT64,
        .description = "begining of the MMIO register space",
        .is_mandatory = false,
        .u64_value = MMIO_ALLOCATE
    },
    {
        .name = "uartclk",
        .type = PARAM_CSTRING,
        .description = "reference of the uart clock",
        .is_mandatory = true,
    },
    {
        .name = "apb_pclk",
        .type = PARAM_CSTRING,
        .description = "reference of the chip clock",
        .is_mandatory = true,
    },
    {
        .name = "current-speed",
        .type = PARAM_UINT64,
        .description = "current speed",
        .is_mandatory = false,
        .u64_value = 115200
    },
    /*
     IRQs can be described from 3 perspectices
     - device driver perspecttive: all information shall be in the device
     - product maker: information of irq may be split between device (irq type - level or edge trigerred) and the GIC (to which pin it is being routed
     - virtual platform assembler: it makes sense to add a device and specify the routing information as part of the device specification or to add a "routing" complement to the device specification. when using LPI, the GIC ITS may need to be updated with eventid translation into intid
     */
    {
        .name = "irq",
        .type = PARAM_CSTRING,
        .description = "description of irq connection to GIC ([spi:<intid>|lpi:eventid]@<gic reference>)",
        .is_mandatory = true,
    }
};

static vobject_factory_t factory = {
    .key =              "PL011",
    .description =      "Arm PL011 UART",
    .fdt_default_name = "serial",
    .compatible =       ONE_FDT_STRING("arm,sbsa-uart"), // do not add "arm,primecell" as the device will be recognized as the amba device https://elixir.bootlin.com/linux/v5.19/source/drivers/tty/serial/amba-pl011.c#L2942
    .size =             sizeof(pl011_vobject_t),
    .initialize =       initialize,
    .mmio_handler=      mmio_handler,
    .generate_fdt=      fdt_generator,
    .parameters =       parameters,
    .parameter_count =  sizeof(parameters) / sizeof(parameter_t),
    .init_postprocess = post_process,
};




static vmm_action_t mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_write = (iss >> 6) & 1;
    //uint32_t sas = (iss >> 22) & 3;
    //uint32_t len = 1 << sas;
    //int dfsc = iss & 0x3F;
    //bool s1ptw = (iss >> 7) & 1;
    uint32_t srt = (iss >> 16) & 0x1f;
    //uint32_t cm = (iss >> 8) & 0x1;
    uint64_t val = 0;
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    gva_t pc;
    hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
    
    // just ignore any control register for now
    uint64_t offset = cpu_exit->exception.physical_address - range->start;

    stream_backend_o* stream = (stream_backend_o*)range->vobj->backend;
    pl011_vobject_t* pl011dev = (pl011_vobject_t*)range->vobj;
    
    switch(offset) {
        case 0:
            if (is_write) {
                hv_vcpu_get_reg(vcpu, srt, &val);
                uint8_t c = (uint8_t)val;
                TRACE(DEBUG_PL011, "PL011 write %c\n", (char)val);
                stream->write_u8(stream, &c, 1);
                //vcore_disassemble_one(context, vcore, "PL011Data");

            }
            else {
                uint8_t c;
                //TRACE(DEBUG_PL011, "PL011_READ\n");
                stream->read_u8(stream, &c, 1);
                val = c & 0xFF;
                hv_vcpu_set_reg(vcpu, srt, val);
            }
            break;
            
        case 0x18: // FLAG register
            if (!is_write) {
                uint64_t status = UART_PL01x_FR_TXFE | 5;                       // TX FIFO Empty: OK to send
                if (!stream->has_data(stream)) status |= UART_PL01x_FR_RXFE;    // RX FIFO Empty: no data ready
                hv_vcpu_set_reg(vcpu, srt, status);
                //vcore_disassemble_one(context, vcore, "PL011Flag");
            }
            else {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                TRACE(DEBUG_PL011, "PL011: write %08llx to 0x18 (Flag Register, LCR\n", val);
            }
            break;
            
        case 0x2C:
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                if (val & 1) {
                    // FIFO enable
                    TRACE(DEBUG_PL011, "PL011: FIFO enable\n");
                    pl011dev->is_in_fifo = true;
                }
                else {
                    // FIFO disable UART
                    pl011dev->is_in_fifo = false;
                    TRACE(DEBUG_PL011, "PL011: FIFO disable\n");
                }
            }
            else {
                TRACE(DEBUG_PL011, "PL011: 0x2C register read\n");
            }
            break;

        case 0x24: //  baud rate register
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                TRACE(DEBUG_PL011, "PL011: baud rate set\n");
            }
            else {
                TRACE(DEBUG_PL011, "PL011: baud rate read\n");
            }
            break;

        case 0x28: // fractional baud rate register
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                TRACE(DEBUG_PL011, "PL011: fractional baud set\n");
            }
            else {
                TRACE(DEBUG_PL011, "PL011: fractional baud rate read\n");
            }
            break;

        case 0x30:
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                TRACE(DEBUG_PL011, "PL011: UART Control Register write %0llx, UART %s, TX %s, RX %s\n",
                      val,
                      val & 1 ? "enabled" : "disabled",
                      val & (1<<8) ? "enabled" : "disabled",
                      val & (1<<9) ? "enabled" : "disabled"
                      );
                
                pl011dev->control_register = (uint32_t)val;
                if (val == 0x101) {
                    //vcore_disassemble_caller(context, vcore, "PL011");
                    //vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
                }

            }
            else {
                TRACE(DEBUG_PL011, "PL011: UART COntrol Register read\n");
                //vcore_disassemble_one(context, vcore, "PL011");
                hv_vcpu_set_reg(vcpu, srt, pl011dev->control_register);
                //vcore_disassemble_caller(context, vcore, "PL011");
                //vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
            }
            break;
            
        case 0x38: // Interrupt Mask register
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                    // the mask is such that a 1 value enables generation of IRQ
                TRACE(DEBUG_PL011, "PL011: Interrupt mask 0x%llx: RX_timeout=%s RX=%s TX=%s\n", val,
                      (val >> 6) & 1 ? "enabled": "disabled",
                      (val >> 4) & 1 ? "enabled": "disabled",
                      (val >> 5) & 1 ? "enabled": "disabled"
                      );
                //vcore_disassemble_caller(context, vcore, "PL011");
                //vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
            }
            else {
                TRACE(DEBUG_PL011, "PL011: Interrupt mask read\n");

            }
            break;

        case 0x3C: // Interrupt status register
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                    // the mask is such that a 1 value enables generation of IRQ
                TRACE(DEBUG_PL011, "PL011: Interrupt status write ignored (RO register)\n");
            }
            else {
                TRACE(DEBUG_PL011, "PL011: Interrupt status read\n");
                val = pl011dev->is_rxirq_in_progress ? ( 1 << 4) : 0;
                hv_vcpu_set_reg(vcpu, srt, val);
            }
            break;

        case 0x44: // Interrupt Clear Register
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                TRACE(DEBUG_PL011, "PL011: Interrupt Clear Register write\n");
                //TODO: proper handling of IRQs...
                pl011dev->is_rxirq_in_progress = false;
            }
            else {
                TRACE(DEBUG_PL011, "PL011: Interrupt Clear Register read\n");
            }
            break;

        case 0xfe0 ... 0xffc:
            // read AMBA ID
            if (!is_write) {
                static uint32_t pl011_amba_id[] = {
                    // matching https://elixir.bootlin.com/linux/v5.19/source/drivers/tty/serial/amba-pl011.c#L2940
                    0x11, 0x10, 0x34, 0x00,
                    // matching https://elixir.bootlin.com/linux/v5.19/source/include/linux/amba/bus.h#L22
                    0x0D, 0xF0, 0x05, 0xB1
                };
                int index = (int)((offset - 0xfe0) / sizeof(uint32_t));
                hv_vcpu_set_reg(vcpu, srt, pl011_amba_id[index]);
            }
            break;
            
        default:
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                //vcore_disassemble_one(context, vcore, "PL011");
                printf("PL011: ignore write x%d (=%llx) to %llx\n", srt, val, cpu_exit->exception.physical_address - range->start);
            }
            else {
                //vcore_disassemble_caller(context, vcore, "PL011");
                printf("PL011: ignore read access from %llx to register x%d\n", cpu_exit->exception.physical_address - range->start, srt);
            }
    }

mmio_continue:
    hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
    
    return VMM_CONTINUE;
}


static void stream_handler( struct vobject* vobject)
{
    pl011_vobject_t* pl011vobj = (pl011_vobject_t*)vobject;
    pl011vobj->is_rxirq_in_progress=true;
    vmm_inject_irq_for(vobject->context, vobject);
}


static void fdt_generator(struct vobject* vobj, void* fdt)
{
    pl011_vobject_t* pl011vobj = (pl011_vobject_t*)vobj;
    /*
        pl011@9000000 {
                clock-names = "uartclk\0apb_pclk";
                clocks = <0x8000 0x8000>;
                interrupts = <0x00 0x01 0x04>;
                reg = <0x00 0x9000000 0x00 0x1000>;
                compatible = "arm,pl011\0arm,primecell";
        };
    */
    gpa_t address = VOBJECT_CAST(pl011vobj)->mmio_range->start;


    uint64_t mmio_reg_prop[]    = {
        cpu_to_fdt64(address),
        cpu_to_fdt64(0x1000),
    };

    uint32_t interrupt_prop[]    = { cpu_to_fdt32(0), cpu_to_fdt32(1), cpu_to_fdt32(4) };

    parameter_t* param ;
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "apb_pclk");
    vobject_t* apb_pclk = vobjects_find_byname(param->cstring_value);
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "uartclk");
    vobject_t* uartclk = vobjects_find_byname(param->cstring_value);
    
    fdt32_t clocks[2];
    clocks[0]=cpu_to_fdt32(uartclk->phandle);
    clocks[1]=cpu_to_fdt32(apb_pclk->phandle);
    
    char node_name[32];
    sprintf(node_name, "pl011@%llx", address); // this is to avoid dtc complaining "node has a reg or ranges property, but no unit name"
    vobj->fdt_name = strdup(node_name);
    _FDT(fdt_begin_node(fdt, node_name));
    _FDT(fdt_property_fdtstring(fdt, "compatible", &(FACTORY_CAST(pl011vobj)->compatible)));
    fdt_string_t clock_names = TWO_FDT_STRING("uartclk", "apb_pclk");
    _FDT(fdt_property_fdtstring(fdt, "clock-names", &clock_names));
    _FDT(fdt_property(fdt, "clocks", clocks, 2 * sizeof(fdt32_t)));
    _FDT(fdt_property(fdt, "reg", mmio_reg_prop, sizeof(mmio_reg_prop)));
    _FDT(fdt_property_u32(fdt, "current-speed", pl011vobj->speed));
    _FDT(fdt_property(fdt, "interrupts", interrupt_prop, sizeof(interrupt_prop)));
    _FDT(fdt_end_node(fdt));

exit_return:; // this is for _FDT
    
}

static int post_process(struct vmm_context* context, struct vobject* vobj)
{
    if (vobj == NULL) return -EINVAL;
    parameter_t* param;
    pl011_vobject_t* pl011vobj = (pl011_vobject_t*)vobj;
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "irq");
    char type[64];
    uint64_t id;
    char gic_name[64];
    int n = sscanf(param->cstring_value, "%[^:]:%llx@%s", type, &id, gic_name);
    if (n != 3) {
        printf("Invalid IRQ spec: %s\n", param->cstring_value);
        return EXIT_FAILURE;
    }
    if (context->interrupt_parent == NULL) {
        printf("No GIC root has been specified\n");
        return -ENODEV;
    }
    vmm_register_interrupt(context, vobj, IRQ_SPI, 1, NULL, &pl011vobj->intid);
    return EXIT_SUCCESS;
}

/*
-vobj PL011,"console",0x09000000=pipe:/tmp/hvftool
-vobj PL011,"console",0x09000000=socket:tcp:1234
-vobj PL011,"console"=pipe:/tmp/hvftool // default address in the object type
*/

static vobject_t* initialize(struct vmm_context* context, vobject_t* vobj)
{
    // at this stage, parameters are parsed and checked, mandatory parameters are filled (may be with incorrect values though)
    // the backlend is operational
    // let's just finalize vobject instantiation
    
    if (vobj == NULL) return NULL;
    pl011_vobject_t* pl011vobj = (pl011_vobject_t*)vobj;

    parameter_t* param = parameter_lookup(vobj->parameters, vobj->parameters_count, "address");
    mmio_range_t* range = vobject_register_mmio(vobj, param->u64_value, REGISTER_SIZE);
    if (range == NULL) {
        vobject_free(vobj);
        return NULL;
    }
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "current-speed");
    pl011vobj->speed = (uint32_t)param->u64_value;
    
    VOBJECT_CAST(pl011vobj)->notify = stream_handler;
    
    pl011vobj->is_in_fifo = false;
    
    return (vobject_t*)pl011vobj;
}


int pl011_init(void)
{
    return vobjtype_register(&factory);
}
