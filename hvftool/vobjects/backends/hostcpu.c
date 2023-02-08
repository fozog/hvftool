/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


/*
    // indicate ANY would fit
    char cluster_type=' ';
    int core_id=-1;

    if (implementation_spec != NULL) {
        char cluster_spec[32];
        char cpu_spec[32];
        int n = sscanf(implementation_spec, "%[^,],%s", cluster_spec, cpu_spec);
        if (n < 1) {
            vobject_free(vobj);
            return NULL;
        }
        
        if (sscanf(cluster_spec, "cluster:%c", & cluster_type) != 1) {
            vobject_free(vobj);
            return NULL;
        }

        if (n==2) {
            if (sscanf(cpu_spec,"id:%d", &core_id) != 1) {
                vobject_free(vobj);
                return NULL;
            }
        }
    }
    
    cpu_node_t* cpu = cpu_find_bycluster(cluster_type, core_id);
    
    cpu->used = true;
    
    cpuvobj->mpidr = 0; // TODO: calculate this better
    cpuvobj->cpu = cpu;
    uint64_t mpidr = cpu->cluster->id << 16;
    mpidr |= cpu->id;
    cpuvobj->mpidr = mpidr;
    
    cpuvobj->index = cpu_factory.current_index++; // used to create cpu0, cpu1, cpu2...
    
    cpus[cpu_count++] = cpuvobj;
  */



#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "parameters.h"
#include "vobjects.h"
#include "backends.h"
#include "sysinfo.h"
#include "trace.h"

static parameter_t parameters[] = {
    {
        .name = "cluster",
        .type = PARAM_CSTRING,
        .description = "(P)erformance of (E)nergy efficient",
        .is_mandatory = false,
        .u64_value = 0
    }
};

// --------------------------------------
// backend creation and registration

static backend_o* hostcpu_backend_instantiate(parameter_t* parameters, int parameter_count);

static backend_c hostcpu_backend_class = {
    .key = "hostcpu",
    .instantiate = hostcpu_backend_instantiate,
    .parameters = parameters,
    .parameter_count = sizeof(parameters)/sizeof(parameter_t)
};

static fdt_string_t* get_compatible(cpu_backend_o* backend)
{
    hostcpu_backend_o* cpu = (hostcpu_backend_o*)backend;
    return cpu->node->compatible;
}

static backend_o* hostcpu_backend_instantiate( parameter_t* parameters, int parameters_count)
{
    hostcpu_backend_o* hostcpu = malloc(sizeof(hostcpu_backend_o));
    if (hostcpu == NULL) return NULL;
    BACKEND_CLASS_CAST(hostcpu) = &hostcpu_backend_class;
    BACKEND_CAST(hostcpu)->parameters = parameters;
    BACKEND_CAST(hostcpu)->parameter_count = parameters_count;


    char cluster_type=' ';
    parameter_t* param = parameter_lookup(parameters, parameters_count, "cluster");
    cluster_type = *((char*)param->ptr_value);
    free(param);
    
    cpu_node_t* cpu = cpu_find_bycluster(cluster_type, -1);
    cpu->used = true;
    hostcpu->node = cpu;
    
    hostcpu->cpu.get_compatible = get_compatible;
    
    return (backend_o*)hostcpu;
}

int hostcpu_backend_init(void)
{
    return backends_register(&hostcpu_backend_class);
}


