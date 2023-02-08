/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "parameters.h"
#include "vobjects.h"
#include "backends.h"

#include "trace.h"

static size_t hostmem_get_capacity(memory_backend_o* backend)
{
    hostmem_backend_o* hostmem = (hostmem_backend_o*)backend;
    return hostmem->capacity;
}

static void* hostmem_get_base(memory_backend_o* backend)
{
    hostmem_backend_o* hostmem = (hostmem_backend_o*)backend;
    return hostmem->base;
}

static parameter_t parameters[] = {
    {
        .name = "size",
        .type = PARAM_UINT64,
        .description = "size in MB",
        .is_mandatory = true,
        .u64_value = 0
    }
};

// --------------------------------------
// backend creation and registration

static backend_o* hostmem_backend_instantiate(parameter_t* parameters, int parameter_count);

static backend_c hostmem_backend_class = {
    .key = "hostmem",
    .instantiate = hostmem_backend_instantiate,
    .parameters = parameters,
    .parameter_count = sizeof(parameters)/sizeof(parameter_t)
};

static backend_o* hostmem_backend_instantiate( parameter_t* parameters, int parameters_count)
{
    hostmem_backend_o* hostmem = malloc(sizeof(hostmem_backend_o));
    if (hostmem == NULL) return NULL;
    BACKEND_CLASS_CAST(hostmem) = &hostmem_backend_class;
    BACKEND_CAST(hostmem)->parameters = parameters;
    BACKEND_CAST(hostmem)->parameter_count = parameters_count;

    size_t capacity;
    
    parameter_t* param = parameter_lookup(parameters, parameters_count, "size");
    capacity = param->u64_value;
    free(param);
    
    hostmem->capacity = capacity*MEGABYTE ;
    hostmem->capacity = (hostmem->capacity + getpagesize()-1) & ~(getpagesize() - 1);
    
	//mach_vm_allocate(mach_task_self(), &&hostmem->base,, hostmem->capacity, VM_FLAGS_ANYWHERE);
    int result = posix_memalign(&hostmem->base,  getpagesize(), hostmem->capacity);
    if (result != 0) {
        printf("hostmem: could not allocate %ldMB", capacity);
        return NULL;
    }
    
    TRACE(DEBUG_RAM, "Allocated %lluMB at %p\n", hostmem->capacity/MEGABYTE, hostmem->base);
    hostmem->memory.get_base = hostmem_get_base;
    hostmem->memory.get_capacity = hostmem_get_capacity;
    
    return (backend_o*)hostmem;
}

int hostmem_backend_init(void)
{
    return backends_register(&hostmem_backend_class);
}


