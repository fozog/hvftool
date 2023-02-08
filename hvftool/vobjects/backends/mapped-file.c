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
#include <errno.h>
#include <string.h>

#include "backends.h"
#include "parameters.h"


static parameter_t parameters[] = {
    {
        .name = "path",
        .type = PARAM_CSTRING,
        .description = "File path",
        .is_mandatory = true,
        .u64_value = 0
    }
};

static void* mappedf_get_base(memory_backend_o* backend)
{
    mappedfile_backend_o* mappedf = (mappedfile_backend_o*)backend;
    return mappedf->base;
}

static size_t mappedf_get_capacity(memory_backend_o* backend)
{
    mappedfile_backend_o* mappedf = (mappedfile_backend_o*)backend;
    return mappedf->capacity;
}


// --------------------------------------
// backend creation and registration

static backend_o* mappedf_backend_instantiate(parameter_t* parameters, int parameter_count);
static void mappedf_backend_terminate(struct backend* backend);
static int mappedf_backend_sync(struct backend* backend);
static backend_c mappedf_backend_class = {
    "mapped-file",
    mappedf_backend_instantiate,
    mappedf_backend_terminate,
    mappedf_backend_sync,
    .parameters = parameters,
    .parameter_count = sizeof(parameters) / sizeof(parameter_t)
};

static int mappedf_backend_sync(struct backend* backend)
{
    mappedfile_backend_o* mappedf = (mappedfile_backend_o*) backend;
    msync(mappedf->base, mappedf->capacity, MS_SYNC);
    return ERR_SUCCESS;
}

static void mappedf_backend_terminate(struct backend* backend)
{
    mappedfile_backend_o* mappedf = (mappedfile_backend_o*) backend;
    munmap(mappedf->base, mappedf->capacity);
    close(mappedf->fd);
}

static mappedfile_backend_o* mappedf_alloc()
{
    mappedfile_backend_o* pipe = malloc(sizeof(pipe_backend_o));
    if (pipe == NULL) return NULL;
    memset(pipe, 0, sizeof(mappedfile_backend_o));
    BACKEND_CLASS_CAST(pipe) = &mappedf_backend_class;
    return pipe;
}

static backend_o* mappedf_backend_instantiate(parameter_t* parameters, int parameter_count)
{
    mappedfile_backend_o* mappedf = mappedf_alloc();
    if (mappedf == NULL) return NULL;
    BACKEND_CLASS_CAST(mappedf) = &mappedf_backend_class;
    BACKEND_CAST(mappedf)->parameters = parameters;
    BACKEND_CAST(mappedf)->parameter_count = parameter_count;
    
    parameter_t* param = parameter_lookup(BACKEND_CAST(mappedf)->parameters, BACKEND_CAST(mappedf)->parameter_count, "path");
    
    mappedf->path = strdup(param->ptr_value);
    free(param);
    
    if (mappedf->path != NULL) {
        
        mappedf->fd = open(mappedf->path, O_RDWR);
        if (mappedf->fd < 0) return NULL;
        struct stat file_stat;
        if (fstat(mappedf->fd, &file_stat) < 0) {
            printf("Error: cannot stat %s\n", mappedf->path);
            return NULL;
        };
	    file_stat.st_size += 65536-1;
	    file_stat.st_size &= ~(65536-1);
        mappedf->base = mmap(NULL, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, mappedf->fd, 0);
        if (mappedf->base == (void*)-1) {
            printf("MMAP: %s\n", strerror(errno));
            close(mappedf->fd);
            free(mappedf);
            return NULL;
        }
        
        mappedf->capacity = file_stat.st_size;
        mappedf->memory.get_base = mappedf_get_base;
        mappedf->memory.get_capacity = mappedf_get_capacity;
    }

    return (backend_o*)mappedf;
}

int mappedf_backend_init(void)
{
    return backends_register(&mappedf_backend_class);
}


