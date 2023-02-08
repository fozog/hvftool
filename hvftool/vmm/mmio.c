/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdlib.h>
#include <errno.h>

#include "mmio.h"

#define MAX_RANGES  64

static mmio_range_t* ranges[MAX_RANGES];
static int range_count=0;
static gpa_t current_mmio = INVALID_ADDRESS;

mmio_range_t* mmio_lookup(gpa_t address) {
    int i;
    for (i = 0; i < range_count; i++ ) {
        if (address >= ranges[i]->start && address < ranges[i]->end) return ranges[i];
    }
    return NULL;
}

int mmio_add_range(mmio_range_t* range)
{
    if (range_count >= MAX_RANGES -1) return -ENODEV;
    ranges[range_count++] = range;
    return ERR_SUCCESS;
}

static gpa_t find_slot(size_t range_size)
{
    if (current_mmio == INVALID_ADDRESS) {
        current_mmio = hvftool_config.memory_map->mmio_top;
    }
    gpa_t result = current_mmio;
    
    uint64_t aligned_size = (range_size + 64 * KILOBYTE -1) & ~( 64 * KILOBYTE -1);
    
    current_mmio += aligned_size;
    
    return result;
}

void mmio_range_free(mmio_range_t* range)
{
    if (range == NULL) return;
    int i;
    for (i = 0; i < range_count; i++ ) {
        if (range == ranges[i]) {
            free(range);
            ranges[i]=NULL;
            range_count--;
        };
    }
}

mmio_range_t* mmio_assign_at(gpa_t address, size_t range_size)
{
    mmio_range_t* range = malloc(sizeof(mmio_range_t));
    if (range == NULL) return NULL;
    range->start = address == MMIO_ALLOCATE ? find_slot(range_size): address;
    uint64_t aligned_size = (range_size + 64 * KILOBYTE -1) & ~( 64 * KILOBYTE -1);
    range->end = range->start + aligned_size;
    if (mmio_add_range(range) < 0) {
        free(range);
        return NULL;
    }
    return range;
}

