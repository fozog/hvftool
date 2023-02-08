//
/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef bit_operations_h
#define bit_operations_h

static inline bool is_bit(uint64_t value, int bit) {
    return (value & (1 << bit)) !=0;
}

static inline int get_bits(uint64_t value, int start, int count) {
    uint64_t result = value >> start;
    uint64_t mask = (1ULL << count ) -1;
    result  &= mask;
    return (int)result;
}

// copy count bits at start1 bit from value1 into value2 at start2 and return the merged result
static inline uint64_t copy_bits(uint64_t value1, int start1, uint64_t value2, int start2, int count)
{
    uint64_t mask = (1ULL << count ) -1;
    uint64_t value2_zero_mask = ~(mask << start2);
    uint64_t result = value2 & value2_zero_mask;
    uint64_t value = (value1 >> start1 ) & mask;
    result |= value << start2;
    return result;
}


#endif /* bit_operations_h */
