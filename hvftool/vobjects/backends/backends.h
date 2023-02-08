/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef backends_h
#define backends_h

#include <unistd.h>
#include <pthread.h>

#include "parameters.h"
#include "hvftool.h"
#include "vmm.h"

// ----------------------------------------------
struct backend;
struct vobject;

typedef struct backend* (*backend_creator_f)(parameter_t* parameters, int parameter_count);
typedef void (*backend_terminator_f)(struct backend* backend);
typedef int(*backend_sync_f)(struct backend* backend);

// parent of all backends;

typedef struct backend_factory {
    const char*             key;
    backend_creator_f       instantiate;
    backend_terminator_f    terminate;
    backend_sync_f          sync;
    parameter_t*            parameters;                 //known parameters for the backend
    int                     parameter_count;
} backend_c;

typedef struct backend {
    // all objects points to class information
    backend_c*              factory;
    struct vobject*         vobj;                       // the object using the backend: needed to notify events
    parameter_t*            parameters;                 //actual parameter values for an instantiation
    int                     parameter_count;
} backend_o;

#define BACKEND_CLASS_CAST(x)   (((backend_o*)(x))->factory)
#define BACKEND_CAST(x)         ((backend_o*)(x))


// ----------------------------------------------
struct cpu_backend;
struct fdt_string;
struct cpu_node;

// abstract type, to be considered as an "interface" with multiple implementations

typedef  struct fdt_string* (*get_compatible_f)(struct cpu_backend* cpu_backend);

typedef struct cpu_backend {
    backend_o                   _;
    get_compatible_f                 get_compatible;
    
// probably schedule operations
} cpu_backend_o;


typedef struct hostcpu_backend {
    cpu_backend_o               cpu;
    struct cpu_node*            node;
} hostcpu_backend_o;


// ----------------------------------------------
struct memory_backend;


// abstract type, to be considered as an "interface" with multiple implementations

typedef  size_t (*memory_capacity_f)(struct memory_backend* memd);
typedef  void* (*block_get_basememory_f)(struct memory_backend* memd);

typedef struct memory_backend {
    backend_o                   _;
    block_get_basememory_f      get_base;
    memory_capacity_f           get_capacity;
} memory_backend_o;

typedef struct {
    memory_backend_o memory;
    void* base;
    size_t capacity;
} hostmem_backend_o;

typedef struct {
    memory_backend_o memory;
    void* base;
    size_t capacity;
    const char* path;
    int fd;
} mappedfile_backend_o;


// ----------------------------------------------
struct block_backend;

typedef uint64_t blockid_t;
// abstract type, to be considered as an "interface" with multiple implementations

typedef  int (*block_reader_f)(struct block_backend* blockd, int partition, blockid_t block, uint8_t* sectors_buffer, ssize_t count);
typedef  int (*block_writer_f)(struct block_backend* blockd, int partition, blockid_t block, uint8_t* sectors_buffer, ssize_t count);
typedef  int (*block_eraser_f)(struct block_backend* blockd, blockid_t block, int partition, ssize_t count);
typedef  size_t (*block_partition_capacity_f)(struct block_backend* blockd, int partition);
typedef  size_t (*block_capacity_f)(struct block_backend* blockd);
typedef  size_t (*block_size_f)(struct block_backend* blockd);
typedef  int (*block_partition_f)(struct block_backend* blockd);


typedef struct block_backend {
    backend_o                   _;
    block_reader_f              read;
    block_writer_f              write;
    block_eraser_f              erase;
    block_size_f                get_block_size;
    block_partition_capacity_f  get_partition_capacity;
    block_capacity_f            get_capacity;
    block_partition_f           get_partitions;
} block_backend_o;


// ----------------------------------------------
struct smc_backend;

typedef  vmm_action_t (*smc_f)(struct smc_backend* backend, uint64_t* registers);

typedef struct smc_backend {
    backend_o   parent;
    smc_f       smc;
} smc_backend_o;

// ----------------------------------------------
struct stream_backend;

// abstract type, to be considered as an "interface" with multiple implementations
// for instance pipe_backend, socket_backend, stdio_backend

typedef  int (*reader_ready_f)(struct stream_backend* stream);
typedef  size_t (*u8_reader_f)(struct stream_backend* stream, uint8_t* buffer, ssize_t count);
typedef  size_t (*u32_reader_f)(struct stream_backend* stream, uint32_t* buffer, ssize_t count);
typedef  size_t (*u64_reader_f)(struct stream_backend* stream, uint64_t* buffer, ssize_t count);
typedef  size_t (*u8_writer_f)(struct stream_backend* stream, uint8_t* buffer, ssize_t count);
typedef  size_t (*u32_writer_f)(struct stream_backend* stream, uint32_t* buffer, ssize_t count);
typedef  size_t (*u64_writer_f)(struct stream_backend* stream, uint64_t* buffer, ssize_t count);

typedef struct stream_backend {
    backend_o   _;
    reader_ready_f has_data;
    u8_reader_f read_u8;
    u32_reader_f read_u32;
    u64_reader_f read_u64;
    u8_writer_f write_u8;
    u32_writer_f write_u32;
    u64_writer_f write_u64;
} stream_backend_o;

typedef struct {
    stream_backend_o stream;
    const char* path;
    int out_fd;
    int in_fd;
    pthread_t receive_thread;
} pipe_backend_o;

// ----------------------------------------------

backend_c* backends_lookup(const char* key);
backend_o* backends_instantiate(char* backend_spec);

int backends_register(backend_c* e);
int backends_init(void);

#endif /* backends_h */
