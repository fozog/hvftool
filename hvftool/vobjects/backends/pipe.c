/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>

#include "backends.h"
#include "vobjects.h"

static backend_o* pipe_backend_create(parameter_t* parameters, int parameter_count);
static void pipe_backend_terminate(backend_o* backend);


static parameter_t parameters[] = {
    {
        .name = "path",
        .type = PARAM_CSTRING,
        .description = "path of the pipe",
        .is_mandatory = true,
        .u64_value = 0
    },
};

static backend_c pipe_backend_class = {
    "pipe",
    pipe_backend_create,
    pipe_backend_terminate,
    .parameters = parameters,
    .parameter_count = sizeof(parameters)/sizeof(parameter_t)
};


// poll and select do not work properly on MacOS on pipes!
// they return immediately regardless of data presence.
// so we need a hack...

uint8_t pipe_buffer[4096];
int head=0;
int tail=0;

static ssize_t max_read(void)
{
    if (head >= tail) {
        return sizeof(pipe_buffer) - head;
    }
    else
        return tail-head-1;
}

void* poll_pipe(void* data)
{
    pipe_backend_o* pipe = (pipe_backend_o*)data;
    ssize_t bytes_read = 0;
    do
    {
        bytes_read = read(pipe->in_fd, (char*)&pipe_buffer[head], max_read());
        if (bytes_read < 0) break;
        head += bytes_read;
        if (head >= sizeof(pipe_buffer)) head=0;

        if (pipe->stream._.vobj != NULL) {
            if (pipe->stream._.vobj->notify!=NULL) {
                pipe->stream._.vobj->notify(pipe->stream._.vobj);
            }
            else {
                printf("poll_pipe: got data while vobject does not have a notifier: ignoring\n");
                //TODO: consume the data
            }
        }
        else {
            printf("poll_pipe: got data while front end vobject not known: ignoring\n");
            //TODO: consume the data
        }
    } while( bytes_read >= 0);
    return NULL;
}

int pipe_ready(struct stream_backend* stream)
{
    return head != tail ? 1 : 0;
}




static size_t pipe_read(stream_backend_o* stream, uint8_t* buffer, ssize_t count)
{
    int n = 0;
    pipe_backend_o* pipe = (pipe_backend_o*)stream;
    if (pipe->stream.read_u8 != pipe_read) {
        return -EINVAL;
    }
    if (head != tail) {
        for(n=0; n < count; n++) {
            buffer[n] = pipe_buffer[tail++];
            if (tail >= sizeof(pipe_buffer)) tail=0;
        }
        return count;
    }
    return 0;
}

static size_t pipe_write(stream_backend_o* stream, uint8_t* buffer, ssize_t count)
{
    pipe_backend_o* pipe = (pipe_backend_o*)stream;
    if (pipe->stream.write_u8 != pipe_write) {
        return -EINVAL;
    }
    return write(pipe->out_fd, (char*)buffer, count);
}

static pipe_backend_o* pipe_alloc()
{
    pipe_backend_o* pipe = malloc(sizeof(pipe_backend_o));
    if (pipe == NULL) return NULL;
    memset(pipe, 0, sizeof(pipe_backend_o));
    BACKEND_CLASS_CAST(pipe) = &pipe_backend_class;
    return pipe;
}


static void pipe_backend_terminate(backend_o* backend)
{
    pipe_backend_o* pipe = (pipe_backend_o*)backend;
    close(pipe->in_fd);
    close(pipe->out_fd);
}


static backend_o* pipe_backend_create( parameter_t* parameters, int parameter_count)
{
    pipe_backend_o* pipe = pipe_alloc();
    if (pipe == NULL) return NULL;
    BACKEND_CLASS_CAST(pipe) = &pipe_backend_class;
    BACKEND_CAST(pipe)->parameters = parameters;
    BACKEND_CAST(pipe)->parameter_count = parameter_count;
    
    if (parameters != NULL) { // called with parameters == NULL from stdio backend
        parameter_t* param = parameter_lookup(BACKEND_CAST(pipe)->parameters, BACKEND_CAST(pipe)->parameter_count, "path");
        pipe->path = param->ptr_value;
    }
    
    if (pipe->path  != NULL) {

        size_t len = strlen(pipe->path);
        char* buffer = malloc(len+5);
        
        sprintf(buffer, "%s.out", pipe->path);
        mkfifo(buffer, 0600);
        pipe->out_fd = open(buffer, O_RDWR); // O_RDWR means: do not block at open but blocks at IO
        
        sprintf(buffer, "%s.in", pipe->path);
        mkfifo(buffer, 0600);
        pipe->in_fd = open(buffer, O_RDWR); // O_RDWR means: do not block at open but blocks at IO

        free(buffer);
        
    }

    pipe->stream.has_data = pipe_ready;
    pipe->stream.read_u8 = pipe_read;
    pipe->stream.write_u8 = pipe_write;
    
    pthread_attr_t  attr;
    int ret;
    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        //TODO: cleanup
        return NULL;
    }
    ret = pthread_create(&pipe->receive_thread, &attr, &poll_pipe, pipe);
    if (ret < 0)  {
        //TODO: cleanup
        return NULL;
    }
    return (backend_o*)pipe;
}


int pipe_backend_init(void)
{
    return backends_register(&pipe_backend_class);
}
