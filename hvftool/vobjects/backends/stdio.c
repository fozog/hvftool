/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include "backends.h"


static backend_o* stdio_backend_instantiate(parameter_t* parameters, int paramater_count);

static backend_c stdio_backend_class = {
    "stdio",
    stdio_backend_instantiate
};

static backend_o* stdio_backend_instantiate( parameter_t* parameters, int paramater_count)
{
    backend_c* pipe_class = backends_lookup("pipe");
    if (pipe_class == NULL) return NULL;
    backend_o* backend = pipe_class->instantiate(parameters, paramater_count);
    if (backend == NULL) return NULL;
    BACKEND_CLASS_CAST(backend) = &stdio_backend_class;
    BACKEND_CAST(backend)->parameters = parameters;
    BACKEND_CAST(backend)->parameter_count = paramater_count;
    
    pipe_backend_o* pipe = (pipe_backend_o*)backend;
    pipe->in_fd = STDIN_FILENO;
    pipe->out_fd = STDOUT_FILENO;
    return backend;
}

int stdio_backend_init(void)
{
    return backends_register(&stdio_backend_class);
}
