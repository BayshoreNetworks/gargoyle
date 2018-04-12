/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * shared memory object for sharing memory regions between processes
 *
 * Copyright (c) 2016 - 2018, Bayshore Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
 * following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *****************************************************************************/
#include "shared_mem.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>

void abort_errno(const char *msg) {
#ifdef DEBUG
    printf("Error: '%s'. errno '%s'", msg, strerror(errno));
    abort();
#endif
}

/*
 * We don't want to use exceptions but some of us want RAII, so go ahead and
 * create a factory for these objects so that we can return NULL on failure
 * or the object itself, if successful.
 */
SharedMemRegion *SharedMemRegion::Create(const char *name, size_t initial_size) {
    SharedMemRegion *region = new SharedMemRegion(name, initial_size);
    if(!region)
        return NULL;

    if(region->Init() < 0) {
        delete region;
        return NULL;
    }

    return region;
}

SharedMemRegion::~SharedMemRegion() {
    if (BaseAddr())
        munmap(BaseAddr(), Size());
    if(IsCreator())
        shm_unlink(my_name);
    if (-1!=fd)
        close(fd);
}

int32_t SharedMemRegion::Init() {
    /*
     * The caller wants to know if we are the creator, so try to open and create
     * the file. If the file exists, then we are not the creator. If we fail for
     * some other reason, the value of is_created is undefined.
     */
    fd = shm_open(my_name, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    if(fd < 0 && errno == EEXIST) {
        is_created = false;
        fd = shm_open(my_name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    } else if(fd > 0) {
        is_created = true;
    }

    if(fd < 0) {
        abort_errno("shm_open failed");
        return -1;
    }

    /*
     * The region cannot be re-sized using this operation unless we are the creator
     *
     * Re-sizes may happen, however during other operations such as Write or Append
     */
    if(IsCreator()) {
        if(ftruncate(fd, Size()) < 0) {
            abort_errno("ftruncate failed");
            return -1;
        }
    }

    base_addr = mmap(NULL,
                     Size(),
                     PROT_READ|PROT_WRITE,
                     MAP_SHARED,
                     fd,
                     0);

    if(!base_addr) {
        abort_errno("mmap failed");
        return -1;
    }

    return 0;
}

int32_t SharedMemRegion::Resize(size_t new_size) {
    munmap(base_addr, my_size);
    my_size = new_size;

    if(ftruncate(fd, my_size) < 0) {
        abort_errno("ftruncate failed");
        return -1;
    }

    base_addr = mmap(NULL,
                     Size(),
                     PROT_READ|PROT_WRITE,
                     MAP_SHARED,
                     fd,
                     0);

    if(!base_addr) {
        abort_errno("mmap failed");
        return -1;
    }
    return 0;
}
