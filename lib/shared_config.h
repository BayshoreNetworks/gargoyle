/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * configuration object for sharing IP addresses between processes
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
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdint.h>
#include <sstream>
#include <string>
using namespace std;

#include "shared_mem.h"

const int MAX_TRIES = 100;
const int TIMEOUT_MS = 100;

struct Header {
    pthread_mutex_t mutex;
    volatile size_t capacity;
    volatile int32_t next_ix;
};

class SharedIpConfig {

    string my_name;
    size_t local_capacity;
    SharedMemRegion *region;
    uint32_t step;
    Header *hdr;
    pthread_mutexattr_t attrmutex;
    sigset_t old_sigs;

    SharedIpConfig(string name, size_t starting_num)
        : my_name(name), local_capacity(starting_num), region(NULL), step(0), hdr(NULL) { }

    in_addr_t *ipVectorPtr() const {
        assert(region);
        return (in_addr_t *)((unsigned char *)region->BaseAddr() + sizeof(Header));
    }

    bool hasCapacity() {
        return hdr->next_ix < hdr->capacity;
    }

    void loadHeader() {
        hdr = (Header *)region->BaseAddr();
    }


    int32_t compareAndExpand();
    int32_t init();
    int32_t lock();
    int32_t unlock();
public:
    static SharedIpConfig *Create(string name, size_t size);
    ~SharedIpConfig() {
        /*
         * Do not delete the shared mutex, even if we are the creator. This
         * means that if the creator fails, other processes should be able to still
         * use the mutex. We assume there are no leaks and that the OS cleans up
         * any per-process information w.r.t. the mutex when the process exits.
         */
        delete region;
    }

    int32_t Add(string ip4_addr);
    int32_t Contains(string ip4_addr, bool *result);
    int32_t Remove(string ip4_addr);
    int64_t Size() const { return hdr->next_ix; }
    int32_t ToString(stringstream &ss);
};
