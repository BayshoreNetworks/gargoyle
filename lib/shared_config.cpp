/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * configuration object for sharing IP addresses between processes
 *
 * Copyright (c) 2016 - 2017, Bayshore Networks, Inc.
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
#include "shared_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>


string InAddrToString(in_addr_t a) {
    in_addr addr;
    addr.s_addr = a;
    return string(inet_ntoa(addr));
}

/*
 * The region we are observing may be resized periodically by other processes
 * If we see the capacity in the region changes, then initialize a new region with
 * the new size
 */
int32_t SharedIpConfig::compareAndExpand() {
    if(local_capacity < hdr->capacity) {

        //printf("Resizing: local capacity %ld to %ld\n", local_capacity, hdr->capacity);
        local_capacity = hdr->capacity;
        if(region->Resize(sizeof(Header) + local_capacity * sizeof(in_addr_t)) < 0) 
            return -1;
        loadHeader();
    } 
    
    return 0;
}

int32_t SharedIpConfig::lock() {
    int count = 0;
    int result;
    bool first = true;
    const sigset_t sigs = {SIGINT};

    /*
     * Note: we set a signal handler here to defer some signalling events until
     * after our global lock is released. Any signal, resulting in an exit event,
     * which occurs while this lock is held, will result in a deadlock for all
     * other processes until all references to the shared memory region are
     * released.
     */
    sigprocmask(SIG_BLOCK, &sigs, &old_sigs);

    /*
     * We may not be the creator, so wait for the mutex lock to be initialized
     * which signals for us to start working.
     *
     * This loop should run for no more than TIMEOUT_MS * MAX_TRIES milliseconds
     */
    do {
        result = pthread_mutex_trylock(&hdr->mutex);
        if(result == 0)
            break;

        if(count)
            usleep(TIMEOUT_MS * 1000);

        if(result != EBUSY)
            count++;

    } while(count < MAX_TRIES);

    /*
     * For some reason, we tried and failed to see an initialized lock,
     * so return an error.
     */
    if(count == MAX_TRIES) {
        return -1;
    }
    return 0;
}

int32_t SharedIpConfig::unlock() {
    pthread_mutex_unlock(&hdr->mutex);
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    return 0;
}

int32_t SharedIpConfig::init() {
    step = local_capacity;
    region = SharedMemRegion::Create(my_name.c_str(),
                                     local_capacity * sizeof(in_addr_t));
    if(!region)
        return -1;

    loadHeader();

    /*
     * We are the lucky creator, so go ahead and establish the shared mutex
     */
    if(region->IsCreator()) {
        /*
         * The region is new so update the shared capacity level for other processes
         * to observe
         */
        hdr->capacity = local_capacity;

        assert(!pthread_mutexattr_init(&attrmutex));
        assert(!pthread_mutexattr_setpshared(&attrmutex, PTHREAD_PROCESS_SHARED));
        assert(!pthread_mutex_init(&hdr->mutex, &attrmutex));
    }

    return 0;
}

/*
 * SharedIpConfig::Create
 *
 * Given a region name, creates a shared memory configuration. The 'size' parameter
 * specifies the initial capacity of IP addresses for the region. 'size' is also
 * used as the 'step' when resizing the memory region. For instance, if the
 * initial size is 100 IP elements and an expansion is needed, then the new size
 * would be 200 elements.
 *
 * N.B. for nearly all operations in this object, an inter-process lock 
 * is maintained. If a failure or some other signal (e.g., SIGINT) occurs while
 * one of these global locks is held and the process exits, then other processes
 * accessing the inter-process lock *will* deadlock. It is therefore the responsibility
 * of the caller to provide signal handling capabilities if required and delete
 * the reference to this object in order to release the lock.
 *
 */
SharedIpConfig *SharedIpConfig::Create(string name, size_t size) { 
    SharedIpConfig *config = new SharedIpConfig(name, size);
    if(!config)
        return NULL;

    if(config->init() < 0) {
        delete config;
        return NULL;
    }
    return config;
}

/*
 * SharedIpConfig::Add
 *
 * Adds IPv4 address in dotted quad notation to the set. If the element already
 * exists, then no changes are made. If the size of the current region is not
 * large enough, then it is resized. If a fatal error occurs, then returns -1,
 * otherwise return 0.
 */
int32_t SharedIpConfig::Add(string ip4_addr) {
    int32_t ret = 0;
    in_addr_t *vec_ptr;

    if(lock() < 0)
        return -1;

    if(compareAndExpand() < 0)
        goto error_exit;


    /*
     * Walk through the array. If we find the entry is already there, then exit.
     */
    vec_ptr = ipVectorPtr();
    for(int64_t i = 0; i < Size(); i++) {
        if(InAddrToString(vec_ptr[i]) == ip4_addr)
            goto exit;
    }

    /*
     * The entry isn't there, so we need to append it. First, check capacity.
     */
    if(!hasCapacity()) {
        //printf("Capacity not available. Resizing. Old: %ld New: %ld\n",
        //       hdr->capacity, hdr->capacity + step);
        hdr->capacity += step;
        local_capacity = hdr->capacity;

        // Do the resize
        if(region->Resize(sizeof(Header) + local_capacity * sizeof(in_addr_t)) < 0) 
            return -1;

        /*
         * The address of the header may have changed after the resize, so
         * reload the header reference
         */
        loadHeader();
        
        // Do we really need this? Didn't we just set it?
        local_capacity = hdr->capacity;
    }

    ipVectorPtr()[hdr->next_ix] = inet_addr(ip4_addr.c_str());
    if(ipVectorPtr()[hdr->next_ix] == -1)
        goto error_exit;

    hdr->next_ix++;

    goto exit;
error_exit:
    ret = -1;
exit:
    unlock();
    return ret;
}

/*int32_t SharedIpConfig::ElementAt(int64_t ix, string &ip) {
    int32_t ret = 0;
    if(lock() < 0)
        return -1;

    if(compareAndExpand() < 0)
        goto error_exit;

    if(ix >= Size())
        goto error_exit;

    in_addr addr;
    addr.s_addr = ipVectorPtr()[ix];
    ip = string(inet_ntoa(addr));
    goto exit;

error_exit:
    ret = -1;
exit:
    unlock();
    return ret;
}*/

/*
 * SharedIpConfig::Contains
 *
 * Given an IP4 address string, in dotted quad notation, determine if the
 * IP exists in the current config. Set 'result' accordingly. Returns -1 on
 * error and 0 on success
 */
int32_t SharedIpConfig::Contains(string ip4_addr, bool *result) {
    int32_t ret = 0;
    in_addr_t *vec_ptr = NULL;

    if(lock() < 0)
        return -1;

    if(compareAndExpand() < 0)
        goto error_exit;

    vec_ptr = ipVectorPtr();
    for(int64_t i = 0; i < Size(); i++) {
        if(InAddrToString(vec_ptr[i]) == ip4_addr) {
            *result = true;
            goto exit;
        }
    }
    *result = false;
    goto exit;
error_exit:
    ret = -1;
exit:
    unlock();
    return 0;
}

/*
 * SharedIpConfig::Remove
 *
 * Given IPv4 address in dotted quad notation, removes the address from the config.
 * Returns -1 if a fatal error occurs. Otherwise, returns 0.
 */
int32_t SharedIpConfig::Remove(string ip4_addr) {
    int32_t ret = 0;
    uint32_t tmp = 0;
    int64_t ix = -1;

    in_addr_t *vec_ptr = NULL;
    if(lock() < 0)
        return -1;

    if(compareAndExpand() < 0)
        goto error_exit;

    vec_ptr = ipVectorPtr();
    for(int64_t i = 0; i < Size(); i++) {
        if(InAddrToString(vec_ptr[i]) == ip4_addr) {
            ix = i;
            break;
        }
    }

    if(ix >= 0) {
        for(int64_t i = Size() - 1; i >= ix; i--) {
            uint32_t tmp2 = vec_ptr[i]; 
            vec_ptr[i] = tmp;
            tmp = tmp2;
        }
        hdr->next_ix--;
    }

    goto exit;
error_exit:
    ret = -1;
exit:
    unlock();
    return ret;
}

int32_t SharedIpConfig::ToString(stringstream &ss) {
    int32_t ret = 0;
    in_addr_t *vec_ptr = NULL;

    if(lock() < 0)
        return -1;
    
    vec_ptr = ipVectorPtr();
    const char *commaStr = "";
    for(int64_t i = 0; i < Size(); i++) {
        ss << commaStr;
        ss << InAddrToString(vec_ptr[i]);
        commaStr = ",";
    }

//    goto exit;
//error_exit:
//    ret = -1;
//exit:
    unlock();
    return ret;
}
