/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Shared Memory table for database
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
#ifndef SHARED_MEMORY_TABLE_H
#define SHARED_MEMORY_TABLE_H

#include "shared_mem.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <string>
#include <cstdint>
#include <cstring>
#include <iostream>

#define MAXIMUM_TRIES    100
#define TIMEOUT_MILISECONDS   100

template <typename TypeRecord>
class SharedMemoryTable{
    private:
        struct Header{
            pthread_mutex_t mutex;
            volatile size_t capacity;
            volatile int32_t next_ix;
        };
        std::string my_name;
        size_t local_capacity;
        SharedMemRegion *region;
        uint32_t step;
        Header *hdr;
        pthread_mutexattr_t attrmutex;
        sigset_t old_sigs;
        bool islocked;

        void loadHeader();
        bool hasCapacity();
    protected:
        size_t size() const;
        TypeRecord *begin() const;
        TypeRecord *end() const;
        bool isIn(TypeRecord *) const;
        int32_t compareAndExpand();
        int32_t lock();
        void unlock();
        int32_t init();
        int32_t pushBack(const TypeRecord &);
        void insertById(const TypeRecord &, const uint32_t);
        int32_t getRecordByPos(TypeRecord &, uint32_t);
        int32_t deleteRecordByPos(const uint32_t);
        void deleteAll();

    public:
        SharedMemoryTable(std::string name, size_t starting_num);
        virtual ~SharedMemoryTable();
        virtual int32_t INSERT(TypeRecord entry) = 0;
        virtual int32_t DELETE(const std::string &query) = 0;
        virtual int32_t SELECT(char *result, const std::string &query) = 0;
        virtual int32_t UPDATE(const TypeRecord &entry) = 0;
        virtual uint32_t getPositionByKey(const uint32_t) = 0;
        void TRUNCATE();
};

template <typename TypeRecord>
SharedMemoryTable<TypeRecord>::SharedMemoryTable(std::string name, size_t starting_num):
    my_name(name), local_capacity(starting_num), region(nullptr), step(0), hdr(nullptr), islocked(false){}

template <typename TypeRecord>
SharedMemoryTable<TypeRecord>::~SharedMemoryTable(){
    /*
     * If the process has the mutex locked, this should unlocked and permit
     * others process can access to shared memory
     */
    if(islocked){
        pthread_mutex_trylock(&hdr->mutex);
        /*
         * In this point the mutex will always be locked. is_looked is set to false after unlocking
         * so it can happen that the mutex is unlock and is_locked is still true. This is the reason
         * why pthread_mutex_trylock is called here
         */
        pthread_mutex_unlock(&hdr->mutex);
    }

    if(region != nullptr){
        delete region;
    }
}

template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::init() {
    int32_t initialization = 0;
    step = local_capacity;
    region = SharedMemRegion::Create(my_name.c_str(), local_capacity * sizeof(TypeRecord));

    if(region == nullptr){
        initialization = -1;
    }else{
        loadHeader();
        /*
         * We are the lucky creator, so go ahead and establish the shared mutex
         */
        if(region->IsCreator()){
            /*
             * The region is new so update the shared capacity level for other processes
             * to observe
             */
            hdr->next_ix = 0;
            hdr->capacity = local_capacity;
            assert(!pthread_mutexattr_init(&attrmutex));
            assert(!pthread_mutexattr_setpshared(&attrmutex, PTHREAD_PROCESS_SHARED));
            assert(!pthread_mutex_init(&hdr->mutex, &attrmutex));
        }
    }
    return initialization;
}

/*
 * The region we are observing may be resized periodically by other processes
 * If we see the capacity in the region changes, then initialize a new region with
 * the new size
 */
template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::compareAndExpand() {
    int32_t comparation = 0;
    if(local_capacity < hdr->capacity){
        local_capacity = hdr->capacity;
        if(region->Resize(sizeof(Header) + local_capacity * sizeof(TypeRecord)) < 0){
            comparation = -1;
        }
        loadHeader();
    }

    return comparation;
}

template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::lock(){
    islocked = true;
    int32_t loocked = 0;
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
     * This loop should run for no more than TIMEOUT_MILISECONDS * MAXIMUM_TRIES milliseconds
     */
    do {
        result = pthread_mutex_trylock(&hdr->mutex);
        if(result == 0){
            break;
        }
        if(count){
            usleep(TIMEOUT_MILISECONDS * 1000);
        }
        if(result == EBUSY){
            count++;
        }
    } while(count < MAXIMUM_TRIES);


    if(count == MAXIMUM_TRIES) {
        loocked = -1;
    }
    return loocked;
}

template <typename TypeRecord>
void SharedMemoryTable<TypeRecord>::unlock() {
    pthread_mutex_unlock(&hdr->mutex);
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    islocked = false;
}

template<typename TypeRecord>
bool SharedMemoryTable<TypeRecord>::hasCapacity(){
    return (hdr->next_ix) < (hdr->capacity);
}

template <typename TypeRecord>
void SharedMemoryTable<TypeRecord>::loadHeader(){
    hdr = reinterpret_cast<Header *>(region->BaseAddr());
}

template <typename TypeRecord>
size_t SharedMemoryTable<TypeRecord>::size() const{
    return hdr->next_ix;
}

template <typename TypeRecord>
void SharedMemoryTable<TypeRecord>::TRUNCATE(){
    if(lock() == 0){
        hdr->next_ix = 0;
        unlock();
    }
}

template <typename TypeRecord>
TypeRecord *SharedMemoryTable<TypeRecord>::begin() const{
    assert(region);
    return reinterpret_cast<TypeRecord *>((unsigned char *)region->BaseAddr() + sizeof(Header));
}

template <typename TypeRecord>
TypeRecord *SharedMemoryTable<TypeRecord>::end() const{
    assert(region);
    return reinterpret_cast<TypeRecord *>((unsigned char *)region->BaseAddr() + sizeof(Header) + size()*sizeof(TypeRecord));
}

template <typename TypeRecord>
bool SharedMemoryTable<TypeRecord>::isIn(TypeRecord *record) const{
    return (record >= begin()) && (record < end());
}

template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::pushBack(const TypeRecord &record){
    if(!hasCapacity()) {
        hdr->capacity += step;
        local_capacity = hdr->capacity;
        if(region->Resize(sizeof(Header) + local_capacity * sizeof(TypeRecord)) < 0){
            return -1;
        }else{
            loadHeader();
        }
    }
    memcpy(end(), &record, sizeof(TypeRecord));
    hdr->next_ix++;
    return 0;
}

template <typename TypeRecord>
void SharedMemoryTable<TypeRecord>::insertById(const TypeRecord &record, const uint32_t index){
    memcpy(begin() + index -1, &record, sizeof(TypeRecord));
}

template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::getRecordByPos(TypeRecord &record, uint32_t index){
    int32_t status = 0;
    if(index <= size()){
        memcpy(&record, begin() + index - 1, sizeof(TypeRecord));
    }else{
        status = -1;
    }
    return status;
}

template <typename TypeRecord>
int32_t SharedMemoryTable<TypeRecord>::deleteRecordByPos(uint32_t index){
    int32_t status = 0;
    if(index <= size()){
        memmove(begin() + index - 1, begin() + index, sizeof(TypeRecord)*(size() - index));
        hdr->next_ix--;
    }else{
        status = -1;
    }
    return status;
}

template <typename TypeRecord>
void SharedMemoryTable<TypeRecord>::deleteAll(){
    hdr->next_ix = 0;
}

#endif
