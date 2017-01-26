/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Wrapper to sqlite as a shared lib
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
#ifndef __gargoylesqlitewrapper__H_
#define __gargoylesqlitewrapper__H_


#include <stdio.h>
#include <stdint.h>


#define DB_PATH "/db/port_scan_detect.db"
#define LOCAL_BUF_SZ 60
#define SMALL_DEST_BUF 2097152
#define MEDIUM_DEST_BUF 5242880
//#define MEDIUM_DEST_BUF 10485760
#define SQL_CMD_MAX 512

#define DETECTED_HOSTS_TABLE "detected_hosts"
#define HOSTS_TABLE "hosts_table"
#define HOSTS_PORTS_HITS_TABLE "hosts_ports_hits"


#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////
// detected_hosts table
int add_detected_host(int, int);
int get_detected_hosts_all_active_unprocessed(char *, size_t);
int modify_host_set_processed_ix(int);
int get_total_hit_count_one_host_by_ix(int);
int get_detected_hosts_all_active_unprocessed_ix(char *, size_t);
int get_detected_hosts_all_active_unprocessed_host_ix(char *, size_t);
int get_detected_hosts_row_ix_by_host_ix(size_t);
///////////////////////////////////////////////////////////////////////
// hosts_table table
int get_hosts_all(char *, size_t);
int get_host_by_ix(int, char *, size_t);
int get_host_all_by_ix(int, char *, size_t);
int add_host(const char *);
int get_host_ix(const char *);
///////////////////////////////////////////////////////////////////////
// hosts_ports_hits table
int get_unique_list_of_ports(char *, size_t);
int get_one_host_all_ports(int, char *, size_t);
int get_one_host_hit_count_all_ports(int);
int get_all_host_one_port_threshold(int, int, char *, size_t);
int get_host_port_hit(int, int);
int add_host_port_hit(int, int, int);
int update_host_port_hit(int, int, int);

#ifdef __cplusplus
}
#endif


#endif // __gargoylesqlitewrapper__H_

