/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Wrapper to sqlite as a shared lib
 *
 * Copyright (c) 2016 - 2019, Bayshore Networks, Inc.
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
#include <pthread.h>

//#define DB_PATH "/db/port_scan_detect.db"
#define DB_PATH "/db/gargoyle_attack_detect.db"
#define LOCAL_BUF_SZ 60
#define SMALL_DEST_BUF 2097152
#define MEDIUM_DEST_BUF 5242880
#define SQL_CMD_MAX 512
#define SQL_FAIL_RETRY 5

#define DETECTED_HOSTS_TABLE "detected_hosts"
#define HOSTS_TABLE "hosts_table"
#define HOSTS_PORTS_HITS_TABLE "hosts_ports_hits"
#define IGNORE_IP_LIST_TABLE "ignore_ip_list"
#define BLACK_LIST_TABLE "black_ip_list"

#ifdef __cplusplus
extern "C" {
#endif

int set_sqlite_properties(int time);
void delete_sqlite_properties();

///////////////////////////////////////////////////////////////////////
// detected_hosts table
size_t sqlite_add_detected_host(size_t, size_t, const char *);
size_t sqlite_get_detected_hosts_all(char *, size_t, const char *);
size_t sqlite_get_detected_hosts_row_ix_by_host_ix(size_t, const char *);
size_t sqlite_remove_detected_host(size_t, const char *);
size_t sqlite_remove_detected_hosts_all(const char *);
int sqlite_is_host_detected(int, const char *);
///////////////////////////////////////////////////////////////////////
// hosts_table table
int sqlite_get_hosts_all(char *, size_t, const char *);
int sqlite_get_host_by_ix(int, char *, size_t, const char *);
int sqlite_get_host_all_by_ix(int, char *, size_t, const char *);
int sqlite_add_host(const char *, const char *);
int sqlite_add_host_all(uint32_t, const char *, time_t, time_t, const char *);
int sqlite_get_host_ix(const char *, const char *);
size_t sqlite_update_host_last_seen(size_t, const char *);
size_t sqlite_remove_host(size_t, const char *);
///////////////////////////////////////////////////////////////////////
// hosts_ports_hits table
int sqlite_get_unique_list_of_ports(char *, size_t, const char *);
int sqlite_get_one_host_all_ports(int, char *, size_t, const char *);
int sqlite_get_one_host_hit_count_all_ports(int, const char *);
int sqlite_get_total_hit_count_one_host_by_ix(int, const char *);
int sqlite_get_all_host_one_port_threshold(int, int, char *, size_t, const char *);
int sqlite_get_host_port_hit(int, int, const char *);
int sqlite_add_host_port_hit(int, int, int, const char *);
int sqlite_add_host_port_hit_all(int, int, int, int, const char *);
int sqlite_update_host_port_hit(int, int, int, const char *);
size_t sqlite_remove_host_ports_all(size_t, const char *);
size_t sqlite_get_unique_list_of_hosts_ix(char *, size_t, const char *);
///////////////////////////////////////////////////////////////////////
// ignore_ip_list table
size_t sqlite_add_host_to_ignore(size_t, size_t, const char *);
size_t sqlite_get_hosts_to_ignore_all(char *, size_t, const char *);
int sqlite_is_host_ignored(int, const char *);
int sqlite_remove_host_to_ignore(int, const char *);
///////////////////////////////////////////////////////////////////////
// black_ip_list table
size_t sqlite_add_host_to_blacklist(size_t, size_t, const char *);
size_t sqlite_get_hosts_blacklist_all(char *, size_t, const char *);
int sqlite_is_host_blacklisted(int, const char *);
int sqlite_remove_host_from_blacklist(int, const char *);
///////////////////////////////////////////////////////////////////////
int sqlite_get_all_ignore_or_black_ip_list(char *, size_t, const char *, const char *);
///////////////////////////////////////////////////////////////////////
void sqlite_reset_autoincrement(const char *, const char *);
size_t sqlite_remove_all(const char *db_loc, const char *table);
size_t sqlite_add_all_by_table(uint32_t, uint32_t, time_t, const char *, const char *);

#ifdef __cplusplus
}
#endif


#endif // __gargoylesqlitewrapper__H_
