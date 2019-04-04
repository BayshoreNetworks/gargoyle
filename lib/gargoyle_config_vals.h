/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Config values for use across all gargoyle daemons/progs
 *
 * Copyright (c) 2017 - 2019, Bayshore Networks, Inc.
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
#ifndef __gargoyleconfig__H_
#define __gargoyleconfig__H_


#ifdef __cplusplus
extern "C" {
#endif



//const char *GARGOYLE_VERSION = "1.0";
#define GARGOYLE_PSCAND "Gargoyle_pscand"
#define GARGOYLE_VERSION "1.6.7"
#define GARGOYLE_DEBUG "GARGOYLE DEBUG -"
#define GARGOYLE_ERROR "GARGOYLE ERROR -"
#define GARGOYLE_DEFAULT_ROOT_PATH "/opt/gargoyle_pscand"
//const char *GARGOYLE_CHAIN_NAME = "GARGOYLE_Input_Chain";
#define GARGOYLE_CHAIN_NAME "GARGOYLE_Input_Chain"
#define IPTABLES_INPUT_CHAIN "INPUT"
//const char *IPTABLES = "iptables";
#define IPTABLES "iptables"
//const char *NFQUEUE = "NFQUEUE";
#define NFQUEUE "NFQUEUE"
#define NFQUEUE_NUM_LINE "NFQUEUE num 5"
#define NFLOG "NFLOG"
#define NFLOG_NUM_LINE "--nflog-group 5"

//static const char *VIOLATOR_SYSLOG = "violator";
#define BLOCKED_SYSLOG "block"
#define VIOLATOR_SYSLOG "violator"
#define DETECTION_TYPE_SYSLOG "detection_type"
#define TIMESTAMP_SYSLOG "timestamp"
#define SIGNAL_CAUGHT_SYSLOG "Signal caught"
#define PROG_TERM_SYSLOG "program terminating"
#define ALREADY_RUNNING "process already running. See"
#define INFO_SYSLOG "INFO:"
#define ACTION_SYSLOG "action"
#define REPORT_SYSLOG "report"
#define PORT_SYSLOG "port"
#define HITS_SYSLOG "hits"
#define UNBLOCKED_SYSLOG "unblock"
#define REMOVE_SYSLOG "remove"
#define FIRST_SEEN_SYSLOG "first_seen"
#define LAST_SEEN_SYSLOG "last_seen"
#define CONFIG_SYSLOG "config"
#define DB_FILE_SYSLOG "DB file:"
#define DOESNT_EXIST_SYSLOG "does not exist"
#define CANNOT_CONTINUE_SYSLOG "cannot continue"
#define ENFORCE_STATE_SYSLOG "enforce"


#define GARGOYLE_WHITELIST_SHM_NAME "/gargoyle_whitelist_shm"
#define GARGOYLE_WHITELIST_SHM_SZ 250
#define GARGOYLE_BLACKLIST_SHM_NAME "/gargoyle_blacklist_shm"
#define GARGOYLE_BLACKLIST_SHM_SZ 250
#define GARGOYLE_BLACK_IP_LIST_TABLE_NAME "/gargoyle_black_ip_table_shm"
#define GARGOYLE_BLACK_IP_LIST_TABLE_SIZE 250
#define GARGOYLE_DETECTED_HOSTS_TABLE_NAME "/gargoyle_detected_hosts_table_shm"
#define GARGOYLE_DETECTED_HOSTS_TABLE_SIZE 250
#define GARGOYLE_HOSTS_PORTS_HITS_TABLE_NAME "/gargoyle_hosts_ports_hits_table_shm"
#define GARGOYLE_HOSTS_PORTS_HITS_TABLE_SIZE 250
#define GARGOYLE_HOSTS_TABLE_NAME "/gargoyle_hosts_table_shm"
#define GARGOYLE_HOSTS_TABLE_SIZE 250
#define GARGOYLE_IGNORE_IP_LIST_TABLE_NAME "/gargoyle_ignore_ip_list_table_shm"
#define GARGOYLE_IGNORE_IP_LIST_TABLE_SIZE 250


#ifdef __cplusplus
}
#endif


#endif // __gargoyleconfig__H_
