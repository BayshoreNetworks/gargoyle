/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * main cleanup daemon
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
#include <stdexcept>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>

#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "singleton.h"

// 9 hours
size_t LOCKOUT_TIME = 32400;
const char *MONITOR_CHAIN_NAME = "GARGOYLE_Input_Chain";
const char *MONITOR_VIOLATOR_SYSLOG = "violator";
const char *MONITOR_TIMESTAMP_SYSLOG = "timestamp";

volatile sig_atomic_t stop;


void handle_signal (int signum) {
	stop = 1;
	syslog(LOG_INFO | LOG_LOCAL6, "%s", "signal caught, program terminating");
	exit(0);
}


void run_monitor() {
	
	//syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "running monitor process at", (int) time(NULL));

	int iter_cnt;
	int resp3;
	int row_ix;
	int host_ix;
	int timestamp;
	int active;
	int processed;
	int now;
	size_t rule_ix;
	int tstamp;

	const char *tok1 = ">";
	char *token1;
	char *token1_save;
	const char *tok2 = ":";
	char *token2;
	char *token2_save;

	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts3 = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

	resp3 = get_detected_hosts_all_active_unprocessed(l_hosts3, dst_buf_sz);
	if (resp3 == 0) {
		/*
		 std::cout << std::endl << resp3 << std::endl;
		 std::cout << l_hosts3 << std::endl;
		 */ 
		token1 = strtok_r(l_hosts3, tok1, &token1_save);
		while (token1 != NULL) {
			
			iter_cnt = 0;
			timestamp = 0;
			host_ix = 0;
			active = -1;
			processed = -1;
			row_ix = -1;
			
			//std::cout << token1 << std::endl;
			token2 = strtok_r(token1, tok2, &token2_save);
			while (token2 != NULL) {
	
				//std::cout << token2 << " - " << iter_cnt << std::endl;
				if (iter_cnt == 0) {
					row_ix = atoi(token2);
				} else if (iter_cnt == 1) {
					host_ix = atoi(token2);
				} else if (iter_cnt == 2) {
					timestamp = atoi(token2);
				} else if (iter_cnt == 3) {
					active = atoi(token2);
				} else if (iter_cnt == 4) {
					processed = atoi(token2);
				}
	
				iter_cnt++;
				token2 = strtok_r(NULL, tok2, &token2_save);
			}
			
			if (row_ix >= 0 && active >= 0 && processed >= 0 && host_ix > 0) {
	
				//std::cout << row_ix << " - " << host_ix << " - " << timestamp << " - " << active << " - " << processed << std::endl;
				now = (int) time(NULL);
				*host_ip = 0;
				rule_ix = 0;
				/*
				get_host_by_ix(host_ix, host_ip);
				std::cout << host_ip << std::endl;
				 */
				// has it been in jail long enuf?
				if ((now - timestamp) >= LOCKOUT_TIME) {
		
					// we have the host ix so get the ip addr from the DB
					get_host_by_ix(host_ix, host_ip, dst_buf_sz1);
					//std::cout << "HOST IP: " << host_ip << std::endl;
		
					// we have the ip addr so get the rule ix from iptables
					rule_ix = iptables_find_rule_in_chain(MONITOR_CHAIN_NAME, host_ip);
					//std::cout << "RULE IX: " << rule_ix << std::endl;
					if (rule_ix > 0 && host_ip) {
		
						tstamp = 0;
						// delete rule from chain
						/*
						char str[15];
						snprintf (str, 15, "%d", rule_ix);
						iptables_delete_rule_from_chain(MONITOR_CHAIN_NAME, str);
						 */
						iptables_delete_rule_from_chain(MONITOR_CHAIN_NAME, rule_ix);
		
						tstamp = (int) time(NULL);			
						syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"", "unblocked", MONITOR_VIOLATOR_SYSLOG, host_ip, MONITOR_TIMESTAMP_SYSLOG, tstamp);
		
						/*
						 * update DB set active=0, processed=1
						 * 
						 * do this even if there is no rule in iptables
						 * because someone else could have deleted it or
						 * flushed the rules. if the time threshold is passed
						 * the DB table must get updated
						 */
						modify_host_set_processed_ix(row_ix);
					}
					//std::cout << std::endl;
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}
	free(l_hosts3);
	free(host_ip);
}


int main() {

	signal(SIGINT, handle_signal);

	SingletonProcess singleton(6699);
	if (!singleton()) {
		std::cerr << "process running already. See " << singleton.GetLockFileName() << std::endl;
		return 1;
	}

	while (!stop) {
		run_monitor();
		// every 12 hours
		sleep(43200);
	}

	return 0;
}
