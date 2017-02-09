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
#include "gargoyle_config_vals.h"
#include "config_variables.h"

// 9 hours
size_t LOCKOUT_TIME = 32400;
size_t IPTABLES_SUPPORTS_XLOCK;

char DB_LOCATION[SQL_CMD_MAX+1];

volatile sig_atomic_t stop;


void handle_signal (int signum) {
	stop = 1;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);
	exit(0);
}


void run_monitor() {
	
	syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "monitor process commencing at", (int) time(NULL));

	int iter_cnt;
	//int resp3;
	size_t resp3;
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

	//resp3 = get_detected_hosts_all_active_unprocessed(l_hosts3, dst_buf_sz);
	resp3 = get_detected_hosts_all(l_hosts3, dst_buf_sz, DB_LOCATION);
	
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
			//active = -1;
			//processed = -1;
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
				} 
				/*
				else if (iter_cnt == 3) {
					active = atoi(token2);
				} else if (iter_cnt == 4) {
					processed = atoi(token2);
				}
				*/
				iter_cnt++;
				token2 = strtok_r(NULL, tok2, &token2_save);
			}
			
			//if (row_ix >= 0 && active >= 0 && processed >= 0 && host_ix > 0) {
			if (row_ix >= 0 && host_ix > 0) {
	
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
					if (get_host_by_ix(host_ix, host_ip, dst_buf_sz1, DB_LOCATION) == 0) {
						//std::cout << "HOST IP: " << host_ip << std::endl;
			
						// we have the ip addr so get the rule ix from iptables
						//rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, host_ip);
						//std::cout << "RULE IX: " << rule_ix << std::endl;
						//if (rule_ix > 0 && strcmp(host_ip, "") != 0) {
						if (strcmp(host_ip, "") != 0) {
							
							// find the row ix for this host (in detected_hosts table)
							size_t row_ix = get_detected_hosts_row_ix_by_host_ix(host_ix, DB_LOCATION);
							if (row_ix > 0) {
							
								// remove DB row from when we blocked this host
								if (remove_detected_host(row_ix, DB_LOCATION) == 0) {
									
									size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, host_ip, IPTABLES_SUPPORTS_XLOCK);
									// delete rule from chain
									iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix, IPTABLES_SUPPORTS_XLOCK);

									tstamp = 0;
									tstamp = (int) time(NULL);
									syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"", "unblocked", VIOLATOR_SYSLOG, host_ip, TIMESTAMP_SYSLOG, tstamp);
								}
							}
						}
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	
	syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "monitor process finishing at", (int) time(NULL));
	
	free(l_hosts3);
	free(host_ip);
}


int main() {

	signal(SIGINT, handle_signal);
	
    if (geteuid() != 0) {
    	std::cerr << std::endl << "Root privileges are necessary for this to run ..." << std::endl << std::endl;
    	return 1;
    }

	/*
	 * Get location for the DB file
	 */
	const char *gargoyle_db_file;
	gargoyle_db_file = getenv("GARGOYLE_DB");
	if (gargoyle_db_file == NULL) {
		char cwd[SQL_CMD_MAX/2];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
	} else {
		snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", gargoyle_db_file);
	}
	
	int monitor_port;
	const char *port_config_file = ".gargoyle_internal_port_config";
	monitor_port = 0;
	
	ConfigVariables cv;
	if (cv.get_vals(port_config_file) == 0) {
		monitor_port = cv.get_gargoyle_pscand_monitor_udp_port();
	} else {
		return 1;
	}
	
	if (monitor_port <= 0)
		return 1;

	
	SingletonProcess singleton(monitor_port);
	if (!singleton()) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_pscand_monitor", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
		return 1;
	}
	
	// Get config data
	//const char *config_file = ".gargoyle_config";
	const char *config_file;
	config_file = getenv("GARGOYLE_CONFIG");
	if (config_file == NULL)
		config_file = ".gargoyle_config";
	
	ConfigVariables cvv;
	if (cvv.get_vals(config_file) == 0) {
		LOCKOUT_TIME = cvv.get_lockout_time();
	} else {
		return 1;
	}
	
	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();

	// processing loop
	while (!stop) {
		// every 12 hours by default
		sleep(43200);
		run_monitor();
	}
	return 0;
}
