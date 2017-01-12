/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * main analysis daemon
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
#include <algorithm>
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

//std::vector<std::string> IPTABLES_ENTRIES;
std::vector<int> IPTABLES_ENTRIES;
size_t PORT_SCAN_THRESHOLD = 15;
size_t SINGLE_IP_SCAN_THRESHOLD = 6;
size_t OVERALL_PORT_SCAN_THRESHOLD = 8;
// 8 hours
size_t LAST_SEEN_DELTA = 28800;
const char *ANALYSIS_CHAIN_NAME = "GARGOYLE_Input_Chain";
const char *ANALYSIS_VIOLATOR_SYSLOG = "violator";
const char *ANALYSIS_DETECTION_TYPE = "detection_type";
const char *ANALYSIS_TIMESTAMP_SYSLOG = "timestamp";

volatile sig_atomic_t stop;


void handle_signal (int signum) {
	stop = 1;
	syslog(LOG_INFO | LOG_LOCAL6, "%s", "signal caught, program terminating");
}


//bool exists_in_iptables_entries(std::string s) {
bool exists_in_iptables_entries(int s) {

	std::vector<int>::const_iterator iter;

	iter = std::find(IPTABLES_ENTRIES.begin(), IPTABLES_ENTRIES.end(), s);
	if (iter != IPTABLES_ENTRIES.end()) {
		//std::cout << *iter << " is on position " << (iter - IPTABLES_ENTRIES.begin() + 1);
		return true;
	} else {
		return false;
	}
}

//void add_to_iptables_entries(std::string s) {
void add_to_iptables_entries(int s) {
	if (exists_in_iptables_entries(s) == false)
		IPTABLES_ENTRIES.push_back(s);
}

void do_block_actions(const char *the_ip, int the_ix, int detection_type = 0) {

	if (the_ip and the_ix) {

		size_t ret;
		int tstamp;
		tstamp = (int) time(NULL);

		ret = iptables_add_drop_rule_to_chain(ANALYSIS_CHAIN_NAME, the_ip);

		syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\" %s=\"%d\"",
				"blocked", ANALYSIS_VIOLATOR_SYSLOG, the_ip, ANALYSIS_DETECTION_TYPE,
				detection_type, ANALYSIS_TIMESTAMP_SYSLOG, tstamp);

		// add to DB
		add_detected_host(the_ix, tstamp);
		// so that we dont have to deal with duplicate data
		add_to_iptables_entries(the_ix);
	}
}


/*
 * one port, too many hits from one host
 */
void query_for_single_port_hits_last_seen() {

	int ret;
	int row_ix;
	int host_ix;
	int port_num;
	int hit_count;
	int iter_cnt;
	int iter_cnt2;
	int now;

	int first_seen;
	int last_seen;

	const char *tok1 = ">";
	char *token1;
	char *token1_save;
	char *token2;
	char *token2_save;
	const char *tok2 = ":";
	char *token3;
	char *token3_save;
	char *token4;
	char *token4_save;

	//char list_of_ports[(size_t)SMALL_DEST_BUF];
	size_t list_ports_dst_sz = SMALL_DEST_BUF;
	char *list_of_ports = (char*) malloc(list_ports_dst_sz+1);
	ret = get_unique_list_of_ports(list_of_ports, list_ports_dst_sz);

	size_t list_hosts_dst_sz = SMALL_DEST_BUF;
	char *l_hosts = (char*) malloc(list_hosts_dst_sz+1);

	token1 = strtok_r(list_of_ports, tok1, &token1_save);
	while (token1 != NULL) {

		*l_hosts = 0;
		get_all_host_one_port_threshold(atoi(token1), PORT_SCAN_THRESHOLD, l_hosts, list_hosts_dst_sz);
		if (strlen(l_hosts) > 0) {
			/*
			 std::cout << std::endl << token1 << std::endl;
			 std::cout << l_hosts << std::endl << std::endl;
			 */
			//std::cout << "LHOSTS: " << l_hosts << std::endl << std::endl;
			token2 = strtok_r(l_hosts, tok1, &token2_save);
			while (token2 != NULL) {
				/*
				std::cout << "TOKEN2: " << token2 << " - " << iter_cnt
						<< std::endl;
				*/
				token3 = strtok_r(token2, tok2, &token3_save);
				iter_cnt = 0;
				while (token3 != NULL) {

					if (iter_cnt == 0) {
						row_ix = atoi(token3);
					} else if (iter_cnt == 1) {
						host_ix = atoi(token3);
					} else if (iter_cnt == 2) {
						port_num = atoi(token3);
					} else if (iter_cnt == 3) {
						hit_count = atoi(token3);
					}
					iter_cnt++;
					token3 = strtok_r(NULL, tok2, &token3_save);
				}
				/*
				std::cout << "ROW/HOST/PORT/CNT: " << row_ix << " - " << host_ix
						<< " - " << port_num << " - " << hit_count << std::endl;
				*/
				if (exists_in_iptables_entries(host_ix) == false) {

					size_t get_all_dst_sz = LOCAL_BUF_SZ;
					char *h_all = (char*) malloc(get_all_dst_sz+1);
					get_host_all_by_ix(host_ix, h_all, get_all_dst_sz);
					//std::cout << h_all << std::endl;

					char *host_ip = (char*) malloc(60);
					iter_cnt2 = 0;
					token4 = strtok_r(h_all, tok2, &token4_save);
					while (token4 != NULL) {

						if (iter_cnt2 == 0) {
						} else if (iter_cnt2 == 1) {
							//host_ip = atoi(token4);
							snprintf(host_ip, 60, "%s", token4);
						} else if (iter_cnt2 == 2) {
							first_seen = atoi(token4);
						} else if (iter_cnt2 == 3) {
							last_seen = atoi(token4);
						}

						iter_cnt2++;
						token4 = strtok_r(NULL, tok2, &token4_save);
					}

					//tmp_host_ix,host_ip,first_seen,last_seen = h_all.value.split(':')
					/*
					std::cout << host_ip << " - " << first_seen << " - "
							<< last_seen << std::endl << std::endl;
					*/
					
					now = (int) time(NULL);
					if ((now - last_seen) <= LAST_SEEN_DELTA) {
						/*
						 * !! ENFORCE
						 * if we are here then this host violated the
						 * acceptable number of port hits (for one port per host).
						 * did we see this host less than LAST_SEEN_DELTA hours ago?
						 * if so block this bitch
						 */
						do_block_actions(host_ip, host_ix, 7);
					}
					free(h_all);
					free(host_ip);
				}
				token2 = strtok_r(NULL, tok1, &token2_save);
			}
		}
		token1 = strtok_r(NULL, tok1, &token1_save);
	}
	free(list_of_ports);
	free(l_hosts);
}



void query_for_multiple_ports_hits_last_seen() {

	int ret;
	int row_ix;
	int host_ix;
	int first_seen;
	int last_seen;
	int iter_cnt;
	int now;
	int hit_cnt_resp;
	int l_count;
	
	const char *tok1 = ">";
	char *token1;
	char *token1_save;
	const char *tok2 = ":";
	char *token2;
	char *token2_save;
	
	size_t dst_buf_sz = MEDIUM_DEST_BUF;
	char *hosts_all_buf = (char*) malloc(dst_buf_sz+1);
	char *host_ip = (char*) malloc(60);
	
	ret = get_hosts_all(hosts_all_buf, dst_buf_sz);
	/*
	std::cout << hosts_all_buf << std::endl;
	std::cout << strlen(hosts_all_buf) << std::endl;
	*/
	
	if (ret == 0) {
		token1 = strtok_r(hosts_all_buf, tok1, &token1_save);
		while (token1 != NULL) {
			
			iter_cnt =0;
			token2 = strtok_r(token1, tok2, &token2_save);
			
			while (token2 != NULL) {
				
				if (iter_cnt == 0) {
					host_ix = atoi(token2);
				} else if (iter_cnt == 1) {
					snprintf(host_ip, 60, "%s", token2);
				} else if (iter_cnt == 2) {
					first_seen = atoi(token2);
				} else if (iter_cnt == 3) {
					last_seen = atoi(token2);
				}
				
				iter_cnt++;
				token2 = strtok_r(NULL, tok2, &token2_save);
			}
			/*
			std::cout << host_ix << " - " << host_ip << " - " << first_seen << " - "
					<< last_seen << std::endl << std::endl;
			*/
			if (exists_in_iptables_entries(host_ix) == false) {
				
				now = (int) time(NULL);
				if ((now - last_seen) <= LAST_SEEN_DELTA) {
					
					hit_cnt_resp = 0;
					hit_cnt_resp = get_total_hit_count_one_host_by_ix(host_ix);
					if (hit_cnt_resp >= SINGLE_IP_SCAN_THRESHOLD) {
						/*
						 * !! ENFORCE - if more than SINGLE_IP_SCAN_THRESHOLD ports
						 * were scanned by this src ip then block this bitch
						 * 
						 * do this by row count from the DB
						 */
						do_block_actions(host_ip, host_ix, 6);
					} else {
						/*
						 * !! ENFORCE - if the collective activity for
						 * this host surpasses a threshold then block this bitch.
						 * 
						 * we already have host_ix and host_ip
						 * get a total count of port hits for this host
						 */
						l_count = 0;
						l_count = get_one_host_hit_count_all_ports(host_ix);
						if (l_count > OVERALL_PORT_SCAN_THRESHOLD) {
							do_block_actions(host_ip, host_ix, 8);
						}
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	free(hosts_all_buf);
	free(host_ip);
}


void run_analysis() {
	
	//syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "running analysis process at", (int) time(NULL));
	
	int iter_cnt;
	int resp3;

	const char *tok1 = ">";
	char *token1;
	char *token1_save;
	const char *tok2 = ":";
	char *token2;
	char *token2_save;

	size_t dst_buf_sz = SMALL_DEST_BUF;
	char *l_hosts3 = (char*) malloc(dst_buf_sz+1);
	
	resp3 = get_detected_hosts_all_active_unprocessed(l_hosts3, dst_buf_sz);
	/*
	 std::cout << std::endl << resp3 << std::endl;
	 std::cout << l_hosts3 << std::endl;
	*/ 
	token1 = strtok_r(l_hosts3, tok1, &token1_save);
	while (token1 != NULL) {
		iter_cnt = 0;
		//std::cout << token1 << std::endl;
		token2 = strtok_r(token1, tok2, &token2_save);
		while (token2 != NULL) {
			//std::cout << token2 << " - " << iter_cnt << std::endl;
			if (iter_cnt == 1) {
				//IPTABLES_ENTRIES.push_back(token2);
				add_to_iptables_entries(atoi(token2));
			}
			token2 = strtok_r(NULL, tok2, &token2_save);
			iter_cnt++;
		}
		token1 = strtok_r(NULL, tok1, &token1_save);
	}
	/*
	std::cout << std::endl << std::endl;
	for (std::vector<int>::const_iterator i = IPTABLES_ENTRIES.begin();
			i != IPTABLES_ENTRIES.end(); ++i)
		std::cout << *i << ' ';

	std::cout << std::endl << std::endl;
	std::cout << exists_in_iptables_entries(31880) << std::endl;
	std::cout << exists_in_iptables_entries(31881) << std::endl;
	*/
	query_for_single_port_hits_last_seen();
	query_for_multiple_ports_hits_last_seen();

	free(l_hosts3);
}


int main() {

	signal(SIGINT, handle_signal);

	SingletonProcess singleton(6666);
	if (!singleton()) {
		std::cerr << "process running already. See " << singleton.GetLockFileName() << std::endl;
		return 1;
	}

	while (!stop) {
		run_analysis();
		// every 30 minutes
		sleep(1800);
	}
	
	return 0;
}
