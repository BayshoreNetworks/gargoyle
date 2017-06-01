/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * main analysis daemon - port scan detection and protection
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
#include <map>

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
#include "string_functions.h"
#include "ip_addr_controller.h"


struct greater_val
{
    template<class T>
    bool operator()(T const &a, T const &b) const { return a > b; }
};


std::vector<std::string> WHITE_LISTED_IP_ADDRS;
std::vector<int> IPTABLES_ENTRIES;
size_t PORT_SCAN_THRESHOLD = 15;
size_t SINGLE_IP_SCAN_THRESHOLD = 6;
size_t OVERALL_PORT_SCAN_THRESHOLD = 8;
// 8 hours
size_t LAST_SEEN_DELTA = 28800;
bool ENFORCE = true;
size_t IPTABLES_SUPPORTS_XLOCK;
// 5 days
size_t LAST_SEEN_THRESHOLD = 432000;

char DB_LOCATION[SQL_CMD_MAX+1];
const char *GARG_ANALYSIS_PROGNAME = "Gargoyle Pscand Analysis";

volatile sig_atomic_t stop;

void handle_signal (int);
bool exists_in_iptables_entries(int);
void add_to_iptables_entries(int);
void query_for_single_port_hits_last_seen();
void query_for_multiple_ports_hits_last_seen();
void run_analysis();
bool is_white_listed_ip_addr(std::string);
void add_to_ip_entries(std::string);
void get_default_gateway_linux();
void get_local_ip_addrs();
void get_white_list_addrs();
void clean_up_stale_data();
void clean_up_iptables_dupe_data();


void handle_signal (int signum) {
	stop = 1;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);
	exit(0);
}


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


void add_to_iptables_entries(int s) {
	if (!exists_in_iptables_entries(s))
		IPTABLES_ENTRIES.push_back(s);
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
	ret = get_unique_list_of_ports(list_of_ports, list_ports_dst_sz, DB_LOCATION);

	size_t list_hosts_dst_sz = SMALL_DEST_BUF;
	char *l_hosts = (char*) malloc(list_hosts_dst_sz+1);

	token1 = strtok_r(list_of_ports, tok1, &token1_save);
	while (token1 != NULL) {

		*l_hosts = 0;
		get_all_host_one_port_threshold(atoi(token1), PORT_SCAN_THRESHOLD, l_hosts, list_hosts_dst_sz, DB_LOCATION);
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
				if (!exists_in_iptables_entries(host_ix)) {

					size_t get_all_dst_sz = LOCAL_BUF_SZ;
					char *h_all = (char*) malloc(get_all_dst_sz+1);
					get_host_all_by_ix(host_ix, h_all, get_all_dst_sz, DB_LOCATION);
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
						do_block_actions(host_ip, 7, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);
						add_to_iptables_entries(host_ix);
						
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
	
	ret = get_hosts_all(hosts_all_buf, dst_buf_sz, DB_LOCATION);
	/*
	std::cout << hosts_all_buf << std::endl;
	std::cout << strlen(hosts_all_buf) << std::endl;
	*/
	
	if (ret == 0) {
		token1 = strtok_r(hosts_all_buf, tok1, &token1_save);
		while (token1 != NULL) {
			
			iter_cnt = 0;
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
			if (!exists_in_iptables_entries(host_ix)) {
				
				now = (int) time(NULL);
				if ((now - last_seen) <= LAST_SEEN_DELTA) {
					
					hit_cnt_resp = 0;
					hit_cnt_resp = get_total_hit_count_one_host_by_ix(host_ix, DB_LOCATION);
					if (hit_cnt_resp >= SINGLE_IP_SCAN_THRESHOLD) {
						/*
						 * !! ENFORCE - if more than SINGLE_IP_SCAN_THRESHOLD ports
						 * were scanned by this src ip then block this bitch
						 * 
						 * do this by row count from the DB
						 */
						do_block_actions(host_ip, 6, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);
						add_to_iptables_entries(host_ix);
						
					} else {
						/*
						 * !! ENFORCE - if the collective activity for
						 * this host surpasses a threshold then block this bitch.
						 * 
						 * we already have host_ix and host_ip
						 * get a total count of port hits for this host
						 */
						l_count = 0;
						l_count = get_one_host_hit_count_all_ports(host_ix, DB_LOCATION);
						if (l_count >= OVERALL_PORT_SCAN_THRESHOLD) {

							do_block_actions(host_ip, 8, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);
							add_to_iptables_entries(host_ix);
							
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
	
	int start_time = (int) time(NULL);
	syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "analysis process commencing at", start_time);
	
	IPTABLES_ENTRIES.clear();
	get_white_list_addrs();
	
	const char *tok1 = "\n";
	char *token1;
	char *token1_save;
	
	size_t d_buf_sz = DEST_BUF_SZ * 2;
	char *l_hosts = (char*) malloc(d_buf_sz);
	*l_hosts = 0;
	
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1+1);
	*host_ip = 0;
	
	const char *dash_dash = "--  ";
	size_t dash_dash_len = 4;
	const char *w_space = " ";
	char *s_lchains3;
	char *s_lchains4;

	size_t added_host_ix;
	added_host_ix = 0;
	int tstamp;
	
	/*
	 * get the latest data from iptables and
	 * populate vector IPTABLES_ENTRIES with
	 * the index of each ip actively blocked
	 * via iptables
	 */
	iptables_list_chain(GARGOYLE_CHAIN_NAME, l_hosts, d_buf_sz, IPTABLES_SUPPORTS_XLOCK);
	
	if (l_hosts) {
		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {

			s_lchains3 = strstr (token1, dash_dash);
			if (s_lchains3) {
				
				size_t position1 = s_lchains3 - token1;
				s_lchains4 = strstr (token1 + position1 + dash_dash_len, w_space);
				size_t position2 = s_lchains4 - token1;

				*host_ip = 0;
				added_host_ix = 0;
				
				bayshoresubstring(position1 + dash_dash_len, position2, token1, host_ip, 16);
				if (host_ip) {
					
					added_host_ix = get_host_ix(host_ip, DB_LOCATION);
					if (added_host_ix > 0) {
						add_to_iptables_entries(added_host_ix);
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}

	clean_up_stale_data();
	query_for_single_port_hits_last_seen();
	query_for_multiple_ports_hits_last_seen();
	clean_up_iptables_dupe_data();
	
	int end_time = (int) time(NULL);
	syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "analysis process finishing at", end_time);
	syslog(LOG_INFO | LOG_LOCAL6, "%s %d %s", "analysis process took", end_time - start_time, "seconds");
	
	free(l_hosts);
	free(host_ip);
}


bool is_white_listed_ip_addr(std::string s){

	std::vector<std::string>::const_iterator iter;

	iter = std::find(WHITE_LISTED_IP_ADDRS.begin(), WHITE_LISTED_IP_ADDRS.end(), s);
	if (iter != WHITE_LISTED_IP_ADDRS.end()) {
		return true;
	} else {
		return false;
	}
}


void add_to_ip_entries(std::string s) {
	if (!is_white_listed_ip_addr(s))
		WHITE_LISTED_IP_ADDRS.push_back(s);
}


void get_default_gateway_linux() {
	
	FILE *fp;
	char *dot;
	char *default_gway = (char*) malloc(1024);
	
	const char *tok1 = " ";
	char *token1;
	char *token1_save;
	
	fp = popen("ip route | grep default", "r");
	if (fp) {
		while (fgets(default_gway, 1024, fp) != NULL) {
			//std::cout << "--- " << default_gway << " --- " << strlen(default_gway) << std::endl;
			token1 = strtok_r(default_gway, tok1, &token1_save);
			while (token1 != NULL) {
				dot = strstr (token1, ".");
				if (dot) {
					add_to_ip_entries(token1);
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}
	free(default_gway);
	pclose(fp);
}


void get_local_ip_addrs() {
	
	FILE *fp;
	
	char *inet;
	char *dot;
	char *f_slash;
	
	char *ip_addrs = (char*) malloc(1024);
	
	const char *tok1 = " ";
	char *token1;
	char *token1_save;
	
	const char *tok2 = "/";
	char *token2;
	char *token2_save;
	
	int iter_cnt;

	fp = popen("ip addr", "r");
	if (fp) {
		while (fgets(ip_addrs, 1024, fp) != NULL) {
			//std::cout << "--- " << ip_addrs << " --- " << strlen(ip_addrs) << std::endl;
			inet = strstr (ip_addrs, "inet");
			dot = strstr (ip_addrs, ".");
			if (inet && dot) {
				//std::cout << "--- " << ip_addrs << " --- " << strlen(ip_addrs) << std::endl;

				token1 = strtok_r(ip_addrs, tok1, &token1_save);
				while (token1 != NULL) {
					//std::cout << token1 << std::endl;
					f_slash = strstr (token1, "/");
					if (f_slash) {
						iter_cnt = 0;
						token2 = strtok_r(token1, tok2, &token2_save);
						while (token2 != NULL) {
							if (iter_cnt == 0)
								add_to_ip_entries(token2);
							iter_cnt++;
							token2 = strtok_r(NULL, tok2, &token2_save);
						}
					}
					token1 = strtok_r(NULL, tok1, &token1_save);
				}
			}
		}
	}
	free(ip_addrs);
	pclose(fp);
}


void get_white_list_addrs() {

	const char *tok1 = ">";
	char *token1;
	char *token1_save;


	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

	size_t resp = get_hosts_to_ignore_all(l_hosts, dst_buf_sz, DB_LOCATION);
	
	if (resp == 0) {

		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {
			
			if (atoi(token1) > 0) {
			
				get_host_by_ix(atoi(token1), host_ip, dst_buf_sz1, DB_LOCATION);
				
				if (strcmp(host_ip, "") != 0) {
					add_to_ip_entries(host_ip);
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}

	free(l_hosts);
	free(host_ip);
}


void clean_up_stale_data() {
	
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
	
	ret = get_hosts_all(hosts_all_buf, dst_buf_sz, DB_LOCATION);
	/*
	std::cout << hosts_all_buf << std::endl;
	std::cout << strlen(hosts_all_buf) << std::endl;
	*/
	
	if (ret == 0) {
		
		token1 = strtok_r(hosts_all_buf, tok1, &token1_save);
		while (token1 != NULL) {
			
			iter_cnt = 0;
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

			if (!exists_in_iptables_entries(host_ix) && !is_white_listed_ip_addr(host_ip)) {
				
				now = (int) time(NULL);
				if ((now - last_seen) >= LAST_SEEN_THRESHOLD) {
					/*
					 * the following must be done in order to
					 * minimize the overall intensity of the
					 * analysis process as it can peg a CPU at
					 * close to 100% when there is a lot of data
					 * to process
					 * 
					 * the next steps will remove all traces of
					 * a particular host if we havent encountered
					 * it in over LAST_SEEN_THRESHOLD (5 days by
					 * default)
					 */
					
					/*
					// delete all records for this host_ix from hosts_ports_hits table
					remove_host_ports_all(host_ix, DB_LOCATION);
					// delete the host record
					remove_host(host_ix, DB_LOCATION);
					
					syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\" %s=\"%d\"", "removing record",
							VIOLATOR_SYSLOG, host_ip, "first_seen", first_seen, "last_seen", last_seen);
					*/
					do_host_remove_actions(host_ip, host_ix, DB_LOCATION, first_seen, last_seen);
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	free(hosts_all_buf);
	free(host_ip);
}


void clean_up_iptables_dupe_data() {
	
	size_t dst_buf_sz = DEST_BUF_SZ;
	char *l_chains = (char*) malloc(dst_buf_sz + 1);
	*l_chains = 0;
	char *l_chains2 = (char*) malloc(dst_buf_sz + 1);
	*l_chains2 = 0;
	
	const char *tok1 = "\n";
	
	char *token1;
	char *token1_save;
	char *token2;
	char *token2_save;
	
	
	const char *dash_dash = "--  ";
	size_t dash_dash_len = 4;
	const char *w_space = " ";
	
	char *s_lchains1;
	char *s_lchains2;
	char *s_lchains3;
	char *s_lchains4;
	
	char *host_ip = (char*) malloc(60);
	char *host_ip2 = (char*) malloc(60);
	
	int rule_ix1;
	int rule_ix2;
	
	std::map<std::string, int> iptables_map;
	
	iptables_list_chain_with_line_numbers(GARGOYLE_CHAIN_NAME, l_chains, dst_buf_sz, IPTABLES_SUPPORTS_XLOCK);
	if (l_chains) {
		token1 = strtok_r(l_chains, tok1, &token1_save);
		while (token1 != NULL) {
			
			rule_ix1 = atoi(token1);
			s_lchains1 = strstr (token1, dash_dash);
			
			if (s_lchains1) {
				
				size_t position1 = s_lchains1 - token1;
				s_lchains2 = strstr (token1 + position1 + dash_dash_len, w_space);
				size_t position2 = s_lchains2 - token1;

				*host_ip = 0;
				
				bayshoresubstring(position1 + dash_dash_len, position2, token1, host_ip, 16);
				if (host_ip) {
					iptables_map.insert(std::pair<std::string,int>(host_ip,rule_ix1));
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}

	std::map<std::string,int>::iterator it = iptables_map.begin();
	/*
	for (it=iptables_map.begin(); it!=iptables_map.end(); ++it) {
			
		std::cout << it->first << " => " << it->second << '\n';
	}
	*/
	std::vector<int> vec;
	for (it=iptables_map.begin(); it!=iptables_map.end(); ++it) {
		
	    //std::cout << it->first << " => " << it->second << '\n';
		iptables_list_chain_with_line_numbers(GARGOYLE_CHAIN_NAME, l_chains2, dst_buf_sz, IPTABLES_SUPPORTS_XLOCK);
							
		if (l_chains2) {
			
			token2 = strtok_r(l_chains2, tok1, &token2_save);
			while (token2 != NULL) {
				
				rule_ix2 = atoi(token2);
				s_lchains3 = strstr (token2, dash_dash);
				if (s_lchains3) {
					
					size_t position3 = s_lchains3 - token2;
					s_lchains4 = strstr (token2 + position3 + dash_dash_len, w_space);
					size_t position4 = s_lchains4 - token2;

					*host_ip2 = 0;
					bayshoresubstring(position3 + dash_dash_len, position4, token2, host_ip2, 16);
					if (host_ip2) {

						if ((strcmp((it->first).c_str(), host_ip2) == 0) && (it->second < rule_ix2)) {
							/*
							std::cout << it->first << " - " << host_ip2 << std::endl;
							std::cout << it->second << " - " << rule_ix2 << std::endl << std::endl;
							*/
							vec.push_back(rule_ix2);
						}
					}
				}
				token2 = strtok_r(NULL, tok1, &token2_save);
			}
		}
	}

	if (vec.size() > 0) {
		/*
		 * We have to remove rules from the bottom
		 * up in iptables
		 */
		std::sort(vec.begin(), vec.end(), greater_val());
		for (std::vector<int>::const_iterator itv=vec.begin(); itv!=vec.end(); ++itv) {
			//std::cout << *itv << " ";
			iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, *itv, IPTABLES_SUPPORTS_XLOCK);
		}
	}
	free(l_chains);
	free(l_chains2);
	free(host_ip);
	free(host_ip2);
}



int main(int argc, char *argv[]) {

	signal(SIGINT, handle_signal);
	
	if (geteuid() != 0) {
    	std::cerr << std::endl << "Root privileges are necessary for this to run ..." << std::endl << std::endl;
    	return 1;
    }

    /*
     * in order to keep stuff lean and mean I
     * am doing this manually here and not
     * using a lib that parses command line args,
     * maybe we replace this in the future ...
     */
    if (argc > 2 || argc < 1) {
    	
    	std::cerr << std::endl << GARG_ANALYSIS_PROGNAME << " - Argument errors, exiting ..." << std::endl << std::endl;
    	return 1;
    	
    } else if (argc == 2) {
    	
    	std::string arg_one = argv[1];
    	
    	if ((case_insensitive_compare(arg_one.c_str(), "-v")) || (case_insensitive_compare(arg_one.c_str(), "--version"))) {
    		std::cout << std::endl << GARGOYLE_PSCAND << " Version: " << GARGOYLE_VERSION << std::endl << std::endl;
    	} else if ((case_insensitive_compare(arg_one.c_str(), "-c"))) { }
    	else {
    		return 0;
    	}
    }
	
	int analysis_port;
	//const char *port_config_file = ".gargoyle_internal_port_config";
	const char *port_config_file;
	port_config_file = getenv("GARGOYLE_INTERNAL_PORT_CONFIG");
	if (port_config_file == NULL)
		port_config_file = ".gargoyle_internal_port_config";
	analysis_port = 0;
	
	ConfigVariables cv;
	if (cv.get_vals(port_config_file) == 0) {
		analysis_port = cv.get_gargoyle_pscand_analysis_udp_port();
	} else {
		return 1;
	}
	
	if (analysis_port <= 0)
		return 1;

		
	SingletonProcess singleton(analysis_port);
	if (!singleton()) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_pscand_analysis", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
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
	
	// Get config data
	//const char *config_file = ".gargoyle_config";
	const char *config_file;
	config_file = getenv("GARGOYLE_CONFIG");
	if (config_file == NULL)
		config_file = ".gargoyle_config";
	
	ConfigVariables cvv;
	if (cvv.get_vals(config_file) == 0) {
		
		ENFORCE = cvv.get_enforce_mode();
		PORT_SCAN_THRESHOLD = cvv.get_port_scan_threshold();
		SINGLE_IP_SCAN_THRESHOLD = cvv.get_single_ip_scan_threshold();
		OVERALL_PORT_SCAN_THRESHOLD = cvv.get_overall_port_scan_threshold();
		LAST_SEEN_DELTA = cvv.get_last_seen_delta();

	} else {
		return 1;
	}
	
	WHITE_LISTED_IP_ADDRS.push_back("0.0.0.0");
	get_default_gateway_linux();
	get_local_ip_addrs();
	get_white_list_addrs();

	std::stringstream ss;
	int l_cnt = 1;
	int v_cnt = WHITE_LISTED_IP_ADDRS.size();
	for (std::vector<std::string>::const_iterator i = WHITE_LISTED_IP_ADDRS.begin(); i != WHITE_LISTED_IP_ADDRS.end(); ++i) {
		//std::cout << *i << std::endl;
		if (l_cnt == v_cnt)
			ss << *i;
		else
			ss << *i << ",";
		l_cnt++;
	}
	syslog(LOG_INFO | LOG_LOCAL6, "%s - %s %s", GARG_ANALYSIS_PROGNAME, "ignoring IP addr's:", (ss.str().c_str()));
	
	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();
	
	
	// processing loop
	while (!stop) {
		run_analysis();
		// every 15 minutes by default
		sleep(900);
	}
	return 0;
}
