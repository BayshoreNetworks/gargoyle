/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * main daemon
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
#include <csignal>

#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "nf_queue.h"
#include "packet_handler.h"
#include "singleton.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "string_functions.h"

///////////////////////////////////////////////////////////////////////////////////
bool IGNORE_LISTENING_PORTS = true;
bool IGNORE_LOCAL_IP_ADDRS = true;

size_t IPTABLES_SUPPORTS_XLOCK;
size_t EPHEMERAL_LOW;
size_t EPHEMERAL_HIGH;

char DB_LOCATION[SQL_CMD_MAX+1];

std::vector<int> IGNORE_PORTS;
std::vector<std::string> LOCAL_IP_ADDRS;
///////////////////////////////////////////////////////////////////////////////////

int hex_to_int(const char *);
bool exists_in_ports_entries(int);
bool exists_in_ip_entries(std::string);
void add_to_ports_entries(int);
void add_to_ip_entries(std::string);
void nfqueue_signal_handler(int);
void graceful_exit (int);
void handle_chain();
void get_ports_to_ignore();
void get_ephemeral_range_to_ignore();
void get_local_ip_addrs();
void get_default_gateway_linux();
void get_white_list_addrs();

///////////////////////////////////////////////////////////////////////////////////

void nfqueue_signal_handler(int signum) {
	graceful_exit(signum);
}


void graceful_exit(int signum) {
	
	if (signum == 11) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);
		exit(0);
	}
	
	//std::cout << "Signal caught: " << signum << ", destroying queue ..." << std::endl;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s %s", SIGNAL_CAUGHT_SYSLOG, signum, "destroying queue, cleaning up iptables entries and", PROG_TERM_SYSLOG);
	
	/*
	 * 1. delete NFQUEUE rule from INPUT chain
	 * 2. delete GARGOYLE_CHAIN_NAME rule from the INPUT chain
	 * 3. flush (delete any rules that exist in) GARGOYLE_CHAIN_NAME
	 * 4. clear items in DB table detected_hosts
	 * 5. deete GARGOYLE_CHAIN_NAME
	 */
	///////////////////////////////////////////////////
	// 1
	size_t rule_ix;
	rule_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFQUEUE, NFQUEUE_NUM_LINE, IPTABLES_SUPPORTS_XLOCK);
	if (rule_ix > 0) {
		iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, rule_ix, IPTABLES_SUPPORTS_XLOCK);
	}
	///////////////////////////////////////////////////
	// 2
	size_t g_rule_ix;
	g_rule_ix = iptables_find_rule_in_chain(IPTABLES_INPUT_CHAIN, GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	//syslog(LOG_INFO | LOG_LOCAL6, "%s: %zu, %s %s %s %s", "Rule", g_rule_ix, "is", GARGOYLE_CHAIN_NAME, "inside", IPTABLES_INPUT_CHAIN);
	if (g_rule_ix > 0) {
		iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, g_rule_ix, IPTABLES_SUPPORTS_XLOCK);
	}
	///////////////////////////////////////////////////
	// 3
	iptables_flush_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	///////////////////////////////////////////////////
	// 4
	remove_detected_hosts_all(DB_LOCATION);
	///////////////////////////////////////////////////
	// 5
	iptables_delete_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);

}


void handle_chain() {

	/*
	 * 1. if the chain GARGOYLE_CHAIN_NAME doesnt exist create it
	 * look for something like this: Chain BSN_test_Chain (1 references)
	 * 2. add GARGOYLE_CHAIN_NAME at index 1 in chain INPUT
	 * 3. add nfqueue rule to chain INPUT ...
	 * this rule needs to be the last one in the INPUT chain
	 * since NFQUEUE is terminal (when we set verdict it
	 * is final and packets will go no further in terms
	 * of iptables rules
	 */
	///////////////////////////////////////////////////
	// 1
	/*
	 * if the chain doesnt exist it could not possibly have been added
	 * to the INPUT chain so create the chain and then add it to INPUT
	 */
	char *p_lchains;
	
	size_t dst_buf_sz = DEST_BUF_SZ;
	char *l_chains = (char*) malloc(dst_buf_sz+1);
	*l_chains = 0;
	iptables_list_all(l_chains, dst_buf_sz, IPTABLES_SUPPORTS_XLOCK);
	
	if (l_chains) {
		//std::cout << l_chains << std::endl;
		p_lchains = strstr (l_chains, GARGOYLE_CHAIN_NAME);
		if (!p_lchains) {
			// create new chain used just for this
			//std::cout << "CREATING Chain " << GARGOYLE_CHAIN_NAME << std::endl;
			iptables_create_new_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
			/*
			 * example out:
			 * 
			 * Dec 22 11:55:29 shadow-box gargoyle_pscand[2278]: Creating Chain-GARGOYLE_Input_Chain
			 */
			syslog(LOG_INFO | LOG_LOCAL6, "%s-%s", "Creating Chain", GARGOYLE_CHAIN_NAME);
		}
	}
	///////////////////////////////////////////////////
	// 2
	size_t dst_buf_sz2 = DEST_BUF_SZ;
	char *l_chains2 = (char*) malloc(dst_buf_sz2+1);
	*l_chains2 = 0;
	
	const char *tok1 = "\n";
	char *token1;
	char *token1_save;
	
	char *p_lchains2;
	char *s_lchains2;
	
	bool ADD_CHAIN_TO_INPUT = true;
	
	iptables_list_all_with_line_numbers(l_chains2, dst_buf_sz2, IPTABLES_SUPPORTS_XLOCK);
	if (l_chains2) {
		token1 = strtok_r(l_chains2, tok1, &token1_save);
		while (token1 != NULL) {
			p_lchains2 = strstr (token1, GARGOYLE_CHAIN_NAME);
			if (p_lchains2) {
				s_lchains2 = strstr (token1, "Chain");
				if (s_lchains2) {
					int position = s_lchains2 - token1;
					if (position != 0) {
						ADD_CHAIN_TO_INPUT = false;
						break;
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}

	if (ADD_CHAIN_TO_INPUT) {
		// insert this to INPUT chain at specific index 1
		iptables_insert_chain_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, "1", GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	}
	
	int drop_ix;
	int reject_ix;
	int	targ_ix;
		
	drop_ix = 0;
	reject_ix = 0;
	targ_ix = 0;	
	///////////////////////////////////////////////////
	// 3
	/*
	 * setup nfqueue rule last as we want the
	 * blocking rules from Chain (GARGOYLE_CHAIN_NAME)
	 * to be executed before packets get handed
	 * off to the nfqueue
	 * 
	 * Any blocking rules that get added to the INPUT
	 * chain after this one will not work, as in packets
	 * will get through since we always set verdict
	 * with NF_ACCEPT as the verdict
	 * 
	 * iptables -A INPUT -j NFQUEUE --queue-num 5
	 */
	size_t rule_ix;
	rule_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFQUEUE, NFQUEUE_NUM_LINE, IPTABLES_SUPPORTS_XLOCK);
	
	size_t d_buf_sz = DEST_BUF_SZ * 2;
	char *l_chains3 = (char*) malloc(d_buf_sz);
	*l_chains3 = 0;
	
	char *p_lchains3;
	char *s_lchains3;
	char *drop_ix_buf = (char*) malloc(5);
	*drop_ix_buf = 0;
	
	char *p_lchains4;
	char *s_lchains4;
	char *reject_ix_buf = (char*) malloc(5);
	*reject_ix_buf = 0;
	
	if (rule_ix == 0) {
		//std::cout << rule_ix << std::endl;
		/*
		 * look for rules that start with DROP or REJECT
		 * we need to get injected before them
		 */
		iptables_list_chain_with_line_numbers(IPTABLES_INPUT_CHAIN, l_chains3, d_buf_sz, IPTABLES_SUPPORTS_XLOCK);
		if (l_chains3) {
			token1 = strtok_r(l_chains3, tok1, &token1_save);
			while (token1 != NULL) {
				
				p_lchains3 = strstr (token1, "DROP ");
				p_lchains4 = strstr (token1, "REJECT ");
				
				if (p_lchains3) {
					s_lchains3 = strstr (token1, " ");
					if (s_lchains3) {
						int position2 = s_lchains3 - token1;
						strncpy(drop_ix_buf, token1, position2);
						drop_ix_buf[position2] = '\0';
						drop_ix = atoi(drop_ix_buf);
						/*
						std::cout << position2 << std::endl;
						std::cout << drop_ix_buf << " - " << strlen(drop_ix_buf) << std::endl;
						*/
					}
					//std::cout << token1 << std::endl;
				}
				
				if (p_lchains4) {
					s_lchains4 = strstr (token1, " ");
					if (s_lchains4) {
						int position3 = s_lchains4 - token1;
						strncpy(reject_ix_buf, token1, position3);
						reject_ix_buf[position3] = '\0';
						reject_ix = atoi(reject_ix_buf);
					}
					//std::cout << token1 << std::endl;
				}
				
				targ_ix = atoi(token1);
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
		
		if (drop_ix > 0 && reject_ix > 0) {
			
			//targ_ix = std::min(drop_ix,reject_ix);
			//targ_ix = last rule index of INPUT
			int drop_ix_delta = targ_ix - drop_ix;
			int reject_ix_delta = targ_ix - reject_ix;
			/*
			std::cout << "DROPD: " << drop_ix_delta << std::endl;
			std::cout << "REJECTD: " << reject_ix_delta << std::endl;
			*/
			if (drop_ix_delta < 2 && reject_ix_delta < 2) {
				
				std::cout << "Gargoyle_pscand cannot run with iptables (INPUT chain) rules " << drop_ix << " and " << reject_ix << " in place" << std::endl << std::endl;
				// dont continue
				graceful_exit(2);
				exit(0);
			}
		}
		
		if (targ_ix >= 1)
			targ_ix = targ_ix + 1;
		
		if (targ_ix == 0)
			targ_ix = 2;

		iptables_insert_nfqueue_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, targ_ix, IPTABLES_SUPPORTS_XLOCK);

	}
	///////////////////////////////////////////////////
	free(l_chains);
	free(l_chains2);
	free(l_chains3);
	free(drop_ix_buf);
	free(reject_ix_buf);
}


int hex_to_int(const char *hex) {
	
	int res;
	res = 0;
	
    while (*hex) {
    	if (*hex > 47 && *hex < 58)
    		res += (*hex - 48);
    	else if (*hex > 64 && *hex < 71)
    		res += (*hex - 55);
    	else if (*hex > 96 && *hex < 103)
    		res += (*hex - 87);
    	
    	if (*++hex)
    		res <<= 4;
    }

    return res;
}


void get_ports_to_ignore() {
	
	FILE *fp;
	char *net_tcp = (char*) malloc(133);
	char *target = (char*) malloc(6);

	fp = popen("cat /proc/net/tcp", "r");
	if (fp) {
		while (fgets(net_tcp, 132, fp) != NULL) {
			//printf("%s\n", net_tcp);
			//std::cout << net_tcp << std::endl;
				
			snprintf(target, 5, "%s", net_tcp+15);
			if (target[0] != ' ') {
				//std::cout << target << " - " << hex_to_int(target) << std::endl;
				int the_port = hex_to_int(target);
				if (EPHEMERAL_LOW > 0 && EPHEMERAL_HIGH > 0) {
					if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
						add_to_ports_entries(the_port);
					}
				}
			}
		}
	}
	free(net_tcp);
	free(target);
	pclose(fp);
}


bool exists_in_ports_entries(int s) {

	std::vector<int>::const_iterator iter;

	iter = std::find(IGNORE_PORTS.begin(), IGNORE_PORTS.end(), s);
	if (iter != IGNORE_PORTS.end()) {
		return true;
	} else {
		return false;
	}
}


bool exists_in_ip_entries(std::string s){

	std::vector<std::string>::const_iterator iter;

	iter = std::find(LOCAL_IP_ADDRS.begin(), LOCAL_IP_ADDRS.end(), s);
	if (iter != LOCAL_IP_ADDRS.end()) {
		return true;
	} else {
		return false;
	}
}


void add_to_ports_entries(int s) {
	if (exists_in_ports_entries(s) == false)
		IGNORE_PORTS.push_back(s);
}


void add_to_ip_entries(std::string s) {
	if (exists_in_ip_entries(s) == false)
		LOCAL_IP_ADDRS.push_back(s);
}


void get_ephemeral_range_to_ignore() {
	
	FILE *fp;
	char *ephemeral_tcp = (char*) malloc(13);
	char *target = (char*) malloc(6);
	
	const char *tok1 = "\t";
	char *token1;
	char *token1_save;
	
	int iter_cnt;

	fp = popen("cat /proc/sys/net/ipv4/ip_local_port_range", "r");
	if (fp) {
		if (fgets(ephemeral_tcp, 20, fp) != NULL) {
			//std::cout << "--- " << ephemeral_tcp << " --- " << strlen(ephemeral_tcp) << std::endl;
			iter_cnt = 0;
			token1 = strtok_r(ephemeral_tcp, tok1, &token1_save);
			while (token1 != NULL) {
				//std::cout << token1 << std::endl;
				
				if (iter_cnt == 0)
					EPHEMERAL_LOW = atoi(token1);
				if (iter_cnt == 1)
					EPHEMERAL_HIGH = atoi(token1);
				
				iter_cnt++;
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}
	free(ephemeral_tcp);
	free(target);
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

///////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	
    // Set up signal handlers
    signal (SIGINT, nfqueue_signal_handler);
    signal (SIGSEGV, nfqueue_signal_handler);
    
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
    	
    	std::cerr << std::endl << "Argument errors, exiting ..." << std::endl << std::endl;
    	return 1;
    	
    } else if (argc == 2) {
    	
    	std::string arg_one = argv[1];
    	
    	if ((case_insensitive_compare(arg_one.c_str(), "-v")) || (case_insensitive_compare(arg_one.c_str(), "--version"))) {
    		std::cout << std::endl << GARGOYLE_PSCAND << " Version: " << GARGOYLE_VERSION << std::endl << std::endl;
    	}
    	return 0;
    }
    
    // Get port config data
	int daemon_port;
	const char *port_config_file;
	port_config_file = getenv("GARGOYLE_INTERNAL_PORT_CONFIG");
	if (port_config_file == NULL)
		port_config_file = ".gargoyle_internal_port_config";
	daemon_port = 0;
	
	ConfigVariables cv;
	if (cv.get_vals(port_config_file) == 0) {
		daemon_port = cv.get_gargoyle_pscand_udp_port();
	} else {
		return 1;
	}
	
	if (daemon_port <= 0)
		return 1;

	SingletonProcess singleton(daemon_port);
	if (!singleton()) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_pscand", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
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
	bool enforce_mode = true;
	size_t single_ip_scan_threshold = 0;
	size_t single_port_scan_threshold = 0;
	std::string ports_to_ignore;
	
	const char *config_file;
	config_file = getenv("GARGOYLE_CONFIG");
	if (config_file == NULL)
		config_file = ".gargoyle_config";
	
	ConfigVariables cvv;
	if (cvv.get_vals(config_file) == 0) {
		
		enforce_mode = cvv.get_enforce_mode();
		
		single_ip_scan_threshold = cvv.get_single_ip_scan_threshold();
		single_port_scan_threshold = cvv.get_port_scan_threshold();
		
		ports_to_ignore = cvv.get_ports_to_ignore();
		
	} else {
		return 1;
	}
	
	// does iptables support xlock
	// 1 = true, 0 = false
	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();
	
	handle_chain();

	get_ephemeral_range_to_ignore();
	/*
	std::cout << EPHEMERAL_LOW << std::endl;
	std::cout << EPHEMERAL_HIGH << std::endl;
	*/
	syslog(LOG_INFO | LOG_LOCAL6, "%s %zu - %zu", "ignoring ephemeral port range:", EPHEMERAL_LOW, EPHEMERAL_HIGH);
	
	if (IGNORE_LISTENING_PORTS) {

		/*
		 * first get any ports to ignore from
		 * .gargoyle_config
		 */
		if (ports_to_ignore.size() > 0) {
			// tokenize , delimited
			if (EPHEMERAL_LOW > 0 && EPHEMERAL_HIGH > 0) {
				
				const char *tok1 = ",";
				char *token1;
				char *token1_save;
				int the_port;
				char *ret_dash;
				
				token1 = strtok_r(&ports_to_ignore[0], tok1, &token1_save);
				while (token1 != NULL) {
					
					/*
					 * look for dash and process this
					 * as a range of ports
					 */
					ret_dash = strstr(token1, "-");
					if (ret_dash) {
						
						int start_port = atoi(token1);
						int end_port = atoi(ret_dash + 1);
						
						if (start_port < end_port && start_port > 0) {
						
							//std::cout << start_port << std::endl;
							//std::cout << end_port << std::endl;
							for(int x = start_port; x <= end_port; x++)
								add_to_ports_entries(x);
						}
					} else {
						the_port = atoi(token1);
						if(the_port > 0) {
							if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
								add_to_ports_entries(the_port);
							}
						}
					}
					token1 = strtok_r(NULL, tok1, &token1_save);
				}
			}
		}
		
		/*
		 * get ports to ignore from
		 * system
		 */
		get_ports_to_ignore();

		std::stringstream ss;
		int l_cnt = 1;
		int v_cnt = IGNORE_PORTS.size();
		for (std::vector<int>::const_iterator i = IGNORE_PORTS.begin(); i != IGNORE_PORTS.end(); ++i) {
			if (l_cnt == v_cnt)
				ss << *i;
			else
				ss << *i << ",";
			l_cnt++;
		}
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "ignoring ports:", (ss.str().c_str()));
	}

	LOCAL_IP_ADDRS.push_back("0.0.0.0");
	get_default_gateway_linux();
	if (IGNORE_LOCAL_IP_ADDRS) {
		
		get_local_ip_addrs();
		get_white_list_addrs();

		std::stringstream ss;
		int l_cnt = 1;
		int v_cnt = LOCAL_IP_ADDRS.size();
		for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
			//std::cout << *i << std::endl;
			if (l_cnt == v_cnt)
				ss << *i;
			else
				ss << *i << ",";
			l_cnt++;
		}
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "ignoring IP addr's:", (ss.str().c_str()));
	}
	
	Library lib;
	lib.bind(AF_INET);
	
	CompoundHandler c_handlers;
	
	GargoylePscandHandler gargoyleHandler;
	
	/*
	 * this can be more elegant but works for now
	 */
	for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
		gargoyleHandler.add_to_ip_entries(*i);
	}
	gargoyleHandler.set_ignore_local_ip_addrs(IGNORE_LOCAL_IP_ADDRS);
	gargoyleHandler.set_ephemeral_low(EPHEMERAL_LOW);
	gargoyleHandler.set_ephemeral_high(EPHEMERAL_HIGH);
	gargoyleHandler.set_chain_name(GARGOYLE_CHAIN_NAME);
	gargoyleHandler.set_enforce_mode(enforce_mode);
	if (single_ip_scan_threshold > 0)
		gargoyleHandler.set_single_ip_scan_threshold(single_ip_scan_threshold);
	if (single_port_scan_threshold > 0)
		gargoyleHandler.set_single_port_scan_threshold(single_port_scan_threshold);
	
	/*
	 * this can be more elegant but works for now
	 */
	for (std::vector<int>::const_iterator i = IGNORE_PORTS.begin(); i != IGNORE_PORTS.end(); ++i) {
		gargoyleHandler.add_to_ports_entries(*i);
	}
	gargoyleHandler.set_iptables_supports_xlock(IPTABLES_SUPPORTS_XLOCK);
	gargoyleHandler.set_db_location(DB_LOCATION);
	
	c_handlers.add_handler(gargoyleHandler);
	
	Queue queue(lib, 5, c_handlers);
	
	lib.loop();

	graceful_exit(SIGINT);
	
	return 0;
}
