/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * main daemon - port scan detection and protection
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
#include "packet_handler.h"
#include "singleton.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "string_functions.h"
#include "ip_addr_controller.h"
#include "system_functions.h"
#include "data_base.h"


#ifdef __cplusplus
extern "C" {
#endif
#include <libnetfilter_log/libnetfilter_log.h>
#ifdef __cplusplus
}
#endif

///////////////////////////////////////////////////////////////////////////////////
bool IGNORE_LISTENING_PORTS = true;
bool IGNORE_LOCAL_IP_ADDRS = true;
bool DEBUG = false;
//bool DEBUG = true;

size_t IPTABLES_SUPPORTS_XLOCK;
size_t EPHEMERAL_LOW;
size_t EPHEMERAL_HIGH;

char DB_LOCATION[SQL_CMD_MAX+1];

std::vector<int> IGNORE_PORTS;
std::vector<std::string> LOCAL_IP_ADDRS;

struct nflog_handle *nfl_handle;
struct nflog_g_handle *qh;

GargoylePscandHandler gargoyleHandler;
DataBase *gargoyle_pscand_data_base_shared_memory = nullptr;

int NFLOG_BIND_GROUP = 5;
SharedIpConfig *gargoyle_blacklist_shm = NULL;
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
void get_blacklist_ip_addrs(int);

///////////////////////////////////////////////////////////////////////////////////

void nfqueue_signal_handler(int signum) {
	graceful_exit(signum);
}


void graceful_exit(int signum) {

    if(gargoyle_blacklist_shm) {
        delete gargoyle_blacklist_shm;
        //gargoyle_blacklist_shm;
    }

	if (signum == 11) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);
		exit(0);
	}

	//std::cout << "Signal caught: " << signum << ", destroying queue ..." << std::endl;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s %s", SIGNAL_CAUGHT_SYSLOG, signum, "destroying queue, cleaning up iptables entries and", PROG_TERM_SYSLOG);

	/*
	 * 1. delete NFLOG rule from INPUT chain
	 * 2. delete GARGOYLE_CHAIN_NAME rule from the INPUT chain
	 * 3. flush (delete any rules that exist in) GARGOYLE_CHAIN_NAME
	 * 4. clear items in DB table detected_hosts
	 * 5. reset auto-increment counter for table detected_hosts
	 * 6. delete GARGOYLE_CHAIN_NAME
	 */
	///////////////////////////////////////////////////
	// 1
	int rule_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFLOG, "nflog-group", IPTABLES_SUPPORTS_XLOCK);
	if (rule_ix > 0) {
		iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, rule_ix, IPTABLES_SUPPORTS_XLOCK);
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %d", "Deleting NFLOG rule from chain", IPTABLES_INPUT_CHAIN, "at index", rule_ix);
	}
	///////////////////////////////////////////////////
	// 2
	int g_rule_ix = iptables_find_rule_in_chain(IPTABLES_INPUT_CHAIN, GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	if (g_rule_ix > 0) {
		iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, g_rule_ix, IPTABLES_SUPPORTS_XLOCK);
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s %d", "Deleting", GARGOYLE_CHAIN_NAME, "from chain", IPTABLES_INPUT_CHAIN, "at index", g_rule_ix);
	}
	///////////////////////////////////////////////////
	// 3
	iptables_flush_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	///////////////////////////////////////////////////
	// 4
	if(gargoyle_pscand_data_base_shared_memory != nullptr){
		string query = "DELETE FROM detected_hosts";
		gargoyle_pscand_data_base_shared_memory->detected_hosts->DELETE(query);
	}else{
		sqlite_remove_detected_hosts_all(DB_LOCATION);
	}
	// 5
	if(gargoyle_pscand_data_base_shared_memory != nullptr){
		gargoyleHandler.cleanTables("detected_hosts_table");
	}else{
		sqlite_reset_autoincrement(DETECTED_HOSTS_TABLE, DB_LOCATION);
	}
	///////////////////////////////////////////////////
	// 6
	iptables_delete_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	///////////////////////////////////////////////////
	//if(gargoyleHandler.get_type_data_base() == "shared_memory"){
	//	gargoyleHandler.cleanTables();
	//}

    if(gargoyle_pscand_data_base_shared_memory != nullptr){
    	delete gargoyle_pscand_data_base_shared_memory;
    }

	exit(0);
}


void handle_chain() {

	/*
	 * 1. if the chain GARGOYLE_CHAIN_NAME doesnt exist create it
	 * look for something like this: Chain GARGOYLE_Input_Chain (1 references)
	 * 2. add GARGOYLE_CHAIN_NAME at some index in chain INPUT
	 * 3. add nflog rule to chain INPUT
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
	iptables_list_all(l_chains, dst_buf_sz, IPTABLES_SUPPORTS_XLOCK);

	if (l_chains) {
		p_lchains = strstr (l_chains, GARGOYLE_CHAIN_NAME);
		if (!p_lchains) {
			// create new chain used just for this
			iptables_create_new_chain(GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
			/*
			 * example out:
			 *
			 * Dec 22 11:55:29 shadow-box gargoyle_pscand[2278]: Creating Chain-GARGOYLE_Input_Chain
			 */
			syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "Creating Chain", GARGOYLE_CHAIN_NAME);
		}
	}
	///////////////////////////////////////////////////
	// 2
	bool ADD_CHAIN_TO_INPUT = true;

	int position = iptables_find_rule_in_chain(IPTABLES_INPUT_CHAIN, GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
	if (position > 0)
		ADD_CHAIN_TO_INPUT = false;

	if (ADD_CHAIN_TO_INPUT) {
		position = 1;
		// insert this to INPUT chain at specific index 1
		iptables_insert_chain_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, "1", GARGOYLE_CHAIN_NAME, IPTABLES_SUPPORTS_XLOCK);
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s %d", "Adding", GARGOYLE_CHAIN_NAME, "to chain", IPTABLES_INPUT_CHAIN, "at index", position);
	} else {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %d %s %s", GARGOYLE_CHAIN_NAME, "already exists at index", position, "in chain", IPTABLES_INPUT_CHAIN);
	}
	///////////////////////////////////////////////////
	// 3
	int targ_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFLOG, "nflog-group", IPTABLES_SUPPORTS_XLOCK);

	if (targ_ix == 0) {
		targ_ix = position + 1;

		iptables_insert_nflog_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, targ_ix, IPTABLES_SUPPORTS_XLOCK);
		//iptables_insert_nflog_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, 2, IPTABLES_SUPPORTS_XLOCK);
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %d", "Adding NFLOG rule to chain", IPTABLES_INPUT_CHAIN, "at index", targ_ix);
	} else {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %d %s %s", "NFLOG rule already exists at index", targ_ix, "in chain", IPTABLES_INPUT_CHAIN);
	}
	///////////////////////////////////////////////////
	free(l_chains);
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
    	else
    		return 0;

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
				if (the_port > 0 && the_port <= 65535) {
					if (EPHEMERAL_LOW > 0 && EPHEMERAL_HIGH > 0) {
						if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
							add_to_ports_entries(the_port);
						}
					}
				}
			}
		}
		pclose(fp);
	}
	free(net_tcp);
	free(target);
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
	if (!exists_in_ports_entries(s))
		IGNORE_PORTS.push_back(s);
}


void add_to_ip_entries(std::string s) {
	if (!exists_in_ip_entries(s))
		LOCAL_IP_ADDRS.push_back(s);
}


void get_ephemeral_range_to_ignore() {

	FILE *fp;
	char ephemeral_tcp[32];

	const char *tok1 = "\t";
	char *token1;
	char *token1_save;

	int iter_cnt;

	fp = popen("cat /proc/sys/net/ipv4/ip_local_port_range", "r");
	if (fp) {
		if (fgets(ephemeral_tcp, sizeof(ephemeral_tcp), fp) != NULL) {
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
		pclose(fp);
	}
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
		pclose(fp);
	}
	free(ip_addrs);
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
		pclose(fp);
	}
	free(default_gway);
}


void get_white_list_addrs() {

	const char *tok1 = ">";
	char *token1;
	char *token1_save;


	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

	size_t resp = sqlite_get_hosts_to_ignore_all(l_hosts, dst_buf_sz, DB_LOCATION);

	if (resp == 0) {

		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {

			if (atoi(token1) > 0) {

				sqlite_get_host_by_ix(atoi(token1), host_ip, dst_buf_sz1, DB_LOCATION);

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


void get_blacklist_ip_addrs(int enforce_state) {

	const char *tok1 = ">";
	char *token1;
	char *token1_save;


	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

	size_t resp = sqlite_get_hosts_blacklist_all(l_hosts, dst_buf_sz, DB_LOCATION);

	if (resp == 0) {

		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {

			int host_ix = atoi(token1);
			if (host_ix > 0) {

				sqlite_get_host_by_ix(host_ix, host_ip, dst_buf_sz1, DB_LOCATION);

				if (strcmp(host_ip, "") != 0) {

					do_black_list_actions(host_ip,
										(void *) gargoyle_blacklist_shm,
										IPTABLES_SUPPORTS_XLOCK,
										enforce_state
										);

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

    	std::cerr << std::endl << GARGOYLE_PSCAND << " - Argument errors, exiting ..." << std::endl << std::endl;
		std::cerr << std::endl << "Usage: ./gargoyle_pscand_pcap [-v | --version] [-s | --shared_memory]" << std::endl << std::endl;
    	return 1;

    } else if (argc == 2) {

    	std::string arg_one = argv[1];

    	if ((case_insensitive_compare(arg_one.c_str(), "-v")) || (case_insensitive_compare(arg_one.c_str(), "--version"))) {
    		std::cout << std::endl << GARGOYLE_PSCAND << " Version: " << GARGOYLE_VERSION << std::endl << std::endl;
    		return 0;
    	} else if ((case_insensitive_compare(arg_one.c_str(), "-c"))) {
    	} else if ((case_insensitive_compare(arg_one.c_str(), "-s")) || (case_insensitive_compare(arg_one.c_str(), "--shared_memory"))){
    		gargoyle_pscand_data_base_shared_memory = DataBase::create();
    		gargoyleHandler.set_data_base_shared_memory(gargoyle_pscand_data_base_shared_memory);
    	}
    	else {
			std::cerr << std::endl << "Usage: ./gargoyle_pscand_pcap [-v | --version] [-s | --shared_memory]" << std::endl << std::endl;
    		return 0;
    	}
    }

	const char *gargoyle_debug_flag;
	gargoyle_debug_flag = getenv("GARGOYLE_DEBUG_FLAG");
	if (gargoyle_debug_flag != NULL) {
		DEBUG = true;
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
	try {
		if (!singleton()) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_pscand", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
			return 1;
		}
	} catch (std::runtime_error& e) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_pscand", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
		return 1;
	}

	/*
	 * Get location for the DB file
	 */
	const char *gargoyle_db_file;
	gargoyle_db_file = getenv("GARGOYLE_DB");
	if (gargoyle_db_file == NULL) {
		snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", GARGOYLE_DEFAULT_ROOT_PATH, DB_PATH);
	} else {
		snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", gargoyle_db_file);
	}

	if (!does_file_exist(DB_LOCATION)) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s - %s", DB_FILE_SYSLOG, DB_LOCATION, DOESNT_EXIST_SYSLOG, CANNOT_CONTINUE_SYSLOG);
		return 1;
	}

	if (DEBUG) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG, "Using DB:", DB_LOCATION);
	}

	// Get config data
	bool enforce_mode = true;
	size_t single_ip_scan_threshold = 0;
	size_t single_port_scan_threshold = 0;
	std::string ports_to_ignore;
	std::string hot_ports;

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
		hot_ports = cvv.get_hot_ports();

	} else {
		return 1;
	}

	gargoyle_blacklist_shm = SharedIpConfig::Create(GARGOYLE_BLACKLIST_SHM_NAME, GARGOYLE_BLACKLIST_SHM_SZ);

	// does iptables support xlock
	// 1 = true, 0 = false
	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();

	gargoyleHandler.set_iptables_supports_xlock(IPTABLES_SUPPORTS_XLOCK);
	gargoyleHandler.set_db_location(DB_LOCATION);
	gargoyleHandler.set_debug(DEBUG);

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

						if (start_port < end_port && start_port > 0 && start_port <= 65535) {

							//std::cout << start_port << std::endl;
							//std::cout << end_port << std::endl;
							for(int x = start_port; x <= end_port; x++)
								add_to_ports_entries(x);
						}
					} else {
						the_port = atoi(token1);
						if(the_port > 0 && the_port <= 65535) {
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
		syslog(LOG_INFO | LOG_LOCAL6, "%s - %s %s", GARGOYLE_PSCAND, "ignoring ports:", (ss.str().c_str()));
	}


	// process list of hot ports
	if (hot_ports.size() > 0) {
		// tokenize , delimited
		if (EPHEMERAL_LOW > 0 && EPHEMERAL_HIGH > 0) {

			const char *tok1 = ",";
			char *token1;
			char *token1_save;
			int the_port;
			char *ret_dash;

			token1 = strtok_r(&hot_ports[0], tok1, &token1_save);
			while (token1 != NULL) {

				/*
				 * look for dash and process this
				 * as a range of ports
				 */
				ret_dash = strstr(token1, "-");
				if (ret_dash) {

					int start_port = atoi(token1);
					int end_port = atoi(ret_dash + 1);

					if (start_port < end_port && start_port > 0 && start_port <= 65535) {
						for(int x = start_port; x <= end_port; x++) {
							//std::cout << x << std::endl;
							gargoyleHandler.add_to_hot_ports_list(x);
						}
					}
				} else {
					the_port = atoi(token1);
					if(the_port > 0 && the_port <= 65535) {
						if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
							//std::cout << the_port << std::endl;
							gargoyleHandler.add_to_hot_ports_list(the_port);
						}
					}
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}

	if(gargoyleHandler.get_type_data_base() == "shared_memory"){
		gargoyleHandler.sqlite_to_shared_memory();
	}

	get_blacklist_ip_addrs(enforce_mode);

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
		syslog(LOG_INFO | LOG_LOCAL6, "%s - %s %s", GARGOYLE_PSCAND, "ignoring IP addr's:", (ss.str().c_str()));
	}

	for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
		gargoyleHandler.add_to_white_listed_entries(*i);
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

	for (std::vector<int>::const_iterator i = IGNORE_PORTS.begin(); i != IGNORE_PORTS.end(); ++i) {
		gargoyleHandler.add_to_ports_entries(*i);
	}

	int rv, fd;
	char buf[4096] __attribute__ ((aligned));

	nfl_handle = nflog_open();
	if (!nfl_handle) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "Error obtaining netfilter log connection handle");
		return 1;
	}

	// unbinding existing nf_log handler for AF_INET (if any)
	if (nflog_unbind_pf(nfl_handle, AF_INET) < 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "Error unbinding the netfilter_log kernel logging backend");
		return 1;
	}

	// binding nfnetlink_log to AF_INET
	if (nflog_bind_pf(nfl_handle, AF_INET) < 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "Error binding the netfilter_log kernel logging backend");
		return 1;
	}

	// binding socket to group NFLOG_BIND_GROUP
	qh = nflog_bind_group(nfl_handle, NFLOG_BIND_GROUP);
	if (!qh) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %d", "Error aquiring handle for nflog group", NFLOG_BIND_GROUP);
		return 1;
	}

	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "Error setting packet copy mode");
		return 1;
	}

	// 128 * 1024 - max buffer size
	if (nflog_set_nlbufsiz(qh, 131072) < 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "Could not set group buffer size");
	    return 1;
	}

	fd = nflog_fd(nfl_handle);
	nflog_callback_register(qh, &GargoylePscandHandler::packet_handle, &gargoyleHandler);

	// main loop to get data via nflog
	//while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
	while (TEMP_FAILURE_RETRY((rv = recv(fd, buf, sizeof(buf), 0)))) {
		// handle message in packet that just arrived
		if (rv > 0)
			nflog_handle_packet(nfl_handle, buf, rv);
	}

	if (qh) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s: %d", "Unbinding from group", NFLOG_BIND_GROUP);
		nflog_unbind_group(qh);
	}

	if (nfl_handle) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s", "closing handle to NFLOG");
		nflog_close(nfl_handle);
	}

	graceful_exit(SIGINT);

	return 0;
}
