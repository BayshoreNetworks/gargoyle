/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * ip addr removal/cleanup prog
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
#include <arpa/inet.h>

#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "singleton.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "ip_addr_controller.h"
#include "shared_config.h"
#include "system_functions.h"
#include "data_base.h"
#include "string_functions.h"

bool DEBUG = false;
bool ENFORCE = true;
size_t IPTABLES_SUPPORTS_XLOCK;

char DB_LOCATION[SQL_CMD_MAX+1];
SharedIpConfig *gargoyle_monitor_blacklist_shm = NULL;
SharedIpConfig *gargoyle_whitelist_shm = nullptr;
DataBase *data_base_shared_memory_analysis = nullptr;

bool validate_ip_addr(std::string ip_addr)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_addr.c_str(), &(sa.sin_addr));
    return result != 0;
}

void insert_ignore_ip_table(int host_ix, size_t tstamp, char *ip){
	if(data_base_shared_memory_analysis != nullptr){
		Ignore_IP_List_Record record;
		record.host_ix = host_ix;
		record.timestamp = tstamp;
		data_base_shared_memory_analysis->ignore_ip_list->INSERT(record);
	}else{
		sqlite_add_host_to_ignore(host_ix, tstamp, DB_LOCATION);
	}
	gargoyle_whitelist_shm->Add(string(ip));
}

void reset_last_seen_host_table(int host_ix, int last_seen){
	// reset last_seen to 1972
	if(data_base_shared_memory_analysis != nullptr){
		Hosts_Record record;
		record.ix = host_ix;
		record.last_seen = last_seen;
		data_base_shared_memory_analysis->hosts->UPDATE(record);
	}else{
		sqlite_update_host_last_seen(host_ix, DB_LOCATION);
	}
}

int main(int argc, char *argv[])
{

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
        snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", GARGOYLE_DEFAULT_ROOT_PATH, DB_PATH);
	} else {
		snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", gargoyle_db_file);
	}

    if (!does_file_exist(DB_LOCATION)) {
        syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s - %s", DB_FILE_SYSLOG, DB_LOCATION, DOESNT_EXIST_SYSLOG, CANNOT_CONTINUE_SYSLOG);
        return 1;
    }

    const char *config_file;
    config_file = getenv("GARGOYLE_CONFIG");
    if (config_file == NULL)
        config_file = ".gargoyle_config";

    ConfigVariables cvv;
    if (cvv.get_vals(config_file) == 0) {
        ENFORCE = cvv.get_enforce_mode();
		set_sqlite_properties(cvv.get_sqlite_locked_try_for_time());
    } else {
		std::cout << std::endl << "File .gargoyle_config not exist in " << config_file << std::endl << std::endl;
        return 1;
    }

    char ip[16];

    if (DEBUG)
    	std::cout << "ARGC " << argc << std::endl;

	switch(argc){
		case 2:
			strncpy(ip, argv[1], 15);
			ip[strlen(argv[1])] = '\0';
			break;
		case 3:
			if((case_insensitive_compare(argv[1], "-s")) || (case_insensitive_compare(argv[1], "--shared_memory"))){
				data_base_shared_memory_analysis = DataBase::create();
				strncpy(ip, argv[2], 15);
				ip[strlen(argv[2])] = '\0';
				break;
			}
		default:
			std::cout << std::endl << "Usage: ./gargoyle_pscand_unblockip [-s | --shared_memory ] <ip_addr>" << std::endl << std::endl;
			exit(1);
	}

	gargoyle_whitelist_shm = SharedIpConfig::Create(GARGOYLE_WHITELIST_SHM_NAME, GARGOYLE_WHITELIST_SHM_SZ);

	if (validate_ip_addr(ip)) {

		/*
		 * if this ip is blacklisted leave it alone
		 */
		if (!is_black_listed(ip, (void *)gargoyle_monitor_blacklist_shm)) {


			if (DEBUG)
				std::cout << "IP addr: " << ip << std::endl;

			size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, ip, IPTABLES_SUPPORTS_XLOCK);

			if (DEBUG)
				std::cout << "RuleIX: " << rule_ix << std::endl;

			if (rule_ix > 0 && strcmp(ip, "") != 0) {

				// find the host ix for the ip
				int host_ix;
				if(data_base_shared_memory_analysis != nullptr){
					char result[SMALL_DEST_BUF];
					memset(result, 0, SMALL_DEST_BUF);
					string query = "SELECT ix FROM hosts_table WHERE host=" + string(ip);
					if((host_ix = data_base_shared_memory_analysis->hosts->SELECT(result, query)) != -1){
						host_ix = atol(result);
					}
				}else{
					host_ix = sqlite_get_host_ix(ip, DB_LOCATION);
				}

				if (host_ix > 0) {

					// find the row ix for this host (in detected_hosts table)
					size_t row_ix;
					if(data_base_shared_memory_analysis != nullptr){
						string query = "SELECT ix FROM detected_hosts WHERE host_ix=" + host_ix;
						char result[SMALL_DEST_BUF];
						memset(result, 0, SMALL_DEST_BUF);
						if((row_ix = data_base_shared_memory_analysis->detected_hosts->SELECT(result, query)) != -1){
							row_ix = atol(result);
						}

					}else{
						row_ix = sqlite_get_detected_hosts_row_ix_by_host_ix(host_ix, DB_LOCATION);
					}

					if (row_ix > 0) {

						if (DEBUG)
							std::cout << "Host ix: " << host_ix << std::endl;
						// delete all records for this host_ix from hosts_ports_hits table
						size_t rhpa;
						if(data_base_shared_memory_analysis != nullptr){
							string query ="DELETE FROM hosts_ports_hits WHERE host_ix=" + host_ix;
							rhpa = data_base_shared_memory_analysis->hosts_ports_hits->DELETE(query);
						}else{
							rhpa = sqlite_remove_host_ports_all(host_ix, DB_LOCATION);
						}

						if (rhpa == 2) {

							int rhpa_i;
							for (rhpa_i = 0; rhpa_i < SQL_FAIL_RETRY; rhpa_i++) {
								rhpa = sqlite_remove_host_ports_all(host_ix, DB_LOCATION);
								if (rhpa == 2) {
									continue;
								}
								if (rhpa == 0) {
									break;
								}
							}
						}

						if (DEBUG)
							std::cout << "Row ix: " << row_ix << std::endl;
						// delete row from detected_hosts
						if(data_base_shared_memory_analysis != nullptr){
							string query = "DELETE FROM detected_hosts WHERE ix=" + row_ix;
							data_base_shared_memory_analysis->detected_hosts->DELETE(query);
						}else{
							sqlite_remove_detected_host(row_ix, DB_LOCATION);
						}

						//int tstamp = (int) time(NULL);
						time_t t_now = time(NULL);

						if (t_now > 0) {

							size_t tstamp = t_now;

							// add to ignore ip table
							if(data_base_shared_memory_analysis != nullptr){
								Ignore_IP_List_Record record;
								record.host_ix = host_ix;
								record.timestamp = tstamp;
								data_base_shared_memory_analysis->ignore_ip_list->INSERT(record);
							}else{
								sqlite_add_host_to_ignore(host_ix, tstamp, DB_LOCATION);
							}

							// reset last_seen to 1972
							if(data_base_shared_memory_analysis != nullptr){
								Hosts_Record record;
								record.ix = host_ix;
								// 01/01/1972 00:00:00 UTC
								record.last_seen = 63072000;
								data_base_shared_memory_analysis->hosts->UPDATE(record);
							}else{
								sqlite_update_host_last_seen(host_ix, DB_LOCATION);
							}

							iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix, IPTABLES_SUPPORTS_XLOCK);

							do_unblock_action_output(ip, (int) tstamp, ENFORCE);
						}
					}
				}
			}
			/*
			 * GARG-82 -> We also want to be able to whitelist an ip address that has not been seen before
			 * (not only when this IP is blocked (IPTables) and we want to whitelisted)
			 */
			int ix_hosts_table = add_ip_to_hosts_table(ip, DB_LOCATION, DEBUG, data_base_shared_memory_analysis);
			time_t t_now = time(nullptr);
			if(ix_hosts_table > 0 && t_now > 0){
				insert_ignore_ip_table(ix_hosts_table, t_now, ip);
				// reset last_seen to 1972 01/01/1972 00:00:00 UTC -> 63072000
				reset_last_seen_host_table(ix_hosts_table, 63072000);
			}
		}
	}

    if(gargoyle_monitor_blacklist_shm) {
        delete gargoyle_monitor_blacklist_shm;
        //gargoyle_monitor_blacklist_shm;
    }

    if(gargoyle_whitelist_shm != nullptr) {
        delete gargoyle_whitelist_shm;
    }

    delete_sqlite_properties();

	return 0;
}
