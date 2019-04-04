/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * ip addr removal from blacklist
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

char DB_LOCATION[SQL_CMD_MAX+1];
SharedIpConfig *gargoyle_blacklist_removal_shm = NULL;
size_t IPTABLES_SUPPORTS_XLOCK;
DataBase *data_base_shared_memory_analysis = nullptr;

bool validate_ip_addr(std::string ip_addr)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_addr.c_str(), &(sa.sin_addr));
    return result != 0;
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

    } else {
        return 1;
    }

	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();
	gargoyle_blacklist_removal_shm = SharedIpConfig::Create(GARGOYLE_BLACKLIST_SHM_NAME, GARGOYLE_BLACKLIST_SHM_SZ);
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
			std::cout << std::endl << "Usage: ./gargoyle_pscand_remove_from_whitelist [-s | --shared_memory] <ip_addr> " << std::endl << std::endl;
			exit(1);
	}

	if (validate_ip_addr(ip)) {

		if (DEBUG)
			std::cout << "IP addr: " << ip << std::endl;

		if (strcmp(ip, "") != 0) {

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
				int result;
				char buffer[SMALL_DEST_BUF];
				memset(buffer, 0, SMALL_DEST_BUF);
				if(data_base_shared_memory_analysis != nullptr){
					string query = "SELECT host_ix FROM black_ip_list WHERE host_ix=" + host_ix;
					if((result = data_base_shared_memory_analysis->black_ip_list->SELECT(buffer, query)) != -1){
						result = atoi(buffer);
					}
				}else{
					result = sqlite_is_host_blacklisted(host_ix, DB_LOCATION);
				}

				if (result > 0) {

					// remove from iptables
					size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, ip, IPTABLES_SUPPORTS_XLOCK);
					if(rule_ix > 0) {

						// delete rule from chain
						iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix, IPTABLES_SUPPORTS_XLOCK);

						do_unblock_action_output(ip, (int) time(NULL), ENFORCE);
					}

					// remove from DB
					if(data_base_shared_memory_analysis != nullptr){
						string query = "DELETE FROM black_ip_list WHERE host_ix=" + host_ix;
						data_base_shared_memory_analysis->black_ip_list->DELETE(query);
					}else{
						sqlite_remove_host_from_blacklist(host_ix, DB_LOCATION);
					}

					// remove from shared mem region
					gargoyle_blacklist_removal_shm->Remove(string(ip));

				}
			}
		}
	}

    if(gargoyle_blacklist_removal_shm) {
        delete gargoyle_blacklist_removal_shm;
        //gargoyle_blacklist_removal_shm;
    }

    if(data_base_shared_memory_analysis != nullptr){
		delete data_base_shared_memory_analysis;
    }

	return 0;
}
