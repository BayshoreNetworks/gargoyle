/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * controller code for handling ip addr actions
 *
 * Copyright (c) 2017 - 2018, Bayshore Networks, Inc.
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
#include <sstream>

#include <syslog.h>
#include <string>

#include "ip_addr_controller.h"
#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "shared_config.h"

int add_ip_to_hosts_table(const std::string &the_ip, const std::string &db_loc, bool debug, DataBase *data_base_shared_memory) {

	int added_host_ix;
	added_host_ix = 0;

	if (debug) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s", GARGOYLE_DEBUG, "Adding", the_ip.c_str(), "to DB: ", db_loc.c_str());
	}
	//std::cout << db_loc << std::endl;

	if (the_ip.size() > 0) {

		// add blacklisted ip to db
		/*
		 * if add_host is successful then it returns
		 * the ix of the DB row it added. Otherwise
		 * it returns 0 (zero) or -1. if -1 is returned then
		 * there is probably an existing record for the
		 * ip addr in question, so try to get its ix
		 * value via get_host
		 */
		if(data_base_shared_memory != nullptr){
			Hosts_Record record;
			record.ix = 0;
			strcpy(record.host, the_ip.c_str());
			time_t now = time(nullptr);
			record.first_seen = now;
			record.last_seen = now;
			// Return the state of this operation not the FK of the record if this has been inserted
			added_host_ix = data_base_shared_memory->hosts->INSERT(record);
			if(added_host_ix == 0){
				char result[SMALL_DEST_BUF];
				memset(result, 0, SMALL_DEST_BUF);
				string query = "SELECT ix FROM hosts_table WHERE host=" + the_ip;
				if((added_host_ix = data_base_shared_memory->hosts->SELECT(result, query)) != -1){
					added_host_ix = atol(result);
				}
			}
		}else{
			added_host_ix = sqlite_add_host(the_ip.c_str(), db_loc.c_str());
		}
		// already exists
		if (added_host_ix == -1) {
			// get existing index
			if(data_base_shared_memory != nullptr){
				char result[SMALL_DEST_BUF];
				memset(result, 0, SMALL_DEST_BUF);
				string query = "SELECT ix FROM hosts_table WHERE host=" + the_ip;
				if((added_host_ix = data_base_shared_memory->hosts->SELECT(result, query)) != -1){
					added_host_ix = atol(result);
				}
			}else{
				added_host_ix = sqlite_get_host_ix(the_ip.c_str(), db_loc.c_str());
			}
		}
	}
	return added_host_ix;
}


int do_block_actions(const std::string &the_ip,
		int detection_type,
		const std::string &db_loc,
		size_t iptables_xlock,
		bool do_enforce,
		void *g_shared_mem,
		bool debug,
		const std::string &config_file_id,
		DataBase *data_base_shared_memory
		) {

	int host_ix;
	host_ix = 0;

	if(data_base_shared_memory != nullptr){
		char result[SMALL_DEST_BUF];
		memset(result, 0, SMALL_DEST_BUF);
		string query = "SELECT ix FROM hosts_table WHERE host=" + the_ip;
		if((host_ix = data_base_shared_memory->hosts->SELECT(result, query)) != -1){
			host_ix = atol(result);
		}
	}else{
		host_ix = sqlite_get_host_ix(the_ip.c_str(), db_loc.c_str());
	}

	if (host_ix == 0)
		host_ix = add_ip_to_hosts_table(the_ip, db_loc, debug, data_base_shared_memory);

	if (debug) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %d", GARGOYLE_DEBUG, "Attempting to block:", the_ip.c_str(), "Host IX: ", host_ix);
	}
	//std::cout << "HOST IX: " << host_ix << std::endl;

	if (the_ip.size() > 0 and host_ix > 0) {

		// we dont ignore this ip if this returns 0
		//if (is_host_ignored(host_ix, db_loc.c_str()) == 0) {

		// if this ip is not whitelisted
		if (!is_white_listed(the_ip, g_shared_mem)) {

			size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, the_ip.c_str(), iptables_xlock);
			if (debug) {
				syslog(LOG_INFO | LOG_LOCAL6, "%s %s %zd %s %s", GARGOYLE_DEBUG, "Iptables rule IX: ", rule_ix, "in Chain: ", GARGOYLE_CHAIN_NAME);
			}
			/*
			 * if this ip does not exist in iptables ...
			 *
			 * this should negate the need to check the blacklist
			 * shared mem region because those ip's would have
			 * already been added to the chain in iptables
			 */
			if(!rule_ix > 0) {

				if (debug) {
					syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s", GARGOYLE_DEBUG, "IP: ", the_ip.c_str(), "does not exist in Chain: ", GARGOYLE_CHAIN_NAME);
				}

				/*
				 * ret should be 1 or 0 once iptables_add_drop_rule_to_chain
				 * gets called
				 *
				 */
				size_t ret = 5;
				int tstamp = (int) time(NULL);

				if (tstamp > 0) {

					/*
					 * queries DB table 'detected_hosts', a return of
					 * 0 (zero) means there is no entry in that DB table,
					 * anything else means there is an entry in that table.
					 * the assumption is that 'detected_hosts' is in sync
					 * with what is live in netfilter (via iptables)
					 *
					 * this check is necessary in order to not have duplicates
					 * in our iptables chain
					 */
					int ix;
					if(data_base_shared_memory != nullptr){
						char result[SMALL_DEST_BUF];
						memset(result, 0, SMALL_DEST_BUF);
						string query = "SELECT ix FROM detected_hosts WHERE host_ix=" + host_ix;
						if((ix = data_base_shared_memory->detected_hosts->SELECT(result, query)) != -1){
							ix = atol(result);
						}
					}else{
						ix = sqlite_is_host_detected(host_ix, db_loc.c_str());
					}
					if (do_enforce && ix == 0) {
						ret = iptables_add_drop_rule_to_chain(GARGOYLE_CHAIN_NAME, the_ip.c_str(), iptables_xlock);

						if (debug) {
							if (ret == 0) {
								syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s", GARGOYLE_DEBUG, "Added IP: ", the_ip.c_str(), "to Chain: ", GARGOYLE_CHAIN_NAME);
							} else {
								syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s", GARGOYLE_DEBUG, "IP: ", the_ip.c_str(), "not added to Chain: ", GARGOYLE_CHAIN_NAME);
							}
						}
					}

					// ret == 0 means ip has been added via iptables
					if (ret == 0) {

						if (detection_type > 0) {

							do_block_action_output(the_ip,
												detection_type,
												tstamp,
												config_file_id,
												do_enforce
												);

						} else {

							do_block_action_output(the_ip,
												0,
												tstamp,
												config_file_id,
												do_enforce
												);

						}

						// add to DB
						size_t adh;
						if(data_base_shared_memory != nullptr){
							Detected_Hosts_Record record;
							record.host_ix = host_ix;
							record.timestamp = tstamp;
							adh = data_base_shared_memory->detected_hosts->INSERT(record);
						}else{
							adh = sqlite_add_detected_host(host_ix, (size_t)tstamp, db_loc.c_str());
						}

						if (debug) {
							if (adh != 0) {
								syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s (%d) %s", GARGOYLE_DEBUG, "Error adding IP: ", the_ip.c_str(), host_ix, "to the detected_hosts table");
								return -1;
							} else {
								syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s (%d) %s", GARGOYLE_DEBUG, "Added IP: ", the_ip.c_str(), host_ix, "to the detected_hosts table");
							}
						}

					} else {
						return -1;
					}

				}

			} else {

				if (debug) {
					syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s %s %s", GARGOYLE_DEBUG, "Not adding: ", the_ip.c_str(), "to Chain: ", GARGOYLE_CHAIN_NAME);
				}
				return -1;

			}
		}
	}
	return host_ix;
}


int add_to_hosts_port_table(const std::string &the_ip,
	int the_port,
	int the_cnt,
	const std::string &db_loc,
	bool debug,
	DataBase *data_base_shared_memory){

	int host_ix;
	host_ix = 0;
	if(data_base_shared_memory != nullptr){
		char result[SMALL_DEST_BUF];
		memset(result, 0, SMALL_DEST_BUF);
		string query = "SELECT ix FROM hosts_table WHERE host=" + the_ip;
		if((host_ix = data_base_shared_memory->hosts->SELECT(result, query)) != -1){
			host_ix = atol(result);
		}
	}else{
		host_ix = sqlite_get_host_ix(the_ip.c_str(), db_loc.c_str());
	}

	if (host_ix == 0){
		host_ix = add_ip_to_hosts_table(the_ip, db_loc, debug, data_base_shared_memory);

	}
	//std::cout << "HOST IX: " << host_ix << std::endl;

	/*
	 * call get_host_port_hit to see if the ip addr/port combo
	 * already exists in the DB. if it does then call the update
	 * function, otherwise add the data into a new record
	 */
	if (host_ix > 0 && the_port > 0 && the_cnt > 0) {

		int resp;
		//number of hits registered in the DB
		if(data_base_shared_memory != nullptr){
			char query[SQL_CMD_MAX];
			sprintf(query, "SELECT hit_count FROM hosts_ports_hits WHERE host_ix=%d AND port_number=%d", host_ix, the_port);
			char result[SMALL_DEST_BUF];
			memset(result, 0, SMALL_DEST_BUF);
			if((resp = data_base_shared_memory->hosts_ports_hits->SELECT(result, query)) != -1){
				resp = atol(result);
			}
			Hosts_Ports_Hits_Record record;
			// new record
			if(resp == -1){
				record.ix = 0;
				record.host_ix = host_ix;
				record.port_number = the_port;
				record.hit_count = the_cnt;
				data_base_shared_memory->hosts_ports_hits->INSERT(record);
			}else if (resp >= 1) {
				int u_cnt = resp + the_cnt;
				record.host_ix = host_ix;
				record.port_number = the_port;
				record.hit_count = u_cnt;
				data_base_shared_memory->hosts_ports_hits->UPDATE(record);
			}
		}else{
			resp = sqlite_get_host_port_hit(host_ix, the_port, db_loc.c_str());
			// new record
			if (resp == 0) {
				sqlite_add_host_port_hit(host_ix, the_port, the_cnt, db_loc.c_str());
			} else if (resp >= 1) {
				int u_cnt = resp + the_cnt;
				sqlite_update_host_port_hit(host_ix, the_port, u_cnt, db_loc.c_str());
			}
		}

	}

	return 0;
}


void do_report_action_output(const std::string &the_ip,
		int the_port,
		int the_hits,
		int the_timestamp,
		int enforce_state) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\" %s=\"%d\" %s=\"%d\"",
			ACTION_SYSLOG, REPORT_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			PORT_SYSLOG, the_port, HITS_SYSLOG, the_hits,
			TIMESTAMP_SYSLOG, the_timestamp, ENFORCE_STATE_SYSLOG, enforce_state
			);

}


void do_block_action_output(const std::string &the_ip,
		int detection_type,
		int the_timestamp,
		const std::string &config_file_id,
		int enforce_state
		) {

	std::stringstream syslog_line;
	syslog_line << ACTION_SYSLOG << "=\"" << BLOCKED_SYSLOG << "\" "
				<< VIOLATOR_SYSLOG << "=\"" << the_ip << "\" "
				<< TIMESTAMP_SYSLOG << "=\"" << the_timestamp << "\"";

	if (detection_type > 0) {
		syslog_line << " " << DETECTION_TYPE_SYSLOG << "=\"" << detection_type << "\"";
	}

	if (config_file_id.size() > 0) {
		syslog_line << " " << CONFIG_SYSLOG << "=\"" << config_file_id << "\"";
	}

	syslog_line << " " << ENFORCE_STATE_SYSLOG << "=\"" << enforce_state << "\"";

	syslog(LOG_INFO | LOG_LOCAL6, "%s", syslog_line.str().c_str());

}


void do_unblock_action_output(const std::string &the_ip,
		int the_timestamp,
		int enforce_state
		) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\"",
			ACTION_SYSLOG, UNBLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			TIMESTAMP_SYSLOG, the_timestamp, ENFORCE_STATE_SYSLOG, enforce_state);

}


void do_remove_action_output(const std::string &the_ip,
		int the_timestamp,
		int first_seen,
		int last_seen,
		int enforce_state
		) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\" %s=\"%d\" %s=\"%d\"",
			ACTION_SYSLOG, REMOVE_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			FIRST_SEEN_SYSLOG, first_seen, LAST_SEEN_SYSLOG, last_seen,
			TIMESTAMP_SYSLOG, the_timestamp, ENFORCE_STATE_SYSLOG, enforce_state);

}


int do_host_remove_actions(const std::string &the_ip,
		int host_ix,
		const std::string &db_loc,
		int first_seen,
		int last_seen,
		DataBase *data_base_shared_memory){

	// delete all records for this host_ix from hosts_ports_hits table
	if(data_base_shared_memory != nullptr){
		string query = "DELETE FROM hosts_ports_hits WHERE host_ix=" + host_ix;
		data_base_shared_memory->hosts_ports_hits->DELETE(query);
	}else{
		sqlite_remove_host_ports_all(host_ix, db_loc.c_str());
	}
	/*
	 * is_host_detected = 0 means it is not actively blocked
	 *
	 * is_host_ignored = 0 means it is not white listed
	 * (not ignored)
	 *
	 * is_host_blacklisted - TODO
	 */
	/*
	 * 06/01/2017 - disabling the deletion of the
	 * ip addr row from hosts_table
	 *
	if (is_host_ignored(host_ix, db_loc.c_str()) == 0) {

		if (is_host_detected(host_ix, db_loc.c_str()) == 0) {

			// delete the host record
			remove_host(host_ix, db_loc.c_str());
			do_remove_action_output(the_ip, (int) time(NULL), first_seen, last_seen);

		}
	}
	*/

	return 0;
}


bool is_white_listed(const std::string &ip_addr, void *g_shared_config) {

	bool result = false;
	if (g_shared_config) {

		SharedIpConfig *g_shared_cfg = static_cast<SharedIpConfig *> (g_shared_config);

		//printf("------- Number of IP entries: %ld\n", g_shared_cfg->Size());

		//bool result;

		g_shared_cfg->Contains(ip_addr, &result);

		/*
		if(result) {
			printf("Found\n");
		} else {
			printf("Not Found\n");
		}
		*/

	}
	return result;
}


bool is_black_listed(const std::string &ip_addr, void *g_shared_config) {

	bool result = false;
	if (g_shared_config) {

		SharedIpConfig *g_shared_cfg = static_cast<SharedIpConfig *> (g_shared_config);

		g_shared_cfg->Contains(ip_addr, &result);
	}

	return result;
}


int do_black_list_actions(const std::string &ip_addr,
						void *g_shared_config,
						size_t iptables_xlock,
						int enforce_state
						) {

	/*
	 * actions:
	 *
	 * 	add to blacklist shared mem region
	 * 	add to iptables in GARGOYLE_CHAIN_NAME
	 *
	 */

	if (g_shared_config && ip_addr.size()) {

		SharedIpConfig *g_shared_cfg = static_cast<SharedIpConfig *> (g_shared_config);
		// add to shared mem region
		g_shared_cfg->Add(ip_addr);

		size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, ip_addr.c_str(), iptables_xlock);

		/*
		 * if this ip does not exist in iptables
		 *
		 */
		if(!rule_ix > 0) {

			// do block action - type 100
			iptables_add_drop_rule_to_chain(GARGOYLE_CHAIN_NAME, ip_addr.c_str(), iptables_xlock);

			do_block_action_output(ip_addr,
								100,
								(int)time(NULL),
								"",
								enforce_state
								);

		}
	}

	return 0;
}
