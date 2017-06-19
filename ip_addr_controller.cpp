/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * controller code for handling ip addr actions
 *
 * Copyright (c) 2017, Bayshore Networks, Inc.
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

#include <syslog.h>

#include "ip_addr_controller.h"
#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "gargoyle_config_vals.h"
#include "shared_config.h"


int add_ip_to_hosts_table(const std::string &the_ip, const std::string &db_loc) {

	int added_host_ix;
	added_host_ix = 0;
	
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
		added_host_ix = add_host(the_ip.c_str(), db_loc.c_str());
		// already exists
		if (added_host_ix == -1) {
			// get existing index
			added_host_ix = get_host_ix(the_ip.c_str(), db_loc.c_str());
		}
	}
	return added_host_ix;
}


int do_block_actions(const std::string &the_ip,
		int detection_type,
		const std::string &db_loc,
		size_t iptables_xlock,
		bool do_enforce,
		void *g_shared_mem) {

	int host_ix;
	host_ix = 0;
	
	host_ix = get_host_ix(the_ip.c_str(), db_loc.c_str());
	if (host_ix == 0)
		host_ix = add_ip_to_hosts_table(the_ip, db_loc);
	
	//std::cout << "HOST IX: " << host_ix << std::endl;

	if (the_ip.size() > 0 and host_ix > 0) {
		
		// we dont ignore this ip if this returns 0
		//if (is_host_ignored(host_ix, db_loc.c_str()) == 0) {
		
		// if this ip is not whitelisted
		if (!is_white_listed(the_ip, g_shared_mem)) {

			size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, the_ip.c_str(), iptables_xlock);
			/*
			 * if this ip does not exist in iptables ...
			 * 
			 * this should negate the need to check the blacklist
			 * shared mem region because those ip's would have
			 * already been added to the chain in iptables
			 */
			if(!rule_ix > 0) {
			
				size_t ret;
				int tstamp = (int) time(NULL);
		
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
				if (do_enforce && is_host_detected(host_ix, db_loc.c_str()) == 0)
					ret = iptables_add_drop_rule_to_chain(GARGOYLE_CHAIN_NAME, the_ip.c_str(), iptables_xlock);
		
				if (detection_type > 0) {
	
					do_block_action_output(the_ip, detection_type, tstamp);
					
				} else {
	
					do_block_action_output(the_ip, 0, tstamp);
					
				}
		
				// add to DB
				add_detected_host(host_ix, tstamp, db_loc.c_str());
			
			}
		}
	}
	return host_ix;
}


int add_to_hosts_port_table(const std::string &the_ip, int the_port, int the_cnt, const std::string &db_loc) {
	
	int host_ix;
	host_ix = 0;
	
	host_ix = get_host_ix(the_ip.c_str(), db_loc.c_str());
	if (host_ix == 0)
		host_ix = add_ip_to_hosts_table(the_ip, db_loc);
	
	//std::cout << "HOST IX: " << host_ix << std::endl;

	/*
	 * call get_host_port_hit to see if the ip addr/port combo
	 * already exists in the DB. if it does then call the update
	 * function, otherwise add the data into a new record
	 */
	if (host_ix > 0 && the_port > 0 && the_cnt > 0) {

		int resp;
		//number of hits registered in the DB
		resp = get_host_port_hit(host_ix, the_port, db_loc.c_str());

		// new record
		if (resp == 0) {
			add_host_port_hit(host_ix, the_port, the_cnt, db_loc.c_str());
		} else if (resp >= 1) {
			int u_cnt = resp + the_cnt;
			update_host_port_hit(host_ix, the_port, u_cnt, db_loc.c_str());
		}
	}
	
	return 0;
}


void do_report_action_output(const std::string &the_ip,
		int the_port,
		int the_hits,
		int the_timestamp) {
	
	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\" %s=\"%d\"",
			ACTION_SYSLOG, REPORT_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			PORT_SYSLOG, the_port, HITS_SYSLOG, the_hits, TIMESTAMP_SYSLOG, the_timestamp);

}


void do_block_action_output(const std::string &the_ip,
		int detection_type,
		int the_timestamp) {
	
	if (detection_type > 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\"",
				ACTION_SYSLOG, BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
				DETECTION_TYPE_SYSLOG, detection_type, TIMESTAMP_SYSLOG, the_timestamp);
	} else {
		syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\"",
				ACTION_SYSLOG, BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(), TIMESTAMP_SYSLOG, the_timestamp);
	}

}


void do_unblock_action_output(const std::string &the_ip, int the_timestamp) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\"",
			ACTION_SYSLOG, UNBLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			TIMESTAMP_SYSLOG, the_timestamp);

}


void do_remove_action_output(const std::string &the_ip,
		int the_timestamp,
		int first_seen,
		int last_seen) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%s\" %s=\"%d\" %s=\"%d\" %s=\"%d\"",
			ACTION_SYSLOG, REMOVE_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(),
			FIRST_SEEN_SYSLOG, first_seen, LAST_SEEN_SYSLOG, last_seen,
			TIMESTAMP_SYSLOG, the_timestamp);

}


int do_host_remove_actions(const std::string &the_ip,
		int host_ix,
		const std::string &db_loc,
		int first_seen,
		int last_seen) {
	
	// delete all records for this host_ix from hosts_ports_hits table
	remove_host_ports_all(host_ix, db_loc.c_str());
	
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


int do_black_list_actions(const std::string &ip_addr, void *g_shared_config, size_t iptables_xlock) {
	
	/*
	 * actions:
	 * 
	 * 	add to blacklist shared mem region
	 * 	add to iptables in GARGOYLE_CHAIN_NAME
	 */
	
	if (g_shared_config && ip_addr.size() && !is_black_listed(ip_addr, g_shared_config)) {
		
		SharedIpConfig *g_shared_cfg = static_cast<SharedIpConfig *> (g_shared_config);
		// add to shared mem region
		g_shared_cfg->Add(ip_addr);
		
		size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, ip_addr.c_str(), iptables_xlock);
		/*
		 * if this ip does not exist in iptables
		 */
		if(!rule_ix > 0) {
			
			// do block action - type 100
			iptables_add_drop_rule_to_chain(GARGOYLE_CHAIN_NAME, ip_addr.c_str(), iptables_xlock);
		
			do_block_action_output(ip_addr, 100, (int)time(NULL));
		}
	}
	
	return 0;
}
