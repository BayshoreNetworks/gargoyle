/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
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





int add_ip_to_hosts_table(std::string the_ip, std::string db_loc) {

	int added_host_ix;
	added_host_ix = 0;
	
	std::cout << db_loc << std::endl;

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


int do_block_actions(std::string the_ip,
		int detection_type,
		std::string db_loc,
		size_t iptables_xlock,
		bool do_enforce) {

	int host_ix;
	host_ix = 0;
	
	std::cout << "YEAH BITCHES" << std::endl;

	
	host_ix = get_host_ix(the_ip.c_str(), db_loc.c_str());
	if (host_ix == 0)
		host_ix = add_ip_to_hosts_table(the_ip, db_loc);
	
	std::cout << "HOST IX: " << host_ix << std::endl;

	//syslog(LOG_INFO | LOG_LOCAL6, "%d-%s=\"%d\" %s=\"%d\"", ENFORCE, "host_ix", host_ix, "size", the_ip.size());

	if (the_ip.size() > 0 and host_ix > 0) {
		
		// we dont ignore this ip if this returns 0
		if (is_host_ignored(host_ix, db_loc.c_str()) == 0) {

			size_t ret;
			int tstamp = (int) time(NULL);
	
			if (do_enforce && is_host_detected(host_ix, db_loc.c_str()) == 0)
				ret = iptables_add_drop_rule_to_chain(GARGOYLE_CHAIN_NAME, the_ip.c_str(), iptables_xlock);
	
			if (detection_type > 0) {
				syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\" %s=\"%d\"",
						BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(), DETECTION_TYPE_SYSLOG,
						detection_type, TIMESTAMP_SYSLOG, tstamp);
			} else {
				syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"",
						BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(), TIMESTAMP_SYSLOG, tstamp);
			}
	
			// add to DB
			add_detected_host(host_ix, tstamp, db_loc.c_str());
		}
	}
	return host_ix;
}




