/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * main cleanup daemon
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
    
    char ip[16];
    std::cout << "ARGC " << argc << std::endl;
    if (argc == 2) {
    	
		if (validate_ip_addr(argv[1])) {
			
			strncpy(ip, argv[1], 15);
			ip[strlen(ip)] = '\0';
			
			std::cout << "IP addr: " << ip << std::endl;
			
			size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, ip);
			
			std::cout << "RuleIX: " << rule_ix << std::endl;
			
			if (rule_ix > 0 && ip) {
				
				iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix);
				
				int tstamp = (int) time(NULL);
				syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"", "manually unblocked", VIOLATOR_SYSLOG, ip, TIMESTAMP_SYSLOG, tstamp);

				/*
				// find the host ix for the ip
				int host_ix = get_host_ix(ip);
				std::cout << "Host ix: " << host_ix << std::endl;
				
				// find the row ix for this block
				int row_ix = get_detected_hosts_row_ix_by_host_ix(host_ix);
				std::cout << "Row ix: " << row_ix << std::endl;
						

				if (modify_host_set_processed_ix(row_ix) == 0) {
					iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix);
					
					int tstamp = (int) time(NULL);
					syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"", "manually unblocked", VIOLATOR_SYSLOG, ip, TIMESTAMP_SYSLOG, tstamp);

				}
				*/
			}
		}
    }
	return 0;
}
