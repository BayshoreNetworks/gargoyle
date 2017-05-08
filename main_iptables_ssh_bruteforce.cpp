/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Program to detect and block SSH brute force attacks
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

/*
 * g++ -std=c++11 -o gargoyle_lscand_ssh_bruteforce main_iptables_ssh_bruteforce.cpp
 * 
 * To run:
 * 
 * ./gargoyle_lscand_ssh_bruteforce log_file regex_file num_hits num_seconds
 * 
 * Example:
 * 
 * ./gargoyle_lscand_ssh_bruteforce /var/log/auth.log lib/sshd_regexes 6 120
 * 
 * 
 * gotta figure out how to handle systemd log data, normal tail is
 * something like this:
 * 
 * 		sudo journalctl -f -u sshd
 * 
 */
#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <regex>
#include <vector>
#include <csignal>
#include <map>

#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ip_addr_controller.h"
#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"


char DB_LOCATION[SQL_CMD_MAX+1];

std::vector<std::string> sshd_regexes;
std::map<std::string, int[2]> IP_HITMAP;

size_t IPTABLES_SUPPORTS_XLOCK;


size_t get_regexes(const char *fname) {
	
	std::string line;
	std::ifstream infile(fname);
	
	if(infile) {
		while(getline(infile, line)) {
			if (line.size() > 2)
				sshd_regexes.push_back(line);
		}
		return 0;
	} else {
		return 1;
	}
}


void signal_handler( int signum ) {

   syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);

   // terminate program
   exit(signum);  

}


bool validate_ip_address(const std::string &ip_address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_address.c_str(), &(sa.sin_addr));
    return result != 0;
}


int handle_log_line(std::string line) {
	
	std::smatch match;
	/*
	 * handle instant block regexes first
	 */
	std::regex invalid_user("[iI](?:llegal|nvalid) user .* from (.*)\\s*");
	std::regex max_exceeded("error: maximum authentication attempts exceeded for .* from (.*) port");
	// fatal: Unable to negotiate with 103.207.39.148 port 56169: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
	std::regex bad_algo("Unable to negotiate with (.*) port");

	//if (std::regex_search(line, match, invalid_user) && match.size() == 2) {
	if (std::regex_search(line, match, max_exceeded) && match.size() == 2) {
		
		std::string ip_addr = match.str(1);
		
		// if we are here then do an instant block because sshd already did
		// the work for us of detecting too many login attempts
		
		//std::cout << "TESTING MAX EXCEEDED" << std::endl;
		//std::cout << "INSTANT BLOCK HERE - " << ip_addr << std::endl;

		if (validate_ip_address(ip_addr)) {
			
			do_block_actions(ip_addr, 50, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, true);
			
		}

		return 0;
		
	} else if (std::regex_search(line, match, invalid_user) && match.size() == 2) {

		std::string ip_addr = match.str(1);
		
		//std::cout << "TESTING INVALID USER" << std::endl;

		if (validate_ip_address(ip_addr)) {

			/*
			 * even if the SSH port isnt 22 it doesnt matter so
			 * we will just use it as the default. The goal here
			 * is to put enough real data in to the hosts_port_hits
			 * so that if relevant the gargoyle analysis process
			 * can detecte slow and low attacks that go under this
			 * radar
			 */
			add_to_hosts_port_table(ip_addr, 22, 1, DB_LOCATION);
			
		}
		
		return 0;						
		
	} else if (std::regex_search(line, match, bad_algo) && match.size() == 2) {
		
		std::string ip_addr = match.str(1);
		
		//std::cout << "TESTING BAD ALGO" << std::endl;

		if (validate_ip_address(ip_addr)) {
			
			add_to_hosts_port_table(ip_addr, 22, 1, DB_LOCATION);
			
		}
		
		return 0;	

	} else {

		for(std::vector<std::string>::iterator it = sshd_regexes.begin(); it != sshd_regexes.end(); ++it) {
			
			/* std::cout << *it; ... */
			std::regex testreg(*it);
			
			//std::cout << "SZ: " << match.size() << std::endl;
			
			//if (std::regex_search(line, match, testreg) && match.size() > 1) {
			if (std::regex_search(line, match, testreg) && match.size() == 2) {

				std::string ip_addr = match.str(1);
				if (validate_ip_address(ip_addr)) {

					std::map<std::string, int[2]>::iterator it = IP_HITMAP.find(ip_addr);
					
					if(it != IP_HITMAP.end()) {
															
						// element exists
							
						IP_HITMAP[ip_addr][1] = IP_HITMAP[ip_addr][1] + 1;
						
						add_to_hosts_port_table(ip_addr, 22, 1, DB_LOCATION);

					} else {
							
						IP_HITMAP[ip_addr][0] = (int) time(NULL);
						IP_HITMAP[ip_addr][1] = 1;
						
						add_to_hosts_port_table(ip_addr, 22, 1, DB_LOCATION);

					}
				}
				break;
			}
		}
	}
}



int main(int argc, char *argv[])
{

	// register signal SIGINT and signal handler  
	signal(SIGINT, signal_handler);
	signal(SIGKILL, signal_handler);
	
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
	
	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();

    /*
     * 0 - prog name
     * 1 - log file to be scanned
     * 2 - regex file name
     * 3 - number of hits
     * 4 - time frame
     */
	if (argc == 5) {
	
		std::ifstream ifs(argv[1]);
		// default = 6
		size_t num_hits = atoi(argv[3]);
		// default = 120
		size_t num_seconds = atoi(argv[4]);
		// populate vector sshd_regexes with regex strings
		get_regexes(argv[2]);
		

		/*
		for(std::vector<std::string>::iterator iit = sshd_regexes.begin(); iit != sshd_regexes.end(); ++iit)
		    std::cout << *iit << std::endl;
		*/
		if (ifs.is_open()) {
			
			std::string line;
			while (true) {

				while (std::getline(ifs, line)) {
					
					//std::cout << line << std::endl;
					handle_log_line(line);

				}
				
				if (!ifs.eof()) {
					break;
				}
				ifs.clear();
	
				// sleep here to avoid being a CPU hog.
				std::this_thread::sleep_for (std::chrono::seconds(3));
				
				
				for (const auto &p : IP_HITMAP) {
					
				    //std::cout << "[" << p.first << "] = " << IP_HITMAP[p.first][0] << " - " << IP_HITMAP[p.first][1] << std::endl << std::endl;
				    
				    std::string ip_addr = p.first;
				    int now = (int) time(NULL);
				    int now_delta = now - IP_HITMAP[p.first][0];
				    int l_num_hits = IP_HITMAP[p.first][1];
				    
				    //std::cout << "PAST THRESH? NOW DELTA: " << now_delta << ", NUM SEC: " << num_seconds << std::endl;
				    
				    if (now_delta > (num_seconds * 3)) {
				    	
				    	if (l_num_hits >= (num_hits * 2)) {
				    		
				    		do_block_actions(ip_addr, 50, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, true);
				    	
				    	}
				    	
				    	IP_HITMAP.erase(ip_addr);

				    } else if (now_delta <= num_seconds) {
				    
				    	if (l_num_hits >= num_hits) {

				    		do_block_actions(ip_addr, 50, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, true);
				    		IP_HITMAP.erase(ip_addr);
				    		
				    	}
				    }
				}
			}
		}
	}
    return 0;
}
