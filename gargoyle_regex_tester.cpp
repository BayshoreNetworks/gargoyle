/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * Program to test a given regex against a set of log data
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
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <algorithm>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "config.h"

#ifdef USE_LIBPCRECPP
#include <pcrecpp.h>
#else
#include <regex>
#endif

#include "system_functions.h"


//std::vector<std::string> sshd_regexes;
size_t line_sz = 2048;
size_t line_cnt = 0;
size_t regex_num_hits = 0;
size_t valid_ip_addr_cnt = 0;
std::vector<std::string> valid_ip_addr;


bool validate_ip_address(const std::string &);
bool valid_ip_addr_exists(const std::string &);
std::string hunt_for_ip_addr(std::string);
#ifndef USE_LIBPCRECPP
void do_regex_check(const std::string &, const std::regex &);
#else
void do_regex_check(const std::string &line, pcrecpp::RE &);
#endif
void add_valid_ip_addr(const std::string &);
void display_valid_ip_addr();



bool validate_ip_address(const std::string &ip_address) {
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip_address.c_str(), &(sa.sin_addr));
	return result != 0;
}


bool valid_ip_addr_exists(const std::string& ip_addr) {
	if(std::find(valid_ip_addr.cbegin(), valid_ip_addr.cend(), ip_addr) != valid_ip_addr.cend())
		return true;
	return false;
}


std::string hunt_for_ip_addr(const std::string &line, const char& c) {

	std::string resp = "";
	std::string buff{""};

	for(auto n:line)
	{
		if(n != c) {
			buff+=n;
		} else {
			if(n == c && buff != "") { 
				if (validate_ip_address(buff))
					return buff;
				buff = "";
			}
		}
	}
	return resp;
}


#ifndef USE_LIBPCRECPP
void do_regex_check(const std::string &line, const std::regex &l_regex) {
#else
void do_regex_check(const std::string &line, pcrecpp::RE &l_regex) {
#endif

	std::string ip_addr;
	
	line_cnt++;

#ifndef USE_LIBPCRECPP
	std::smatch match;
	
	if (std::regex_search(line, match, l_regex)) {
#else
	if (l_regex.PartialMatch(line, &ip_addr)) {
#endif

		regex_num_hits++;
		/*
		std::cout << "MATCH SIZE: " << match.size() << std::endl;
		std::cout << "MATCH 0: " << match.str(0) << std::endl;
		std::cout << "MATCH 1: " << match.str(1) << std::endl;
		*/
#ifndef USE_LIBPCRECPP
		ip_addr = match.str(1);
#endif
		//std::cout << "IP: " << ip_addr << std::endl;
		
		if (validate_ip_address(ip_addr)) {

			//std::cout << "VALID IP ADDR MATCH: " << ip_addr << std::endl;
			add_valid_ip_addr(ip_addr);
			valid_ip_addr_cnt++;

		} else {
			
			std::string hip = hunt_for_ip_addr(ip_addr, ' ');

			// the hack found an ip addr
			if (hip.size()) {
				
				//std::cout << "HIP IP ADDR MATCH: " << hip << std::endl;
				if (validate_ip_address(hip)) {
					
					//std::cout << "VALID IP ADDR MATCH [HIP]: " << hip << std::endl;
					add_valid_ip_addr(hip);
					valid_ip_addr_cnt++;
					
				}
			
			}
			
		}

	} else {
		
		//std::cout << "No regex hit" << std::endl;
		
	}
	
	//std::cout << std::endl;
	
}


void add_valid_ip_addr(const std::string &ip_addr) {
	
	if (!valid_ip_addr_exists(ip_addr))
		valid_ip_addr.push_back(ip_addr);
	
}


void display_valid_ip_addr() {
	
	std::cout << "Unique list of valid IP ADDRs discovered:" << std::endl << "-----------------" << std::endl;
	for (auto& it : valid_ip_addr) {
		std::cout << it << std::endl;
	}
	
}


int main(int argc, char *argv[]) {
	
	std::string log_entity = "";
	std::string regex_str = "";
	int c;
	bool using_file = false;
	
	while ((c = getopt(argc, argv, "r:l:")) != -1)
		switch (c) {
		case 'r':
			regex_str = optarg;
			break;
		case 'l':
			log_entity = optarg;
			break;
		case '?':
			std::cout << std::endl << "Problem with args dude ..." << std::endl << std::endl;
			break;
		}
	
	/*
	std::cout << std::endl;
	std::cout << log_entity << std::endl;
	std::cout << regex_str << std::endl;
	
	std::cout << std::endl;
	*/
	
	if (does_file_exist(log_entity.c_str())) {
		using_file = true;
	}
	

	// if file ....
	//std::ifstream ifs(log_entity.c_str(), std::ios::ate);
    // remember file position
    //std::ios::streampos gpos = ifs.tellg();

    std::string line;

#ifndef USE_LIBPCRECPP
	
	try {
		
		std::regex l_regex(regex_str);
#else
		pcrecpp::RE l_regex(regex_str);
#endif
		
		// working with one target string, not file
		if (!using_file) {
			
			do_regex_check(log_entity, l_regex);
		
		} else {
			
			// iterate on file line by line
			std::ifstream inf(log_entity);
			
			if(!inf) {
				std::cout << std::endl << "Cannot open input file: " << log_entity << std::endl << std::endl;
				return 1;
			}
			
			char str[line_sz];
			
			while(inf) {
				inf.getline(str, line_sz);
				if(inf) {
				
					do_regex_check(str, l_regex);
					//std::cout << str << std::endl;
					
				}
			}
			
			inf.close();
		}

#ifndef USE_LIBPCRECPP
	} catch (std::regex_error& e) {
		
		std::cout << std::endl << "Regex exception: " << e.what() << std::endl;
		std::cout << "Regex exception code is: " << e.code() << std::endl;
		std::cout << "Cannot continue ..." << std::endl << std::endl;
		return 1;
		
	}
#endif

	std::cout << std::endl << "Results" << std::endl << "=======" << std::endl << std::endl;
	
	std::cout << "Entity scanned is a ";
	if (using_file)
		std::cout << "file named ";
	else
		std::cout << "string: ";
	std::cout << "\"" << log_entity << "\"" << std::endl;
	
	if (using_file) {
		std::cout << line_cnt << " lines were consumed and scanned" << std::endl;
	}
	
	std::cout << "Regex used: " << regex_str << std::endl;
	std::cout << "Number of hits for this regex: " << regex_num_hits << std::endl;
	std::cout << "Number of valid IP ADDRs from regex hits: " << valid_ip_addr_cnt << std::endl;
	
	std::cout << std::endl;
	if (valid_ip_addr.size()) {
		display_valid_ip_addr();
	}
	std::cout << std::endl << std::endl;
	
	return 0;
}






