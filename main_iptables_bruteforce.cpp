/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Program to detect and block based on regex and log data
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
#include <sys/stat.h>

#include "ip_addr_controller.h"
#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "system_functions.h"
#include "shared_config.h"


char DB_LOCATION[SQL_CMD_MAX+1];
bool ENFORCE = true;
bool ENABLED = false;
bool DEBUG = false;
//bool DEBUG = true;
int BUF_SZ = 512;

std::vector<std::string> sshd_regexes;
std::map<std::string, int[2]> IP_HITMAP;

size_t IPTABLES_SUPPORTS_XLOCK;
size_t ITER_CNT_MAX = 50;
static int last_position = 0;

SharedIpConfig *gargoyle_bf_whitelist_shm = NULL;

size_t get_regexes(const char *);
void signal_handler(int);
bool validate_ip_address(const std::string &);
int handle_log_line(const std::string &, const std::string &);
void process_iteration(int, int, const std::string &);
std::string hunt_for_ip_addr(std::string);
void handle_ip_addr(const std::string &);
void display_map();


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


void signal_handler(int signum) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);

    if(gargoyle_bf_whitelist_shm) {
        delete gargoyle_bf_whitelist_shm;
        //gargoyle_bf_whitelist_shm;
    }

	// terminate program
	exit(0);

}



bool validate_ip_address(const std::string &ip_address) {
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ip_address.c_str(), &(sa.sin_addr));
	return result != 0;
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


void display_map() {

	for (const auto &p : IP_HITMAP) {

		/*
		 * [232.234.67.22] = 1501791934 - 3
		 *
		 * ip_addr
		 * first seen timestamp
		 * number of hits
		 *
		 */
		std::cout << "[" << p.first << "] = " << IP_HITMAP[p.first][0] << " - " << IP_HITMAP[p.first][1] << std::endl;

	}

	std::cout << endl;
}


void process_iteration(int num_seconds, int num_hits, const std::string &config_file) {

	for (const auto &p : IP_HITMAP) {

		std::string ip_addr = p.first;
		int now = (int)time(NULL);

		int original_timestamp = IP_HITMAP[p.first][0];
		int now_delta = now - original_timestamp;
		int l_num_hits = IP_HITMAP[p.first][1];


		std::cout << original_timestamp << " -- " << now << std::endl;
		std::cout << "[" << p.first << "]" << std::endl << "Delta: " << now_delta << std::endl << "Hits: " << IP_HITMAP[p.first][1] << std::endl << std::endl;


		// delta longer than num_seconds - just cleanup
		if (now_delta > num_seconds) {

			IP_HITMAP.erase(ip_addr);
			continue;

		}

		// delta is in range
		if (now_delta <= num_seconds) {

			// block based purely on number of hits
			if (l_num_hits >= num_hits) {

				do_block_actions(ip_addr,
					51,
					DB_LOCATION,
					IPTABLES_SUPPORTS_XLOCK,
					ENFORCE,
					(void *) gargoyle_bf_whitelist_shm,
					DEBUG,
					config_file
				);
				IP_HITMAP.erase(ip_addr);
				continue;

			}

		}

		// fuck time, if we see this many hits we block
		if (l_num_hits >= (num_hits * 2)) {

			do_block_actions(ip_addr,
				51,
				DB_LOCATION,
				IPTABLES_SUPPORTS_XLOCK,
				ENFORCE,
				(void *) gargoyle_bf_whitelist_shm,
				DEBUG,
				config_file
			);
			IP_HITMAP.erase(ip_addr);

		}
	}
}


void handle_ip_addr(const std::string &ip_addr) {

	std::map<std::string, int[2]>::iterator it = IP_HITMAP.find(ip_addr);

	if(it != IP_HITMAP.end()) {

		// element exists
		IP_HITMAP[ip_addr][0] = (int) time(NULL);
		IP_HITMAP[ip_addr][1] = IP_HITMAP[ip_addr][1] + 1;

	} else {

		// create element
		IP_HITMAP[ip_addr][0] = (int) time(NULL);
		IP_HITMAP[ip_addr][1] = 1;

	}

}


int main(int argc, char *argv[]) {

	// register signal SIGINT and signal handler
	signal(SIGINT, signal_handler);
	signal(SIGKILL, signal_handler);

	std::string config_file = "";
	if (argc == 2) {
		config_file = argv[1];
	}

	// default = 6
	size_t num_hits;
	// default = 120
	size_t num_seconds;
	std::string log_entity = "";
	std::string regex_str = "";
	std::string jctl = "journalctl";

	if (config_file.size() && does_file_exist(config_file.c_str())) {

		ConfigVariables cv;
		if (cv.get_vals(config_file.c_str()) == 0) {

			log_entity = cv.get_bf_log_entity();
			regex_str = cv.get_bf_regex_str();
			num_hits = cv.get_bf_number_of_hits();
			num_seconds = cv.get_bf_time_frame();
			ENFORCE = cv.get_enforce_mode();
			ENABLED = cv.get_enabled_mode();

		} else {
			return 1;
		}
	} else {
		syslog(LOG_INFO | LOG_LOCAL6, "Config entity: \"%s\" does not exist, cannot continue", config_file.c_str());
		return 1;
	}

	if (!ENABLED)
		return 1;

	/*
	std::cout << config_file << std::endl;
	std::cout << log_entity << std::endl;
	std::cout << regex_str << std::endl;
	std::cout << num_hits << std::endl;
	std::cout << num_seconds << std::endl;
	std::cout << ENFORCE << std::endl;
	std::cout << ENABLED << std::endl;
	std::cout << std::endl;
	*/

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


	if (!does_file_exist(log_entity.c_str())) {
		syslog(LOG_INFO | LOG_LOCAL6, "Target log entity: \"%s\" does not exist, cannot continue", log_entity.c_str());
		return 1;
	}

	gargoyle_bf_whitelist_shm = SharedIpConfig::Create(GARGOYLE_WHITELIST_SHM_NAME, GARGOYLE_WHITELIST_SHM_SZ);


	std::ifstream ifs(log_entity.c_str(), std::ios::ate);
    // remember file position
    std::ios::streampos gpos = ifs.tellg();

    std::string line;
	std::smatch match;
	struct stat f_var;
	int ret = -1;

	try {

		std::regex l_regex(regex_str);
		//while(true) {
		while(ifs.is_open()) {

			while(!ifs.eof()) {

				line.clear();
				//std::getline(ifs, line);

				/*
				 * since this is a live running daemon we need
				 * to detect when a log file gets rotated
				 * because it obviously gets a new inode and
				 * is a new file entity altogether. I thought
				 * we could catch that with the detcetion of
				 * eof but that doesnt seem to work tremendously
				 * well so the detection of size zero when the
				 * new log file gets created turns out to be
				 * more reliable even though its more expensive
				 *
				 */
				//if (get_file_size(log_entity) == 0)
				//	break;
				ret = stat(log_entity.c_str(), &f_var);
				if (ret >= 0) {

					if (f_var.st_size == 0) {
						std::this_thread::sleep_for(std::chrono::seconds(5));
						break;
					}

				}

				// try to read line
				if(!std::getline(ifs, line) || ifs.eof()) {

					// if we fail, clear stream, return to beginning of line
					ifs.clear();
					ifs.seekg(gpos);

					// and wait to try again
					std::this_thread::sleep_for(std::chrono::milliseconds(100));
					continue;
				}


				// remember the position of the next line in case
				// the next read fails
				gpos = ifs.tellg();


				// process line here
				//std::cout << "line: " << line << std::endl;

				if (std::regex_search(line, match, l_regex)) {

					if (DEBUG) {
						std::cout << "MATCH SZ: " << match.size() << std::endl;
						std::cout << "MATCH 0: " << match.str(0) << std::endl;
						std::cout << "MATCH 1: " << match.str(1) << std::endl;
					}

					std::string ip_addr;
					if (match.size() >= 2) {
						ip_addr = match.str(1);
						//std::cout << "IP: " << ip_addr << std::endl;
					}

					if (ip_addr.size()) {

						if (validate_ip_address(ip_addr)) {

							if (DEBUG) {
								std::cout << "MATCH IP ADDR: " << ip_addr << std::endl;
							}
							handle_ip_addr(ip_addr);

						} else {

							std::string hip = hunt_for_ip_addr(ip_addr, ' ');
							// the hack found an ip addr
							if (hip.size()) {

								handle_ip_addr(hip);

							}

						}

						process_iteration(num_seconds, num_hits, config_file);

					}

				}

				//process_iteration(num_seconds, num_hits);

			}

			if (DEBUG) {
				std::cout << "Log file: " << log_entity << " CLOSED" << std::endl;
			}
			ifs.close();
			// Roll-over -- the logrotate closed the current file and re-opened it
			ifs.open(log_entity.c_str());

		}

	} catch (std::regex_error& e) {

		std::cout << std::endl << "Regex exception: " << e.what() << std::endl;
		std::cout << "Regex exception code is: " << e.code() << std::endl;
		std::cout << "Cannot continue ..." << std::endl << std::endl;
		return 1;

	}

	return 0;
}
