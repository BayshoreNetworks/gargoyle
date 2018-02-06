/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Program to detect and block SSH brute force attacks
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

/*
 * Note:
 *
 * even if the SSH port isnt 22 it doesnt matter so
 * we will just use FAKE_PORT as the default. The goal here
 * is to put enough real hit data in to the hosts_port_hits
 * table so that if relevant the gargoyle analysis process
 * can detect slow and low attacks that go under this
 * radar
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

#include "config.h"

#ifdef USE_LIBPCRECPP
#include <pcrecpp.h>
#else
#include <regex>
#endif

#include "ip_addr_controller.h"
#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "system_functions.h"
#include "string_functions.h"
#include "singleton.h"
#include "shared_config.h"
#include "LogTail.h"


int BASE_TIME;
int BASE_TIME2;
char DB_LOCATION[SQL_CMD_MAX+1];
int FAKE_PORT = 65537;
int PROCESS_TIME_CHECK = 60;
bool ENFORCE = true;
bool ENABLED = true;
bool DEBUG = false;
int BUF_SZ = 2048;

/*
 * Return code:
 *  0 == graceful exit (no error, SIGINT received)
 *  1 == invalid configuration (or missing required configuration file(s))
 *  2 == invalid regular expression detected
 */
volatile int ret_code = 0;
volatile bool stop_processing = false;

std::vector<std::string> sshd_regexes;
std::map<std::string, int[2]> IP_HITMAP;

size_t IPTABLES_SUPPORTS_XLOCK;
size_t ITER_CNT_MAX = 50;
SharedIpConfig *gargoyle_sshbf_whitelist_shm = NULL;

size_t get_regexes(const char *);
void signal_handler(int);
bool validate_ip_address(const std::string &);
int handle_log_line(const std::string &);
void process_iteration(int, int);
std::string hunt_for_ip_addr(std::string);
void handle_ip_addr(const std::string &);


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

	stop_processing = true;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);

	// terminate program
	exit(ret_code);

}



bool validate_ip_address(const std::string &ip_address)
{
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


#ifndef USE_LIBPCRECPP
int handle_log_line(const std::string &line) {

	//std::cout << "LINE: " << line << std::endl;

	std::smatch match;

	try {

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

				do_block_actions(ip_addr,
					50,
					DB_LOCATION,
					IPTABLES_SUPPORTS_XLOCK,
					ENFORCE,
					(void *)gargoyle_sshbf_whitelist_shm,
					DEBUG,
					""
				);

			}

			return 0;

		} else if (std::regex_search(line, match, invalid_user) && match.size() == 2) {

			std::string ip_addr = match.str(1);

			//std::cout << "TESTING INVALID USER" << std::endl;

			if (validate_ip_address(ip_addr)) {

				handle_ip_addr(ip_addr);

			} else {

				std::string hip = hunt_for_ip_addr(ip_addr, ' ');
				/*
				 * this is a hackjob because when reading output
				 * from journalctl the regex doesnt seem to work
				 * as expected (but when tailing a standard log
				 * file it does work)
				 */
				// the hack found an ip addr
				if (hip.size()) {

					handle_ip_addr(hip);

				}
			}

			return 0;

		} else if (std::regex_search(line, match, bad_algo) && match.size() == 2) {

			std::string ip_addr = match.str(1);

			//std::cout << "TESTING BAD ALGO" << std::endl;

			if (validate_ip_address(ip_addr)) {

				handle_ip_addr(ip_addr);

			}

			return 0;

		} else {

			if (sshd_regexes.size() > 0) {

				for(std::vector<std::string>::iterator it = sshd_regexes.begin(); it != sshd_regexes.end(); ++it) {

					/* std::cout << *it; ... */
					std::regex testreg(*it);

					//std::cout << "SZ: " << match.size() << std::endl;

					//if (std::regex_search(line, match, testreg) && match.size() > 1) {
					if (std::regex_search(line, match, testreg) && match.size() == 2) {

						std::string ip_addr = match.str(1);
						if (validate_ip_address(ip_addr)) {

							handle_ip_addr(ip_addr);

						}
						break;
					}
				}
			}
		}

	} catch (std::regex_error& e) {

		std::cout << std::endl << "Regex exception: " << e.what() << std::endl;
		std::cout << "Regex exception code is: " << e.code() << std::endl;
		std::cout << "Cannot continue ..." << std::endl << std::endl;
		return 1;

	}

	return 0;
}
#else
int handle_log_line(const std::string &line) {

	//std::cout << "LINE: " << line << std::endl;

	std::string ip_addr;
	/*
	 * handle instant block regexes first
	 */
	pcrecpp::RE invalid_user("Failed keyboard-interactive/pam for invalid user .* from (.*)\\\\s*");
	pcrecpp::RE max_exceeded("error: maximum authentication attempts exceeded for .* from (.*) port");
	// fatal: Unable to negotiate with 103.207.39.148 port 56169: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
	pcrecpp::RE bad_algo("Unable to negotiate with (.*) port");

	if (max_exceeded.PartialMatch(line, &ip_addr)) {

		// if we are here then do an instant block because sshd already did
		// the work for us of detecting too many login attempts

		//std::cout << "TESTING MAX EXCEEDED" << std::endl;
		//std::cout << "INSTANT BLOCK HERE - " << ip_addr << std::endl;

		if (validate_ip_address(ip_addr)) {

				do_block_actions(ip_addr,
					50,
					DB_LOCATION,
					IPTABLES_SUPPORTS_XLOCK,
					ENFORCE,
					(void *)gargoyle_sshbf_whitelist_shm,
					DEBUG,
					"");

		}

		return 0;

	} else if (invalid_user.PartialMatch(line, &ip_addr)) {

		//std::cout << "TESTING INVALID USER: " << ip_addr << std::endl;

		if (validate_ip_address(ip_addr)) {
			
			handle_ip_addr(ip_addr);
		
		} else {

			std::string hip = hunt_for_ip_addr(ip_addr, ' ');
			/*
			 * this is a hackjob because when reading output
			 * from journalctl the regex doesnt seem to work
			 * as expected (but when tailing a standard log
			 * file it does work)
			 */
			// the hack found an ip addr
			if (hip.size()) {
				
				handle_ip_addr(hip);
			
			}
		}

		return 0;						

	} else if (bad_algo.PartialMatch(line, &ip_addr)) {

		//std::cout << "TESTING BAD ALGO: " << ip_addr << std::endl;

		if (validate_ip_address(ip_addr)) {
			
			handle_ip_addr(ip_addr);
			
		}

		return 0;	

	} else {

		if (sshd_regexes.size() > 0) {

			for(std::vector<std::string>::iterator it = sshd_regexes.begin(); it != sshd_regexes.end(); ++it) {

				//std::cout << *it << std::endl; //; ... */

				pcrecpp::RE testreg(*it);

				//std::cout << "SZ: " << match.size() << std::endl;

				//std::cout << "Line: " << line << " @ " << *it << std::endl;
				if (testreg.PartialMatch(line, &ip_addr)) {

					//std::cout << "TESTING PROVIDED REGEXEs: " << ip_addr << std::endl;
					if (validate_ip_address(ip_addr)) {
						
						handle_ip_addr(ip_addr);
					
					}
					break;
				}
			}
		}
	}
	
	return 0;
}
#endif


void process_iteration(int num_seconds, int num_hits) {

	for (const auto &p : IP_HITMAP) {

		//std::cout << "[" << p.first << "] = " << IP_HITMAP[p.first][0] << " - " << IP_HITMAP[p.first][1] << std::endl << std::endl;

		std::string ip_addr = p.first;
		int now = (int)time(NULL);
		int now_delta = now - IP_HITMAP[p.first][0];
		int l_num_hits = IP_HITMAP[p.first][1];

		/*
		 * if there are double the hits of the allowed
		 * threshold you get blocked irrespective of
		 * time
		 */
		if (l_num_hits >= (num_hits * 2)) {

			do_block_actions(ip_addr,
				50,
				DB_LOCATION,
				IPTABLES_SUPPORTS_XLOCK,
				ENFORCE,
				(void *)gargoyle_sshbf_whitelist_shm,
				DEBUG,
				""
			);

			IP_HITMAP.erase(ip_addr);

		} else if (now_delta > (num_seconds * 3)) {

			if (l_num_hits >= (num_hits * 3)) {

				do_block_actions(ip_addr,
					50,
					DB_LOCATION,
					IPTABLES_SUPPORTS_XLOCK,
					ENFORCE,
					(void *)gargoyle_sshbf_whitelist_shm,
					DEBUG,
					""
				);

			}

			IP_HITMAP.erase(ip_addr);

		} else if (now_delta <= num_seconds) {

			if (l_num_hits >= num_hits) {

				do_block_actions(ip_addr,
					50,
					DB_LOCATION,
					IPTABLES_SUPPORTS_XLOCK,
					ENFORCE,
					(void *)gargoyle_sshbf_whitelist_shm,
					DEBUG,
					""
				);

				IP_HITMAP.erase(ip_addr);

			}
		}
	}
}



void handle_ip_addr(const std::string &ip_addr) {

	std::map<std::string, int[2]>::iterator it = IP_HITMAP.find(ip_addr);

	if(it != IP_HITMAP.end()) {

		// element exists
		IP_HITMAP[ip_addr][1] = IP_HITMAP[ip_addr][1] + 1;

		if (ENFORCE) {
			add_to_hosts_port_table(ip_addr, FAKE_PORT, 1, DB_LOCATION, DEBUG);
		}
		do_report_action_output(ip_addr, FAKE_PORT, 1, (int) time(NULL));

	} else {

		// create element
		IP_HITMAP[ip_addr][0] = (int) time(NULL);
		IP_HITMAP[ip_addr][1] = 1;

		if (ENFORCE) {
			add_to_hosts_port_table(ip_addr, FAKE_PORT, 1, DB_LOCATION, DEBUG);
		}
		do_report_action_output(ip_addr, FAKE_PORT, 1, (int) time(NULL));
	}
}

class LogProcessor : public LogTail 
{
public:
	LogProcessor(
			const std::string& logFile, 
			size_t _num_hits,
			size_t _num_seconds) 
		: LogTail(logFile) 
		, num_hits(_num_hits)
		, num_seconds(_num_seconds) 
		, invalid_user("[iI](?:llegal|nvalid) user .* from (.*)\\s*")
		, max_exceeded("error: maximum authentication attempts exceeded for .* from (.*) port")
		, bad_algo("Unable to negotiate with (.*) port")
		{}
	virtual ~LogProcessor() {}

	virtual void OnLine(const std::string& line) {

		//std::cout << "LINE: " << line << std::endl;
		std::smatch match;

		try {

			/*
			* handle instant block regexes first
			*/
			#if 0
			// initialized in ctor()
			std::regex invalid_user("[iI](?:llegal|nvalid) user .* from (.*)\\s*");
			std::regex max_exceeded("error: maximum authentication attempts exceeded for .* from (.*) port");
			// fatal: Unable to negotiate with 103.207.39.148 port 56169: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
			std::regex bad_algo("Unable to negotiate with (.*) port");
			#endif

			//if (std::regex_search(line, match, invalid_user) && match.size() == 2) {
			if (std::regex_search(line, match, max_exceeded) && match.size() == 2) {

				std::string ip_addr = match.str(1);

				// if we are here then do an instant block because sshd already did
				// the work for us of detecting too many login attempts

				//std::cout << "TESTING MAX EXCEEDED" << std::endl;
				//std::cout << "INSTANT BLOCK HERE - " << ip_addr << std::endl;

				if (validate_ip_address(ip_addr)) {

					do_block_actions(ip_addr,
						50,
						DB_LOCATION,
						IPTABLES_SUPPORTS_XLOCK,
						ENFORCE,
						(void *)gargoyle_sshbf_whitelist_shm,
						DEBUG,
						""
					);

				}

				process_iteration(num_seconds, num_hits);

				return;

			} else if (std::regex_search(line, match, invalid_user) && match.size() == 2) {

				std::string ip_addr = match.str(1);

				//std::cout << "TESTING INVALID USER" << std::endl;

				if (validate_ip_address(ip_addr)) {

					handle_ip_addr(ip_addr);

				} else {

					std::string hip = hunt_for_ip_addr(ip_addr, ' ');
					/*
					* this is a hackjob because when reading output
					* from journalctl the regex doesnt seem to work
					* as expected (but when tailing a standard log
					* file it does work)
					*/
					// the hack found an ip addr
					if (hip.size()) {

						handle_ip_addr(hip);

					}
				}

				process_iteration(num_seconds, num_hits);

				return;

			} else if (std::regex_search(line, match, bad_algo) && match.size() == 2) {

				std::string ip_addr = match.str(1);

				//std::cout << "TESTING BAD ALGO" << std::endl;

				if (validate_ip_address(ip_addr)) {

					handle_ip_addr(ip_addr);

				}

				process_iteration(num_seconds, num_hits);

				return;

			} else {

				if (sshd_regexes.size() > 0) {

					for(std::vector<std::string>::iterator it = sshd_regexes.begin(); it != sshd_regexes.end(); ++it) {

						/* std::cout << *it; ... */
						std::regex testreg(*it);

						//std::cout << "SZ: " << match.size() << std::endl;

						//if (std::regex_search(line, match, testreg) && match.size() > 1) {
						if (std::regex_search(line, match, testreg) && match.size() == 2) {

							std::string ip_addr = match.str(1);
							if (validate_ip_address(ip_addr)) {

								handle_ip_addr(ip_addr);

							}
							break;
						}
					}
				}
			}

		} catch (std::regex_error& e) {

			std::cout << std::endl << "Regex exception: " << e.what() << std::endl;
			std::cout << "Regex exception code is: " << e.code() << std::endl;
			std::cout << "Cannot continue ..." << std::endl << std::endl;
			stop_processing = true;

			ret_code = 2;
			return;
		}

		process_iteration(num_seconds, num_hits);

		return;
	}

private:
	size_t num_hits;
	size_t num_seconds;

	// Hard-coded regular expressions:
	std::regex invalid_user;
	std::regex max_exceeded;
	std::regex bad_algo;
};


int main(int argc, char *argv[])
{

	// register signal SIGINT and signal handler
	signal(SIGINT, signal_handler);
	signal(SIGKILL, signal_handler);

	if (geteuid() != 0) {
    	std::cerr << std::endl << "Root privileges are necessary for this to run ..." << std::endl << std::endl;
    	return 1;
    }


    if (argc > 2 || argc < 1) {

    	std::cerr << std::endl << "Argument errors, exiting ..." << std::endl << std::endl;
    	return 1;

    } else if (argc == 2) {

    	std::string arg_one = argv[1];

    	if ((case_insensitive_compare(arg_one.c_str(), "-v")) || (case_insensitive_compare(arg_one.c_str(), "--version"))) {
    		std::cout << std::endl << GARGOYLE_PSCAND << " Version: " << GARGOYLE_VERSION << std::endl << std::endl;
    		return 0;
    	} else if ((case_insensitive_compare(arg_one.c_str(), "-c"))) { }
    	else {
    		return 0;
    	}
    }


	int ssh_bf_port = 0;
	//const char *port_config_file = ".gargoyle_internal_port_config";
	const char *port_config_file;
	port_config_file = getenv("GARGOYLE_INTERNAL_PORT_CONFIG");
	if (port_config_file == NULL)
		port_config_file = ".gargoyle_internal_port_config";

	ConfigVariables cv;
	if (cv.get_vals(port_config_file) == 0) {
		ssh_bf_port = cv.get_gargoyle_lscand_ssh_bf_port();
	} else {
		return 1;
	}

	if (ssh_bf_port <= 0)
		return 1;


	SingletonProcess singleton(ssh_bf_port);
	try {
		if (!singleton()) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_lscand_ssh_bruteforce", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
			return 1;
		}
	} catch (std::runtime_error& e) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", "gargoyle_lscand_ssh_bruteforce", ALREADY_RUNNING, (singleton.GetLockFileName()).c_str());
		return 1;
	}

	// default = 6
	size_t num_hits;
	// default = 120
	size_t num_seconds;
	std::string log_entity = "";
	std::string regex_file = "";
	std::string jctl = "journalctl";

	const char *sshbf_config_file;
	sshbf_config_file = getenv("GARGOYLE_SSHD_BRUTE_FORCE_CONFIG");
	if (sshbf_config_file == NULL)
		sshbf_config_file = ".gargoyle_ssh_bruteforce_config";

	const char *sshbf_regex_file;
	sshbf_regex_file = getenv("GARGOYLE_SSHD_BRUTE_FORCE_REGEXES");
	if (sshbf_regex_file != NULL)
		regex_file = sshbf_regex_file;

	ConfigVariables cvv;
	if (cvv.get_vals(sshbf_config_file) == 0) {

		log_entity = cvv.get_bf_log_entity();
		if (regex_file.size() == 0)
			regex_file = cvv.get_sshd_regex_file();
		num_hits = cvv.get_bf_number_of_hits();
		num_seconds = cvv.get_bf_time_frame();
		ENFORCE = cvv.get_enforce_mode();
		ENABLED = cv.get_enabled_mode();

	} else {
		return 1;
	}

	if (!ENABLED)
		return 1;

	/*
	std::cout << log_entity << std::endl;
	std::cout << regex_file << std::endl;
	std::cout << num_hits << std::endl;
	std::cout << num_seconds << std::endl;
	std::cout << ENFORCE << std::endl;
	*/

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

	gargoyle_sshbf_whitelist_shm = SharedIpConfig::Create(GARGOYLE_WHITELIST_SHM_NAME, GARGOYLE_WHITELIST_SHM_SZ);

	IPTABLES_SUPPORTS_XLOCK = iptables_supports_xlock();


	BASE_TIME = (int) time(NULL);
	BASE_TIME2 = (int) time(NULL);
	bool use_journalctl = false;

	if (log_entity.find(jctl) != std::string::npos) {
		use_journalctl = true;
	}

	if (!use_journalctl) {
		if (!does_file_exist(log_entity.c_str())) {
			syslog(LOG_INFO | LOG_LOCAL6, "Target log entity: \"%s\" does not exist, cannot continue", log_entity.c_str());
			return 1;
		}
	}

	/*
	 * if the file with a list of regexes (one per
	 * line) exists then process it
	 */
	if (does_file_exist(regex_file.c_str())) {
		// populate vector sshd_regexes with regex strings
		get_regexes(regex_file.c_str());

		/*
		for(std::vector<std::string>::iterator iit = sshd_regexes.begin(); iit != sshd_regexes.end(); ++iit)
			std::cout << *iit << std::endl;
		 */
	}

	/*
	 * handle standard type of log file where we
	 * control the tail style functionality
	 */
	if (!use_journalctl) {

		LogProcessor lp(log_entity, num_hits, num_seconds);
		if (lp.Initialize()) 
			lp.Process(stop_processing);
		else 
			ret_code = 1;
	} else if (use_journalctl) {

		char buff[BUF_SZ];
		while(true) {

			int now = (int)time(NULL);
			if ((now - BASE_TIME) >= 60) {

				FILE *fp;
				fp = popen(log_entity.c_str(), "r");
				if (fp) {
					while (fgets(buff, BUF_SZ, fp) != NULL) {

						//std::cout << "--- " << buff << " --- " << strlen(buff) << std::endl;
						//handle_log_line(buff);
						if (handle_log_line(buff) != 0) {

							// problem with the regexes
							pclose(fp);
							return 1;

						}

					}
					pclose(fp);
				}
				BASE_TIME = now;

			}

			if ((now - BASE_TIME2) >= 120) {

				process_iteration(num_seconds, num_hits);
				BASE_TIME2 = now;

			}

			std::this_thread::sleep_for (std::chrono::seconds(30));

		}

	}

	return ret_code;
}
