/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * helper class to parse key:value pairs from config text files
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
#include <fstream>
#include <map>

#include <stdio.h>
#include <stdlib.h>

using namespace std;

/*
 * Currently supported keys:
 * 
 * 	port_scan_threshold
 * 	single_ip_scan_threshold
 * 	overall_port_scan_threshold
 * 	last_seen_delta
 * 	lockout_time
 * 	gargoyle_pscand
 * 	gargoyle_pscand_analysis
 * 	gargoyle_pscand_monitor
 * 	enforce
 * 	ports_to_ignore
 * 	hot_ports
 * 	
 */
class ConfigVariables {
	
public:
	
	ConfigVariables() { }
	virtual ~ConfigVariables() { }
	
	/*
	 * return 0 = ok
	 * return 1 = not ok
	 */
	size_t get_vals(const char *fname) {
		
		string line;
		ifstream infile(fname);
		
		if(infile) {
			while(getline(infile, line)) {
				if (line.size() > 2) {
					size_t pos = line.find(":");
					this->key_vals[line.substr(0,pos)] = line.substr(pos+1).c_str();
				}
			}
			return 0;
		} else {
			//cerr << "Couldn't open " << fname << " for reading\n";
			return 1;
		}
	}

	
	size_t get_port_scan_threshold() {
		
		string p_threshold = "port_scan_threshold";
		size_t ret = 0;
		
		if ( key_vals.find(p_threshold) == key_vals.end() ) {
			ret = 15;
		} else {
			//return atoi(key_vals[p_threshold].c_str());
			sscanf(key_vals[p_threshold].c_str(), "%zu", &ret);
		}
		return ret;
	}


	size_t get_single_ip_scan_threshold() {
		
		string sip_threshold = "single_ip_scan_threshold";
		size_t ret = 0;
		
		if ( key_vals.find(sip_threshold) == key_vals.end() ) {
			ret = 6;
		} else {
			//return atoi(key_vals[sip_threshold].c_str());
			sscanf(key_vals[sip_threshold].c_str(), "%zu", &ret);
		}
		return ret;
	}

	
	size_t get_overall_port_scan_threshold() {
		
		string op_threshold = "overall_port_scan_threshold";
		size_t ret = 0;
		
		if ( key_vals.find(op_threshold) == key_vals.end() ) {
			ret = 8;
		} else {
			//return atoi(key_vals[op_threshold].c_str());
			sscanf(key_vals[op_threshold].c_str(), "%zu", &ret);
		}
		return ret;
	}

	
	size_t get_last_seen_delta() {
		
		// return value represents seconds
		string ls_delta = "last_seen_delta";
		size_t ret = 0;
		
		if ( key_vals.find(ls_delta) == key_vals.end() ) {
			ret = 28800;
		} else {
			//return atoi(key_vals[ls_delta].c_str());
			sscanf(key_vals[ls_delta].c_str(), "%zu", &ret);
		}
		return ret;
	}

	
	size_t get_lockout_time() {
		
		// return value represents seconds
		string lck_time = "lockout_time";
		size_t ret = 0;
		
		if ( key_vals.find(lck_time) == key_vals.end() ) {
			ret = 32400;
		} else {
			//return atoi(key_vals[lck_time].c_str());
			sscanf(key_vals[lck_time].c_str(), "%zu", &ret);
		}
		return ret;
	}
	
	
	int get_gargoyle_pscand_udp_port() {
		
		string g_pscand_port = "gargoyle_pscand";
		if ( key_vals.find(g_pscand_port) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[g_pscand_port].c_str());
		}
	}
	
	
	int get_gargoyle_pscand_analysis_udp_port() {
		
		string g_pscanda_port = "gargoyle_pscand_analysis";
		if ( key_vals.find(g_pscanda_port) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[g_pscanda_port].c_str());
		}
	}
	
	
	int get_gargoyle_pscand_monitor_udp_port() {
		
		string g_pscandm_port = "gargoyle_pscand_monitor";
		if ( key_vals.find(g_pscandm_port) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[g_pscandm_port].c_str());
		}
	}
	
	
	bool get_enforce_mode() {
		
		string enforce_mode = "enforce";
		int the_val;
		if ( key_vals.find(enforce_mode) == key_vals.end() ) {
			// enforce by default if nothing is found
			return true;
		} else {
			the_val = atoi(key_vals[enforce_mode].c_str());
			if (the_val == 1)
				return true;
			else
				return false;
		}
	}
	
	
	string get_ports_to_ignore() {
		
		string ports_to_ignore = "ports_to_ignore";
		if ( key_vals.find(ports_to_ignore) == key_vals.end() ) {
			return "";
		} else {
			return key_vals[ports_to_ignore];
		}
	}
	
	
	string get_hot_ports() {
		
		string hot_ports = "hot_ports";
		if ( key_vals.find(hot_ports) == key_vals.end() ) {
			return "";
		} else {
			return key_vals[hot_ports];
		}
	}
	
	
	string get_bf_log_entity() {
		
		string log_entity = "log_entity";
		if ( key_vals.find(log_entity) == key_vals.end() ) {
			return "";
		} else {
			return key_vals[log_entity];
		}
	}
	
	
	string get_sshd_regex_file() {
		
		string regex_file = "regex_file";
		if ( key_vals.find(regex_file) == key_vals.end() ) {
			return "";
		} else {
			return key_vals[regex_file];
		}
	}


	int get_bf_number_of_hits() {
		
		string number_of_hits = "number_of_hits";
		if ( key_vals.find(number_of_hits) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[number_of_hits].c_str());
		}
	}
	
	
	int get_bf_time_frame() {
		
		string time_frame = "time_frame";
		if ( key_vals.find(time_frame) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[time_frame].c_str());
		}
	}
	
	
	string get_bf_regex_str() {
		
		string regex_str = "regex";
		if ( key_vals.find(regex_str) == key_vals.end() ) {
			return "";
		} else {
			return key_vals[regex_str];
		}
	}
	
	
	int get_gargoyle_lscand_ssh_bf_port() {
		
		string g_lscand_ssh_port = "gargoyle_lscand_ssh_bruteforce";
		if ( key_vals.find(g_lscand_ssh_port) == key_vals.end() ) {
			return -1;
		} else {
			return atoi(key_vals[g_lscand_ssh_port].c_str());
		}
	}
	
	
	bool get_enabled_mode() {
		
		string enabled_mode = "enabled";
		int the_val;
		if ( key_vals.find(enabled_mode) == key_vals.end() ) {
			// enabled by default if nothing is found
			return true;
		} else {
			the_val = atoi(key_vals[enabled_mode].c_str());
			if (the_val == 1)
				return true;
			else
				return false;
		}
	}


private:
	
	map<string,string> key_vals;
	
};

