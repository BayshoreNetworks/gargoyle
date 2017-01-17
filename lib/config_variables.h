/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
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
#include <cstring>
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
 * 	
 */
class ConfigVariables {
	
public:
	
	/*
	 * return 0 = ok
	 * return 1 = not ok
	 */
	int get_vals(const char *fname) {
		
		string line;
		ifstream infile(fname);
		
		if(infile) {
			while(getline(infile,line)) {
				size_t pos = line.find(":");
				this->key_vals[line.substr(0,pos)] = line.substr(pos+1).c_str();
			}
			return 0;
		} else {
			//cerr << "Couldn't open " << fname << " for reading\n";
			return 1;
		}
	}


	
	int get_port_scan_threshold() {
		
		string p_threshold = "port_scan_threshold";
		if ( key_vals.find(p_threshold) == key_vals.end() ) {
			return 15;
		} else {
			return atoi(key_vals[p_threshold].c_str());
		}
	}


	int get_single_ip_scan_threshold() {
		
		string sip_threshold = "single_ip_scan_threshold";
		if ( key_vals.find(sip_threshold) == key_vals.end() ) {
			return 6;
		} else {
			return atoi(key_vals[sip_threshold].c_str());
		}
	}

	
	int get_overall_port_scan_threshold() {
		
		string op_threshold = "overall_port_scan_threshold";
		if ( key_vals.find(op_threshold) == key_vals.end() ) {
			return 8;
		} else {
			return atoi(key_vals[op_threshold].c_str());
		}
	}

	
	int get_last_seen_delta() {
		
		// return value represents seconds
		string ls_delta = "last_seen_delta";
		if ( key_vals.find(ls_delta) == key_vals.end() ) {
			return 28800;
		} else {
			return atoi(key_vals[ls_delta].c_str());
		}
	}

	
	int get_lockout_time() {
		
		// return value represents seconds
		string lck_time = "lockout_time";
		if ( key_vals.find(lck_time) == key_vals.end() ) {
			return 32400;
		} else {
			return atoi(key_vals[lck_time].c_str());
		}	
	}

private:
	
	map<string,string> key_vals;
	
};

