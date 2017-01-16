/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Program to set some config key/val pairs for use across all daemons
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
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gargoyle_config_vals.h"

int main () {
	
	std::cout << GARGOYLE_VERSION << std::endl;
	std::cout << GARGOYLE_CHAIN_NAME << std::endl;
	
	std::map<std::string,int> mymap;

	int scand_ix = 6665;
	mymap.insert(std::pair<std::string,int>("gargoyle_pscand", scand_ix));

	int pscand_analysis_ix = 6666;
	mymap.insert(std::pair<std::string,int>("gargoyle_pscand_analysis", pscand_analysis_ix));

	int pscand_monitor_ix = 6667;
	mymap.insert(std::pair<std::string,int>("gargoyle_pscand_monitor", pscand_monitor_ix));

	int mymax = pscand_monitor_ix;

	int n;
	char cmd[100];

	std::string data;
	FILE * stream;

	size_t DEST_BUF_SZ = 1024;
	char *dest;
	dest = (char*) malloc (DEST_BUF_SZ+1);
	bool good = true;

	for (std::map<std::string,int>::iterator mit=mymap.begin(); mit!=mymap.end(); ++mit) {

		//std::cout << mit->first << " => " << mit->second << '\n';
		*cmd = 0;
		*dest = 0;
		data = "";

		snprintf(cmd, 100, "%s%d", "netstat -luan |grep :", mit->second);
		//std::cout << cmd << std::endl;

		stream = popen(cmd, "r");
		if (stream) {
			while (!feof(stream)) {
				if (fgets(dest, DEST_BUF_SZ, stream) != NULL)
					data.append(dest);
			}
			pclose(stream);
		}

		if (data.size() > 0) {

			good = false;
			while (good == false) {
				mymax++;
				std::cout << mymax << std::endl;
				data = "";

				snprintf(cmd, 100, "%s%d", "netstat -luan |grep :", mymax);

				stream = popen(cmd, "r");
				if (stream) {
					while (!feof(stream))
						if (fgets(dest, DEST_BUF_SZ, stream) != NULL)
							data.append(dest);
					pclose(stream);
				}
				if (!data.size() > 0) {
					good = true;
					mymap[mit->first] = mymax;
				}
			}
		}
	}

	std::ofstream myfile (".gargoyle_config");
	if (myfile.is_open()) {

		myfile << "gargoyle_chain_name:GARGOYLE_Input_Chain\n";
		
		for (std::map<std::string,int>::iterator mit=mymap.begin(); mit!=mymap.end(); ++mit) {
			myfile << mit->first << ":" << mit->second << '\n';
		}

		myfile.close();
	}

	free(dest);
	return 0;
}

