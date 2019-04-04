/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Program to view what is in shared mem on a live running system
 *
 * Copyright (c) 2017 - 2019, Bayshore Networks, Inc.
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
#include <vector>
#include <csignal>

#include <syslog.h>
#include <unistd.h>

#include "gargoyle_config_vals.h"
#include "string_functions.h"
#include "shared_config.h"


SharedIpConfig *gargoyle_view_whitelist_shm = NULL;
SharedIpConfig *gargoyle_view_blacklist_shm = NULL;


void signal_handler(int signum) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);

    if(gargoyle_view_whitelist_shm) {
        delete gargoyle_view_whitelist_shm;
        //gargoyle_view_whitelist_shm;
    }


    if(gargoyle_view_blacklist_shm) {
        delete gargoyle_view_blacklist_shm;
        //gargoyle_view_blacklist_shm;
    }

	// terminate program
	exit(0);

}


int main(int argc, char *argv[]) {

	// register signal SIGINT and signal handler
	signal(SIGINT, signal_handler);
	signal(SIGKILL, signal_handler);

	gargoyle_view_whitelist_shm = SharedIpConfig::Create(GARGOYLE_WHITELIST_SHM_NAME, GARGOYLE_WHITELIST_SHM_SZ);
	gargoyle_view_blacklist_shm = SharedIpConfig::Create(GARGOYLE_BLACKLIST_SHM_NAME, GARGOYLE_BLACKLIST_SHM_SZ);


	std::stringstream ss_white;
	gargoyle_view_whitelist_shm->ToString(ss_white);
	std::string white_list = ss_white.str();


	std::stringstream ss_black;
	gargoyle_view_blacklist_shm->ToString(ss_black);
	std::string black_list = ss_black.str();

	std::cout << std::endl;

	std::cout << "WHITE LISTED: " << std::endl << std::endl;
	std::vector<std::string> white_tokens;
	tokenize_string(white_list, white_tokens, ",");

	if (white_tokens.size()) {

		std::vector<std::string>::iterator wit;
		for(wit = white_tokens.begin(); wit < white_tokens.end(); wit++) {
		    std::cout << *wit << std::endl;
		}

	}

	std::cout << std::endl << std::endl;

	std::cout << "BLACK LISTED: " << std::endl << std::endl;
	std::vector<std::string> black_tokens;
	tokenize_string(black_list, black_tokens, ",");

	if (black_tokens.size()) {

		std::vector<std::string>::iterator bit;
		for(bit = black_tokens.begin(); bit < black_tokens.end(); bit++) {
		    std::cout << *bit << std::endl;
		}

	}

	std::cout << std::endl << std::endl;

	return 0;

}
