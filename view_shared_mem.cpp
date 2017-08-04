/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * Program to view what is in shared mem on a live running system
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
#include "config_variables.h"
#include "system_functions.h"
#include "shared_config.h"

#define GARGOYLE_WHITELIST_SHM_NAME "/gargoyle_whitelist_shm"
#define GARGOYLE_WHITELIST_SHM_SZ 250
#define GARGOYLE_BLACKLIST_SHM_NAME "/gargoyle_blacklist_shm"
#define GARGOYLE_BLACKLIST_SHM_SZ 250    

SharedIpConfig *gargoyle_view_whitelist_shm = NULL;
SharedIpConfig *gargoyle_view_blacklist_shm = NULL;


void signal_handler(int signum) {

	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);
	
    if(gargoyle_view_whitelist_shm) {
        delete gargoyle_view_whitelist_shm;
        gargoyle_view_whitelist_shm;
    }
    
    
    if(gargoyle_view_blacklist_shm) {
        delete gargoyle_view_blacklist_shm;
        gargoyle_view_blacklist_shm;
    }

	// terminate program
	exit(0);

}


int main(int argc, char *argv[])
{
	
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
	
	std::cout << "WHITE: " << std::endl << white_list << std::endl << std::endl;
	std::cout << "BLACK: " << std::endl << black_list << std::endl << std::endl;
	
	return 0;
	
}










