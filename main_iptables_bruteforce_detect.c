/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * Program to spawn off child processes for detection, and blocking, of brute force attack attempts (gargoyle_lscand_bruteforce)
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
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>

#define BF_CONF_DIR_MAX 512

sig_atomic_t child_process_ret_status;
char GARG_BF_CONFIG_DIR[BF_CONF_DIR_MAX + 1];


void spawn(char *program,char *argv[]) {

	pid_t child_pid = vfork();

	if(child_pid == 0) {
	
		execvp(argv[0], argv);
	
	}
}


void signal_handler(int signum) {

	if(signum == SIGCHLD){

		wait(&child_process_ret_status);

	}
	
	if(signum == SIGINT){

		exit(0);

	}
}


int main(void){

	signal(SIGCHLD, signal_handler);

	const char *target_resource = "conf.d";
	const char *gargoyle_bf_config_dir;
	gargoyle_bf_config_dir = getenv("GARGOYLE_BRUTE_FORCE_CONFIG_DIR");
	if (gargoyle_bf_config_dir == NULL) {
		char cwd[BF_CONF_DIR_MAX/2];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (GARG_BF_CONFIG_DIR, BF_CONF_DIR_MAX, "%s/%s/", cwd, target_resource);
		}
	} else {
		snprintf (GARG_BF_CONFIG_DIR, BF_CONF_DIR_MAX, "%s/", gargoyle_bf_config_dir);
	}

	
	size_t file_cnt = 0;
	DIR *dpdf1;
	struct dirent *epdf1;
	
	dpdf1 = opendir(GARG_BF_CONFIG_DIR);
	if (dpdf1 != NULL) {
		// get a count
		while (epdf1 = readdir(dpdf1)){
			
			if (epdf1->d_name[0] != '.') {
	
				file_cnt++;
	
			}
		}
		closedir(dpdf1);
	}

	DIR *dpdf;
	struct dirent *epdf;
	char fs[BF_CONF_DIR_MAX + 64 + 1];
	
	dpdf = opendir(GARG_BF_CONFIG_DIR);
	if (dpdf != NULL) {

		size_t files_processed = 0;

		// spawn processes based on detected conf files
		while (epdf = readdir(dpdf)){
			
			FILE *file = NULL;

			size_t garg_bf_dir_sz = strlen(GARG_BF_CONFIG_DIR);
			strncpy (fs, GARG_BF_CONFIG_DIR, garg_bf_dir_sz);
			fs[garg_bf_dir_sz] = '\0';

			//printf("FNAME: %s\n", epdf->d_name);
			
			if (epdf->d_name[0] != '.') {

				strncat (fs, epdf->d_name, strlen(epdf->d_name));
				fs[strlen(fs)] = '\0';


				if(strstr(fs, ".conf") != NULL) {
	
					if (strlen(fs) && strcmp(fs, GARG_BF_CONFIG_DIR) != 0) {
		
						char *program = "./gargoyle_lscand_bruteforce";
						char *argv[]={
								program,
								fs,
								NULL
						};
		
						spawn(program, argv);
						
						files_processed++;
						//printf("CNT1: %lu\n\n", files_processed);
						if (files_processed == file_cnt) {
							break;
						}
					}
				}
			}
		}
		
		closedir(dpdf);
	}

	return 0;
}
