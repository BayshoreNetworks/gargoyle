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


sig_atomic_t child_process_ret_status;


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
}


int main(void){

	signal(SIGCHLD, signal_handler);

	const char *target_resource = "conf.d/";

	DIR *dpdf;
	struct dirent *epdf;
	char fs[300];
	
	dpdf = opendir(target_resource);
	if (dpdf != NULL) {

		while (epdf = readdir(dpdf)){
			
			FILE *file = NULL;

			strncpy (fs, target_resource, strlen(target_resource));
			fs[strlen(target_resource)] = '\0';

			//printf("FNAME: %s\n", epdf->d_name);
			
			if (epdf->d_name[0] != '.') {

				strncat (fs, epdf->d_name, strlen(epdf->d_name));
				fs[strlen(fs)] = '\0';

			}

			if (strlen(fs) && strcmp(fs, target_resource) != 0) {

				char *program = "./gargoyle_lscand_bruteforce_detect";
				char *argv[]={
						program,
						fs,
						NULL
				};

				spawn(program, argv);

			}
		}
		closedir(dpdf);
	}

	return 0;
}
