/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Wrapper to iptables as a shared lib
 *
 * Copyright (c) 2016 - 2017, Bayshore Networks, Inc.
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
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "iptables_wrapper_api.h"
#include "gargoyle_config_vals.h"

/*
 * 
 * for all functions here:
 * 
 * return 0 = ok
 * return 1 = not ok
 */

/*
size_t is_integer (char *the_str) {
	
	int i;
	int str_len = strlen(the_str);
	
	for(i = 0; i < str_len; i++) {
		if(isdigit(the_str[i]) == 0 || ispunct(the_str[i]) != 0)
			break;
	}
	
	if(i != str_len)
		return 1;
	else
		return 0;
}
*/

size_t iptables_create_new_chain(const char *chain_name) {
	
	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s", IPTABLES, "-N", chain_name);
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}								


size_t iptables_flush_chain(const char *chain_name) {
	
	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s", IPTABLES, "-F", chain_name);
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_list_chain_with_line_numbers(const char *chain_name, char *dst, size_t sz_dst) {
		
	char cmd[CMD_BUF_SZ];
	//char dest[DEST_BUF_SZ];
    char *dest;
    dest = (char*) malloc (DEST_BUF_SZ);
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %s", IPTABLES, "-L", chain_name, "-n --line-numbers");
	
	FILE *in;
	extern FILE *popen();
	char buff[512];

	if(!(in = popen(cmd, "r"))) {
		free(dest);
		return 1;
	}

	// populate results from iptables cmd
	*dest = 0;
	while(fgets(buff, sizeof(buff), in)!=NULL) {
		strncat(dest, buff, DEST_BUF_SZ-strlen(dest)-1);
	}
	
	size_t dest_len = strlen(dest);
	dest[dest_len] = '\0';
	//strcpy(dst, dest);
	if (dest_len+1 > sz_dst) {
		free(dest);
		return 1;
	}
	memcpy (dst, dest, dest_len+1);
	
	free(dest);
	pclose(in);
	return 0;
}


size_t iptables_list_chain(const char *chain_name, char *dst, size_t sz_dst) {
	
	char cmd[CMD_BUF_SZ];
	//char dest[DEST_BUF_SZ];
    char *dest;
    dest = (char*) malloc (DEST_BUF_SZ);
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %s", IPTABLES, "-L", chain_name, "-n");
	
	FILE *in;
	extern FILE *popen();
	char buff[512];

	if(!(in = popen(cmd, "r"))){
		free(dest);
		return 1;
	}

	// populate results from iptables cmd
	*dest = 0;
	while(fgets(buff, sizeof(buff), in)!=NULL){
		strncat(dest, buff, DEST_BUF_SZ-strlen(dest)-1);
	}
	
	size_t dest_len = strlen(dest);
	dest[dest_len] = '\0';
	//strcpy(dst, dest);
	if (dest_len+1 > sz_dst) {
		free(dest);
		return 1;
	}
	memcpy (dst, dest, dest_len+1);
	
	free(dest);
	pclose(in);
	return 0;
}


size_t iptables_list_all_with_line_numbers(char *dst, size_t sz_dst) {
	
	char cmd[CMD_BUF_SZ];
	//char dest[DEST_BUF_SZ];
    char *dest;
    dest = (char*) malloc (DEST_BUF_SZ);
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s", IPTABLES, "-L -n --line-numbers");
	
	FILE *in;
	extern FILE *popen();
	char buff[512];

	if(!(in = popen(cmd, "r"))){
		free(dest);
		return 1;
	}

	// populate results from iptables cmd
	*dest = 0;
	while(fgets(buff, sizeof(buff), in)!=NULL){
		strncat(dest, buff, DEST_BUF_SZ-strlen(dest)-1);
	}
	
	size_t dest_len = strlen(dest);
	dest[dest_len] = '\0';
	//strcpy(dst, dest);
	if (dest_len+1 > sz_dst) {
		free(dest);
		return 1;
	}
	memcpy (dst, dest, dest_len+1);
	
	free(dest);
	pclose(in);
	return 0;
}


size_t iptables_list_all(char *dst, size_t sz_dst) {
	
	
	char cmd[CMD_BUF_SZ];
	//char dest[DEST_BUF_SZ];
    char *dest;
    dest = (char*) malloc (DEST_BUF_SZ);
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s", IPTABLES, "-L -n");

	FILE *in;
	extern FILE *popen();
	char buff[512];

	if(!(in = popen(cmd, "r"))){
		free(dest);
		return 1;
	}

	// populate results from iptables cmd
	*dest = 0;
	while(fgets(buff, sizeof(buff), in)!=NULL){
		strncat(dest, buff, DEST_BUF_SZ-strlen(dest)-1);
	}
	
	size_t dest_len = strlen(dest);
	dest[dest_len] = '\0';
	//strcpy(dst, dest);
	if (dest_len+1 > sz_dst) {
		free(dest);
		return 1;
	}
	memcpy (dst, dest, dest_len+1);
	
	free(dest);
	pclose(in);
	return 0;
}


size_t iptables_delete_chain(const char *chain_name) {
	
	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s", IPTABLES, "-X", chain_name);
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_delete_rule_from_chain(const char *chain_name, size_t rule_index) {
	
	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %zu", IPTABLES, "-D", chain_name, rule_index);
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_add_drop_rule_to_chain(const char *chain_name, const char *the_ip) {
	
	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %s %s %s", IPTABLES, "-A", chain_name, "-s", the_ip, "-j DROP");
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_insert_chain_rule_to_chain_at_index(const char *chain_name, const char *ix_pos, const char *chain_to_add) {

	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %s %s %s", IPTABLES, "-I", chain_name, ix_pos, "-j", chain_to_add);
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_insert_nfqueue_rule_to_chain_at_index(const char *chain_name, size_t ix_pos) {

	char cmd[CMD_BUF_SZ];
	
	// construct iptables cmd
	snprintf(cmd, CMD_BUF_SZ, "%s %s %s %zu %s %s %s", IPTABLES, "-I", chain_name, ix_pos, "-j", NFQUEUE, "--queue-num 5");
	
	FILE *in;
	extern FILE *popen();

	if(!(in = popen(cmd, "r"))){
		return 1;
	}
	
	pclose(in);
	return 0;
}


size_t iptables_find_rule_in_chain(const char *chain_name, const char *criteria_one) {
	
	char *token;
	char *token_save;
	//char index_substr[10];
	
	//char *space;
	//int space_index;
	
	const char *s = "\n";
	
	if (chain_name && criteria_one) {

		//char results[DEST_BUF_SZ];
		size_t d_buf_sz = DEST_BUF_SZ;
		char *results;
		results = (char*) malloc (d_buf_sz+1);
		*results = 0;
		size_t x;
		
		if (iptables_list_chain_with_line_numbers(chain_name, results, d_buf_sz) == 0) {
			
			token = strtok_r(results, s, &token_save);

			x = 0;
			// walk through other tokens
			while( token != NULL )
			{
				/*
				space = strchr(token, ' ');
				space_index = (int)(space - token);
				
				strncpy(index_substr, token, space_index);
				index_substr[space_index] = '\0';
				
				if(is_integer(index_substr) == 0) {
					if(strstr(token, criteria_one) != NULL) {
						free(results);
						return atoi(index_substr);
					}
				}
				*/
				x = atoi (token);
				if (x > 0) {
					if(strstr(token, criteria_one) != NULL) {
						free(results);
						return x;
					}
				}
				token = strtok_r(NULL, s, &token_save);
			}
		}
		free(results);
	}
	return 0;
}


size_t iptables_find_rule_in_chain_two_criteria(const char *chain_name, const char *criteria_one, const char *criteria_two) {
	
	char *token;
	char *token_save;
	//char index_substr[10];
	
	//char *space;
	//int space_index;
	
	const char *s = "\n";

	if (chain_name && criteria_one && criteria_two) {

		//char results[DEST_BUF_SZ];
		size_t d_buf_sz = DEST_BUF_SZ;
		char *results;
		results = (char*) malloc (d_buf_sz+1);
		*results = 0;
		size_t x;

		if (iptables_list_chain_with_line_numbers(chain_name, results, d_buf_sz) == 0) {
			
			//printf("\n\nRESULTS: %s\n", results);
			

			//char *token = strtok_r(results, s, &token_save);
			token = strtok_r(results, s, &token_save);

			//int x = atoi (token);
			
			x = 0;
			// walk through other tokens
			while( token != NULL ) {
				/*
				space = strchr(token, ' ');
 				space_index = (int)(space - token);
				
				//printf("SPACE_IX: %d\n", space_index);
				
				strncpy(index_substr, token, space_index);
				index_substr[space_index] = '\0';
				
				//printf("IX_SUBSTR: %s\n", index_substr);

				if(is_integer(index_substr) == 0) {
					if((strstr(token, criteria_one) != NULL) && (strstr(token, criteria_two) != NULL)) {
						free(results);
						return atoi(index_substr);
					}
				}
				*/
				x = atoi (token);
				if (x > 0) {
					if((strstr(token, criteria_one) != NULL) && (strstr(token, criteria_two) != NULL)) {
						free(results);
						return x;
					}
				}
				token = strtok_r(NULL, s, &token_save);
			}
		}
		free(results);
	}
	return 0;
}


