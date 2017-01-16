/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * main daemon
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
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>
#include <csignal>

#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "sqlite_wrapper_api.h"
#include "iptables_wrapper_api.h"
#include "nf_queue.h"
#include "packet_handler.h"
#include "singleton.h"
#include "gargoyle_config_vals.h"
///////////////////////////////////////////////////////////////////////////////////
bool IGNORE_LISTENING_PORTS = true;
bool IGNORE_LOCAL_IP_ADDRS = true;

size_t EPHEMERAL_LOW;
size_t EPHEMERAL_HIGH;

std::vector<int> IGNORE_PORTS;
std::vector<std::string> LOCAL_IP_ADDRS;
///////////////////////////////////////////////////////////////////////////////////

int hex_to_int(const char *);
bool exists_in_ports_entries(int);
bool exists_in_ip_entries(std::string);
void add_to_ports_entries(int);
void add_to_ip_entries(std::string);
void nfqueue_signal_handler(int);
void graceful_exit (int);
void handle_chain();
void get_ports_to_ignore();
void get_ephemeral_range_to_ignore();
void get_local_ip_addrs();
void get_default_gateway_linux();

///////////////////////////////////////////////////////////////////////////////////
void nfqueue_signal_handler(int signum) {

	/*
	printf ("Signal caught, destroying queue ...");
	nfq_destroy_queue(qh);
	printf ("Closing handle \n");
	nfq_close(h);
	*/
	
	graceful_exit(signum);
	//exit(0);
}


void graceful_exit(int signum) {
	
	//std::cout << "Signal caught: " << signum << ", destroying queue ..." << std::endl;
	syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", "Signal caught", signum, "destroying queue and shutting down");
	
	/*
	 * 1. delete NFQUEUE rule from INPUT chain
	 * 2. delete GARGOYLE_CHAIN_NAME rule from INPUT
	 * 3. flush (delete any rules that exist in) GARGOYLE_CHAIN_NAME
	 * 4. reset DB items
	 */
	///////////////////////////////////////////////////
	// 1

	size_t rule_ix;
	rule_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFQUEUE, NFQUEUE_NUM_LINE);
	if (rule_ix > 0) {
		iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, rule_ix);
	}
	
	
	/*
		if NFQUEUE_RULE_NUMBER > 0:
			rule_ix = NFQUEUE_RULE_NUMBER
		else:
			rule_ix = _libgarg_iptables.iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFQUEUE, NFQUEUE_NUM_LINE)
		if int(rule_ix) > 0:
			# delete rule from INPUT chain
			#iptables_delete_rule_from_chain(chain_name=IPTABLES_INPUT_CHAIN, rule_ix=rule_ix)
			_libgarg_iptables.iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, str(rule_ix))

		###################################################
		# 2
		#rule_ix = 0
		'''
		rule_ix = _libgarg_iptables.iptables_find_rule_in_chain(IPTABLES_INPUT_CHAIN, GARGOYLE_CHAIN_NAME)
		if int(rule_ix) > 0:
			_libgarg_iptables.iptables_delete_rule_from_chain(IPTABLES_INPUT_CHAIN, str(rule_ix))
		'''
		###################################################
		# 3
		# flush GARGOYLE_CHAIN_NAME
		#_libgarg_iptables.iptables_flush_chain(GARGOYLE_CHAIN_NAME)
		###################################################	
		#4
		'''
		l_hosts = create_string_buffer(1048576)
		_libgarg_sqlite.get_detected_hosts_all_active_unprocessed_ix(l_hosts)
		for l_host in l_hosts.value.split('>'):
			if l_host:
				_libgarg_sqlite.modify_host_set_processed_ix(int(l_host))
		'''
		###################################################
		#5
		# delete chain GARGOYLE_CHAIN_NAME
		#_libgarg_iptables.iptables_delete_chain(GARGOYLE_CHAIN_NAME)
		###################################################
	
	
	
	*/
	
	
	
	
	
	
	
	
	
	
	/*
	//======================================================================
	// Called by a SIGHUP or SIGINT, unbind the queue and exit
	//======================================================================
	
	printf ("Signal caught, destroying queue ...");
	nfq_destroy_queue(qh);
	printf ("Closing handle \n");
	nfq_close(h);
	exit(0);
	*/
}

void handle_chain() {

	/*
	 * 1. if the chain GARGOYLE_CHAIN_NAME doesnt exist create it
	 * look for something like this: Chain BSN_test_Chain (1 references)
	 * 2. add GARGOYLE_CHAIN_NAME at index 1 in chain INPUT
	 * 3. add nfqueue rule to chain INPUT ...
	 * this rule needs to either be last or right above DROP/REJECT rules
	 * put there at a system level
	 * ?? or does it need to be at index 2 ??
	 */
	///////////////////////////////////////////////////
	// 1
	/*
	 * if the chain doesnt exist it could not possibly have been added
	 * to the INPUT chain so create the chain and then add it to INPUT
	 */
	char *l_chains;
	char *p_lchains;
	
	size_t dst_buf_sz = DEST_BUF_SZ;
	l_chains = (char*) malloc(dst_buf_sz+1);
	*l_chains = 0;
	iptables_list_all(l_chains, dst_buf_sz);
	
	if (l_chains) {
		//std::cout << l_chains << std::endl;
		p_lchains = strstr (l_chains, GARGOYLE_CHAIN_NAME);
		if (!p_lchains) {
			// create new chain used just for this
			//std::cout << "CREATING Chain " << GARGOYLE_CHAIN_NAME << std::endl;
			iptables_create_new_chain(GARGOYLE_CHAIN_NAME);
			/*
			 * example out:
			 * 
			 * Dec 22 11:55:29 shadow-box gargoyle_pscand[2278]: Creating Chain-GARGOYLE_Input_Chain
			 */
			syslog(LOG_INFO | LOG_LOCAL6, "%s-%s", "Creating Chain", GARGOYLE_CHAIN_NAME);
		}
	}
	///////////////////////////////////////////////////
	// 2
	size_t dst_buf_sz2 = DEST_BUF_SZ;
	char *l_chains2;
	l_chains2 = (char*) malloc(dst_buf_sz2+1);
	*l_chains2 = 0;
	
	const char *tok1 = "\n";
	char *token1;
	char *token1_save;
	
	char *p_lchains2;
	char *s_lchains2;
	
	bool ADD_CHAIN_TO_INPUT = true;
	
	iptables_list_all_with_line_numbers(l_chains2, dst_buf_sz2);
	if (l_chains2) {
		token1 = strtok_r(l_chains2, tok1, &token1_save);
		while (token1 != NULL) {
			p_lchains2 = strstr (token1, GARGOYLE_CHAIN_NAME);
			if (p_lchains2) {
				s_lchains2 = strstr (token1, "Chain");
				if (s_lchains2) {
					int position = s_lchains2 - token1;
					if (position != 0) {
						ADD_CHAIN_TO_INPUT = false;
						break;
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}

	if (ADD_CHAIN_TO_INPUT) {
		// insert this to INPUT chain at specific index 1
		iptables_insert_chain_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, "1", GARGOYLE_CHAIN_NAME);
	}
	
	int drop_ix;
	int reject_ix;
	int	targ_ix;
		
	drop_ix = 0;
	reject_ix = 0;
	targ_ix = 0;	
	///////////////////////////////////////////////////
	// 3
	/*
	 * setup nfqueue rule last as we want the
	 * blocking rules from Chain (GARGOYLE_CHAIN_NAME)
	 * to be executed before packets get handed
	 * off to the nfqueue
	 * 
	 * Any blocking rules that get added to the INPUT
	 * chain after this one will not work, as in packets
	 * will get through
	 * 
	 * iptables -A INPUT -j NFQUEUE --queue-num 5
	 */
	size_t rule_ix;
	rule_ix = iptables_find_rule_in_chain_two_criteria(IPTABLES_INPUT_CHAIN, NFQUEUE, NFQUEUE_NUM_LINE);
	
	size_t d_buf_sz = DEST_BUF_SZ * 2;
	char *l_chains3;
	l_chains3 = (char*) malloc(d_buf_sz);
	*l_chains3 = 0;
	
	char *p_lchains3;
	char *s_lchains3;
	//char drop_ix_buf[4];
	char *drop_ix_buf;
	drop_ix_buf = (char*) malloc(5);
	*drop_ix_buf = 0;
	
	char *p_lchains4;
	char *s_lchains4;
	char *reject_ix_buf;
	reject_ix_buf = (char*) malloc(5);
	*reject_ix_buf = 0;
	
	if (rule_ix == 0) {
		//std::cout << rule_ix << std::endl;
		/*
		 * look for rules that start with DROP or REJECT,
		 * we need to get injected before them
		 */
		iptables_list_chain_with_line_numbers(IPTABLES_INPUT_CHAIN, l_chains3, d_buf_sz);
		if (l_chains3) {
			token1 = strtok_r(l_chains3, tok1, &token1_save);
			while (token1 != NULL) {
				
				p_lchains3 = strstr (token1, "DROP ");
				p_lchains4 = strstr (token1, "REJECT ");
				
				if (p_lchains3) {
					s_lchains3 = strstr (token1, " ");
					if (s_lchains3) {
						int position2 = s_lchains3 - token1;
						strncpy(drop_ix_buf, token1, position2);
						drop_ix_buf[position2] = '\0';
						drop_ix = atoi(drop_ix_buf);
						/*
						std::cout << position2 << std::endl;
						std::cout << drop_ix_buf << " - " << strlen(drop_ix_buf) << std::endl;
						*/
					}
					//std::cout << token1 << std::endl;
				}
				
				if (p_lchains4) {
					s_lchains4 = strstr (token1, " ");
					if (s_lchains4) {
						int position3 = s_lchains4 - token1;
						strncpy(reject_ix_buf, token1, position3);
						reject_ix_buf[position3] = '\0';
						reject_ix = atoi(reject_ix_buf);
					}
					//std::cout << token1 << std::endl;
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
		
		if (drop_ix > 0 && reject_ix > 0) {
			targ_ix = std::min(drop_ix,reject_ix);
		}
		if (targ_ix == 0)
			targ_ix = 2;

		iptables_insert_nfqueue_rule_to_chain_at_index(IPTABLES_INPUT_CHAIN, targ_ix);

	}
	///////////////////////////////////////////////////
	free(l_chains);
	free(l_chains2);
	free(l_chains3);
	free(drop_ix_buf);
	free(reject_ix_buf);
}


int hex_to_int(const char *hex) {
	
	int res;
	res = 0;
	
    while (*hex) {
    	if (*hex > 47 && *hex < 58)
    		res += (*hex - 48);
    	else if (*hex > 64 && *hex < 71)
    		res += (*hex - 55);
    	else if (*hex > 96 && *hex < 103)
    		res += (*hex - 87);
    	
    	if (*++hex)
    		res <<= 4;
    }

    return res;
  }

void get_ports_to_ignore() {
	
	FILE *fp;
	char *net_tcp;
	net_tcp = (char*) malloc(133);
	char *target;
	target = (char*) malloc(6);

	fp = popen("cat /proc/net/tcp", "r");
	if (fp) {
		while (fgets(net_tcp, 132, fp) != NULL) {
			//printf("%s\n", net_tcp);
			//std::cout << net_tcp << std::endl;
				
			snprintf(target, 5, "%s", net_tcp+15);
			if (target[0] != ' ') {
				//std::cout << target << " - " << hex_to_int(target) << std::endl;
				int the_port = hex_to_int(target);
				if (EPHEMERAL_LOW > 0 && EPHEMERAL_HIGH > 0) {
					if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
						add_to_ports_entries(the_port);
					}
				}
			}
		}
	}
	free(net_tcp);
	free(target);
	pclose(fp);
}


bool exists_in_ports_entries(int s) {

	std::vector<int>::const_iterator iter;

	iter = std::find(IGNORE_PORTS.begin(), IGNORE_PORTS.end(), s);
	if (iter != IGNORE_PORTS.end()) {
		return true;
	} else {
		return false;
	}
}


bool exists_in_ip_entries(std::string s){

	std::vector<std::string>::const_iterator iter;

	iter = std::find(LOCAL_IP_ADDRS.begin(), LOCAL_IP_ADDRS.end(), s);
	if (iter != LOCAL_IP_ADDRS.end()) {
		return true;
	} else {
		return false;
	}
}


void add_to_ports_entries(int s) {
	if (exists_in_ports_entries(s) == false)
		IGNORE_PORTS.push_back(s);
}


void add_to_ip_entries(std::string s) {
	if (exists_in_ip_entries(s) == false)
		LOCAL_IP_ADDRS.push_back(s);
}


void get_ephemeral_range_to_ignore() {
	
	FILE *fp;
	char *ephemeral_tcp;
	ephemeral_tcp = (char*) malloc(13);
	char *target;
	target = (char*) malloc(6);
	
	const char *tok1 = "\t";
	char *token1;
	char *token1_save;
	
	int iter_cnt;

	fp = popen("cat /proc/sys/net/ipv4/ip_local_port_range", "r");
	if (fp) {
		//while (fgets(ephemeral_tcp, 20, fp) != NULL) {
		if (fgets(ephemeral_tcp, 20, fp) != NULL) {
			//std::cout << "--- " << ephemeral_tcp << " --- " << strlen(ephemeral_tcp) << std::endl;
			iter_cnt = 0;
			token1 = strtok_r(ephemeral_tcp, tok1, &token1_save);
			while (token1 != NULL) {
				//std::cout << token1 << std::endl;
				
				if (iter_cnt == 0)
					EPHEMERAL_LOW = atoi(token1);
				if (iter_cnt == 1)
					EPHEMERAL_HIGH = atoi(token1);
				
				iter_cnt++;
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}
	free(ephemeral_tcp);
	free(target);
	pclose(fp);	
}


void get_local_ip_addrs() {
	
	FILE *fp;
	
	char *inet;
	char *dot;
	char *f_slash;
	
	char *ip_addrs;
	ip_addrs = (char*) malloc(1024);
	
	const char *tok1 = " ";
	char *token1;
	char *token1_save;
	
	const char *tok2 = "/";
	char *token2;
	char *token2_save;
	
	int iter_cnt;

	fp = popen("ip addr", "r");
	if (fp) {
		while (fgets(ip_addrs, 1024, fp) != NULL) {
			//std::cout << "--- " << ip_addrs << " --- " << strlen(ip_addrs) << std::endl;
			inet = strstr (ip_addrs, "inet");
			dot = strstr (ip_addrs, ".");
			if (inet && dot) {
				//std::cout << "--- " << ip_addrs << " --- " << strlen(ip_addrs) << std::endl;

				token1 = strtok_r(ip_addrs, tok1, &token1_save);
				while (token1 != NULL) {
					//std::cout << token1 << std::endl;
					f_slash = strstr (token1, "/");
					if (f_slash) {
						iter_cnt = 0;
						token2 = strtok_r(token1, tok2, &token2_save);
						while (token2 != NULL) {
							if (iter_cnt == 0)
								add_to_ip_entries(token2);
							iter_cnt++;
							token2 = strtok_r(NULL, tok2, &token2_save);
						}
					}
					token1 = strtok_r(NULL, tok1, &token1_save);
				}
			}
		}
	}
	free(ip_addrs);
	pclose(fp);
}








void get_default_gateway_linux() {
	
	FILE *fp;
	/*
	char *inet;
	char *dot;
	char *f_slash;
	*/
	
	char *dot;
	
	char *default_gway;
	default_gway = (char*) malloc(1024);
	
	const char *tok1 = " ";
	char *token1;
	char *token1_save;
	
	fp = popen("ip route | grep default", "r");
	if (fp) {
		while (fgets(default_gway, 1024, fp) != NULL) {
			//std::cout << "--- " << default_gway << " --- " << strlen(default_gway) << std::endl;
			token1 = strtok_r(default_gway, tok1, &token1_save);
			while (token1 != NULL) {
				dot = strstr (token1, ".");
				if (dot) {
					add_to_ip_entries(token1);
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
	}
	free(default_gway);
	pclose(fp);
}

///////////////////////////////////////////////////////////////////////////////////

		
		
/*
// This example shows how to update the TTL of IP packets. These changes to the
// IP header could be exploited to transport steganographic messages.
class StegMangler : public PacketMangler
{
	public:
		void manglePacket(struct iphdr& ipHeader)
		{
			// Let them know the answer to the Ultimate Question of Life,
			// the Universe, and Everything.
			ipHeader.ttl = 42;
		}
};
*/

int main()
{
	
	SingletonProcess singleton(6999);
	if (!singleton()) {
		std::cerr << "process running already. See " << singleton.GetLockFileName() << std::endl;
		return 1;
	}
	
    // Set up signal handlers
    signal (SIGINT, nfqueue_signal_handler);
    signal (SIGSEGV, nfqueue_signal_handler);
	
	handle_chain();

	get_ephemeral_range_to_ignore();
	/*
	std::cout << EPHEMERAL_LOW << std::endl;
	std::cout << EPHEMERAL_HIGH << std::endl;
	*/
	syslog(LOG_INFO | LOG_LOCAL6, "%s %zu - %zu", "ignoring ephemeral port range:", EPHEMERAL_LOW, EPHEMERAL_HIGH);
	
	if (IGNORE_LISTENING_PORTS) {
		get_ports_to_ignore();

		std::stringstream ss;
		int l_cnt = 1;
		int v_cnt = IGNORE_PORTS.size();
		for (std::vector<int>::const_iterator i = IGNORE_PORTS.begin(); i != IGNORE_PORTS.end(); ++i) {
			if (l_cnt == v_cnt)
				ss << *i;
			else
				ss << *i << ",";
			l_cnt++;
		}
			//std::cout << *i << ' ';
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "ignoring ports:", (ss.str().c_str()));
		//std::cout << (ss.str()).substr(0, ss.str().length() - 1) << std::endl;
		//std::cout << ss.str() << IGNORE_PORTS.size() << std::endl;
	}

	LOCAL_IP_ADDRS.push_back("0.0.0.0");
	get_default_gateway_linux();
	if (IGNORE_LOCAL_IP_ADDRS) {
		get_local_ip_addrs();
		
		std::stringstream ss;
		int l_cnt = 1;
		int v_cnt = LOCAL_IP_ADDRS.size();
		for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
			//std::cout << *i << std::endl;
			if (l_cnt == v_cnt)
				ss << *i;
			else
				ss << *i << ",";
			l_cnt++;
		}
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "ignoring IP addr's:", (ss.str().c_str()));
	}
	
	Library lib;
	lib.bind(AF_INET);
	
	CompoundHandler c_handlers;
	
	//GargoylePscandHandler gargoyleHandler = GargoylePscandHandler();
	GargoylePscandHandler gargoyleHandler;
	
	/*
	 * this can be more elegant but works for now
	 */
	for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
		gargoyleHandler.add_to_ip_entries(*i);
	}
	gargoyleHandler.set_ignore_local_ip_addrs(IGNORE_LOCAL_IP_ADDRS);
	gargoyleHandler.set_ephemeral_low(EPHEMERAL_LOW);
	gargoyleHandler.set_ephemeral_high(EPHEMERAL_HIGH);
	gargoyleHandler.set_chain_name(GARGOYLE_CHAIN_NAME);
	/*
	 * this can be more elegant but works for now
	 */
	for (std::vector<int>::const_iterator i = IGNORE_PORTS.begin(); i != IGNORE_PORTS.end(); ++i) {
		gargoyleHandler.add_to_ports_entries(*i);
	}
	
	c_handlers.add_handler(gargoyleHandler);
	
	Queue queue(lib, 5, c_handlers);
	
	lib.loop();
	
	/*
	 * this is an example of how this could be used to pipeline
	 * packets thru multiple handlers
	try
	{
		// Create a packet-handling library bound to the IP address family
		Library lib;
		lib.bind(AF_INET);
		
		// -- Configure packet handlers --- //
		CompoundHandler c_handlers;
		
		// handle incoming packets
		// remove any calls to setVerdict, such as:
		// "queue.setVerdict(id, NF_ACCEPT, 0, NULL);"
		// and let the last class in the pipeline handle
		// that call
		GargoylePscandHandler GargoylePscandHandler("[BEFORE] ");
		c_handlers.add(GargoylePscandHandler);
		
		// Mangle incoming packets
		StegMangler mangler;
		MangleHandler mangleHandler(mangler);
		c_handlers.add(mangleHandler);
		
		
		// Create queue number 5, configured to use the handler stack
		Queue queue(lib, 5, c_handlers);
		

	}
	catch (const char* s)
	{
		cerr << s << " (" << nfq_errno << ")" << endl;
		return -1;
	}
	*/

	graceful_exit(SIGINT);
	
	return 0;
}
