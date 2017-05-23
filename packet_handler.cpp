/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * packet handling code
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
#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <string>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netfilter.h> 
#include <linux/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "iptables_wrapper_api.h"
#include "sqlite_wrapper_api.h"
#include "packet_handler.h"
#include "gargoyle_config_vals.h"
#include "ip_addr_controller.h"


#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

int FLAGS_LIST[] = {128, 64, 32, 16, 8, 4, 2, 1};

/*
 * when ADD_RULES_KNOWN_SCAN_AGGRESSIVE is true
 * automatic blocks will take place when known
 * techniques (NULL, FIN, XMAS, etc) are
 * detected
 */
bool ADD_RULES_KNOWN_SCAN_AGGRESSIVE = true;
bool SYSLOG_ALL_DETECTIONS = true;
bool DEBUG = true;

int BASE_TIME;
//int PROCESS_TIME_CHECK = 120;
int PROCESS_TIME_CHECK = 60;
size_t PH_SINGLE_IP_SCAN_THRESHOLD = 6;
size_t PH_SINGLE_PORT_SCAN_THRESHOLD = 5;
size_t PROCESSING_LIMIT = 200;
/////////////////////////////////////////////////////////////////////////////////
std::vector<int> calculate_flags(int dec) {

	//std::cout << "INCMING FLAGS " << dec << std::endl;

	std::vector<int> final;
	int n;

	for (n = 0; n < 8; ++n) {
		if (dec >= FLAGS_LIST[n]) {
			dec = dec - FLAGS_LIST[n];
			final.push_back(FLAGS_LIST[n]);
		}
	}
	return final;
}


static uint16_t checksum(const uint16_t* buf, unsigned int nbytes) {
	uint32_t sum = 0;

	for (; nbytes > 1; nbytes -= 2)
	{
		sum += *buf++;
	}

	if (nbytes == 1)
	{
		sum += *(unsigned char*) buf;
	}

	sum  = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return ~sum;
}


void *bayshoresubstring(size_t start, size_t stop, const char *src, char *dst, size_t size) {
	int count = stop - start;
	if ( count >= --size ) {
		count = size;
	}
	sprintf(dst, "%.*s", count, src + start);
}


int levenshtein(const char *s1, const char *s2) {
    unsigned int s1len, s2len, x, y, lastdiag, olddiag;
    s1len = strlen(s1);
    s2len = strlen(s2);
    unsigned int column[s1len+1];
    for (y = 1; y <= s1len; y++)
        column[y] = y;
    for (x = 1; x <= s2len; x++) {
        column[0] = x;
        for (y = 1, lastdiag = x-1; y <= s1len; y++) {
            olddiag = column[y];
            column[y] = MIN3(column[y] + 1, column[y-1] + 1, lastdiag + (s1[y-1] == s2[x-1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return(column[s1len]);
}
/////////////////////////////////////////////////////////////////////////////////

GargoylePscandHandler::GargoylePscandHandler() {
	BASE_TIME = (int) time(NULL);
	ENFORCE = true;
	PH_SINGLE_IP_SCAN_THRESHOLD = 6;
	PH_SINGLE_PORT_SCAN_THRESHOLD = 5;
}


int GargoylePscandHandler::packet_handle(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *ldata)
{
	
	GargoylePscandHandler* _this = (GargoylePscandHandler *)ldata;
	
	if (_this) {
		
		int id = 0;
		
		/*
		struct nfulnl_msg_packet_hdr* ph = nflog_get_msg_packet_hdr(nfa);
		if (ph)
		{
			//id = ntohl(ph->packet_id);
			//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
		}
		*/
	
		/*
		struct nfulnl_msg_packet_hw* hwph = nflog_get_packet_hw(nfa);
		if (hwph)
		{
			
			int i, hlen = ntohs(hwph->hw_addrlen);
			
			printf("hw_src_addr=");
			for (i = 0; i < hlen-1; i++)
				printf("%02x:", hwph->hw_addr[i]);
			printf("%02x ", hwph->hw_addr[hlen-1]);
			
		}
		*/
		
		/*
		u_int32_t mark = nflog_get_nfmark(nfa);
		if (mark)
			printf("mark=%u ", mark);
		*/
		
		/*
		u_int32_t ifi = nflog_get_indev(nfa);
		if (ifi)
			printf("indev=%u ", ifi);

		ifi = nflog_get_outdev(nfa);
		if (ifi)
			printf("outdev=%u ", ifi);

		ifi = nflog_get_physindev(nfa);
		if (ifi)
			printf("physindev=%u ", ifi);

		ifi = nflog_get_physoutdev(nfa);
		if (ifi)
			printf("physoutdev=%u ", ifi);
		*/

		char *data;
		int ret = nflog_get_payload(nfa, &data);
		
		if (ret < 0)
			return 0;

		if (ret >= sizeof(struct iphdr))
		{
	
			struct iphdr* ip = (struct iphdr*)(data);
	
			// TCP
			if (ip->protocol == IPPROTO_TCP) {
	
				u_int16_t flags = ntohs(ip->frag_off);
	
				struct tcphdr *tcp_info;
				unsigned short dst_port;
				unsigned short src_port;
				unsigned short seq_num;
				unsigned short ack_num;
	
				tcp_info = (struct tcphdr*)(data + sizeof(*ip));
	
				dst_port = ntohs(tcp_info->dest);
				src_port = ntohs(tcp_info->source);
				seq_num = ntohs(tcp_info->seq);
				ack_num = ntohs(tcp_info->ack_seq);
	
				/*
				printf("\n    ip { version=%d, ihl=%d, tos=%d, len=%d, id=%d, flags=%d frag_off=%d, ttl=%d, protocol=%d, check=%d } ",
						ip->version, ip->ihl, ip->tos, ntohs(ip->tot_len), ip->id, flags >> 13, flags & 0x1FFF, ip->ttl, ip->protocol, ntohs(ip->check)
				);
				 */
	
				// we don't ignore this port
				if (!_this->ignore_this_port(dst_port)) {
	
					/*
					 * in_addr - a statically allocated buffer, which subsequent calls overwrite
					 * so it can't be used twice in a function, have to write out results and
					 * do again
					 */
					struct in_addr src_addr = {ip->saddr};
					std::string s_src(inet_ntoa(src_addr));
					struct in_addr dst_addr = {ip->daddr};
					std::string s_dst(inet_ntoa(dst_addr));
					
					// we dont ignore this ip addr
					if (!_this->is_white_listed_ip_addr(s_src)) {
						
						/////////////////////////////////////////////////////////////////
						/*
						 * if there is a hit that is on the list
						 * of "hot ports" then this warrants an
						 * immediate block action as this means
						 * the user wants no activity on the
						 * specified port
						 */
						if (_this->is_in_hot_ports(dst_port)) {
							
							/*
							 * We will not query iptables here as that overhead
							 * is unacceptable, the analysis process should
							 * catch and cleanup any dupes in iptables if that
							 * situation arises
							 */
							
							// get ix for ip_addr
							int added_host_ix = add_host(s_src.c_str(), _this->DB_LOCATION.c_str());
									
							if (added_host_ix == -1) {
								// get existing index
								added_host_ix = get_host_ix(s_src.c_str(), _this->DB_LOCATION.c_str());
							}
									
							//std:cout << added_host_ix << std::endl;

							if (added_host_ix > 0) {

								_this->add_block_rule(s_src, 9);
								
								_this->add_to_scanned_ports_dict(s_src.c_str(), dst_port);

							}
							return 0;
						}
						/////////////////////////////////////////////////////////////////

						/*
						printf("\n { src_ip=%s, dst_ip=%s, src_port=%d, dst_port=%d, seq_num=%d, ack_num=%d }\n",
								s_src.c_str(),
								s_dst.c_str(),
								src_port,
								dst_port,
								seq_num,
								ack_num
								);
						 */
						/*
						std::cout << "FLAGS: - " << flags << std::endl;
						//std::vector<int> tcp_flags = calculate_flags(flags >> 13);
						
						std::cout << "URG: " << tcp_info->urg << std::endl;
						std::cout << "ACK: " << tcp_info->ack << std::endl;
						std::cout << "PSH: " << tcp_info->psh << std::endl;
						std::cout << "RST: " << tcp_info->rst << std::endl;
						std::cout << "SYN: " << tcp_info->syn << std::endl;
						std::cout << "FIN: " << tcp_info->fin << std::endl;
						*/
						
						/*
						 * U  A  P R S F
						 * 32 16 8 4 2 1
						 */
						std::vector<int> tcp_flags;
						if (tcp_info->urg)
							tcp_flags.push_back(32);
						if (tcp_info->ack)
							tcp_flags.push_back(16);
						if (tcp_info->psh)
							tcp_flags.push_back(8);
						if (tcp_info->rst)
							tcp_flags.push_back(4);
						if (tcp_info->syn)
							tcp_flags.push_back(2);
						if (tcp_info->fin)
							tcp_flags.push_back(1);
	
						/*
						std::cout << "FLAGS: - " << tcp_flags.size() << std::endl;
						for (std::vector<int>::const_iterator i = tcp_flags.begin(); i != tcp_flags.end(); ++i) {
							std::cout << *i << " ";
						}
						std::cout << std::endl;
						*/
		
						if (s_src.size() > 0 && src_port > 0 && s_dst.size() > 0 && dst_port > 0) {
							
							std::ostringstream testdata_tmp;
							testdata_tmp << s_src << ":" << src_port << "->" << s_dst << ":" << dst_port;		
							std::string testdata = testdata_tmp.str();
			
							/*
							std::cout << "SRC: " << s_src << ", LEN: " << s_src.size() << " - " << ip->saddr << std::endl;
							std::cout << "SRCPORT: " << src_port << std::endl;
							std::cout << "DST: " << s_dst << ", LEN: " << s_dst.size() << " - " << ip->daddr << std::endl;
							std::cout << "DSTPORT: " << dst_port << std::endl;
							std::cout << "SEQ: " << seq_num << std::endl;
							std::cout << "ACK: " << ack_num << std::endl;
							std::cout << testdata << std::endl;
							std::cout << "FLAG LEN: " << tcp_flags.size() << std::endl;
							if (tcp_flags.size() > 0) {
								std::cout << "FLAGS: " << std::endl;
								for (std::vector<int>::const_iterator i = tcp_flags.begin(); i != tcp_flags.end(); ++i) {
									std::cout << *i << " ";
								}
							}
							std::cout << std::endl << std::endl;
							*/
		
							bool is_in = _this->THREE_WAY_HANDSHAKE.find(testdata) != _this->THREE_WAY_HANDSHAKE.end();
							if (!is_in)
								_this->three_way_check(s_src,src_port,s_dst,dst_port,seq_num,ack_num,tcp_flags);
			
							_this->main_port_scan_check(s_src,src_port,s_dst,dst_port,seq_num,ack_num,tcp_flags);
							
						}
					}
				}
			} // end of TCP handling
	
			// UDP
			// TODO
	
			///////////////////////////////////////////////////////////////////////////////
			/*
			 * process to run at certain intervals (see PROCESS_TIME_CHECK)
			 * this is what flushes data from memory and blocks stuff
			 * if appropriate
			 */
			if (((int)time(NULL) - BASE_TIME) >= PROCESS_TIME_CHECK) {
				
				// are there any new white list entries in the DB?
				_this->process_ignore_ip_list();
	
				_this->add_block_rules();
				BASE_TIME = (int)time(NULL);
			}
			///////////////////////////////////////////////////////////////////////////////
		}
	}
	return 0;
}



void GargoylePscandHandler::three_way_check (
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	/*
	std::cout << "TCP_FLAGS: " << tcp_flags.size() << std::endl;
	for (std::vector<int>::const_iterator i = tcp_flags.begin(); i != tcp_flags.end(); ++i) {
		std::cout << *i << " ";
	}
	 */

	if (tcp_flags.size() == 1 && tcp_flags[0] == 2) { // flags = SYN - len flags = 1

		if(seq_num > 0 and ack_num == 0) {

			std::ostringstream str_tmp;
			str_tmp << seq_num << "_" << ack_num << "_" << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
			WAITING.insert(str_tmp.str());
		}
	} else if ((tcp_flags.size() == 2) &&
			(std::find(tcp_flags.begin(), tcp_flags.end(), 2) != tcp_flags.end()) && 
			(std::find(tcp_flags.begin(), tcp_flags.end(), 16) != tcp_flags.end())) { // flags = SYN,ACK - len flags = 2

		for(twh_it = WAITING.begin(); twh_it != WAITING.end(); twh_it++) {

			std::size_t pos = (*twh_it).find("_");
			int seq_old = atoi(((*twh_it).substr(0, pos)).c_str());

			if (ack_num == (seq_old + 1)) {

				WAITING.erase(*twh_it);

				std::ostringstream str_tmp;
				str_tmp << seq_num << "_" << ack_num << "_" << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
				WAITING.insert(str_tmp.str());
				break;
			}
		}
	} else if (tcp_flags.size() == 1 && tcp_flags[0] == 16) { // flags = ACK - len flags = 1

		for(twh_it = WAITING.begin(); twh_it != WAITING.end(); twh_it++) {

			std::size_t pos = (*twh_it).find("_");
			int seq_old = atoi(((*twh_it).substr(0, pos)).c_str());

			std::size_t pos2_inc = pos + 1;
			std::size_t pos2 = (*twh_it).find("_", pos2_inc);
			int ack_old = atoi(((*twh_it).substr(pos2_inc, pos2 - pos2_inc)).c_str());

			if ((ack_num == (seq_old + 1)) && (seq_num == ack_old)) {

				WAITING.erase(*twh_it);

				std::ostringstream str_tmp;
				str_tmp << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
				THREE_WAY_HANDSHAKE.insert(str_tmp.str());
				break;
			}
		}
	}
}


bool GargoylePscandHandler::is_in_waiting(std::string s) {

	//if(std::find(WAITING.begin(), WAITING.end(), s) != WAITING.end())
	if (WAITING.count(s) != 0)
		return true;
	return false;
}


bool GargoylePscandHandler::is_in_scanned_ports_cnt_dict(std::string s) {

	if(SCANNED_PORTS_CNT_DICT.find(s) != SCANNED_PORTS_CNT_DICT.end())
		return true;
	return false;
}


bool GargoylePscandHandler::is_in_black_listed_hosts(std::string s) {

	if (BLACK_LISTED_HOSTS.count(s) != 0)
		return true;
	return false;
}


bool GargoylePscandHandler::is_in_three_way_handshake(std::string s) {

	if (THREE_WAY_HANDSHAKE.count(s) != 0)
		return true;
	return false;
}


bool GargoylePscandHandler::is_white_listed_ip_addr(std::string s) {

	std::vector<std::string>::const_iterator local_ip_iter;
	local_ip_iter = std::find(WHITE_LISTED_IP_ADDRS.begin(), WHITE_LISTED_IP_ADDRS.end(), s);
	if (local_ip_iter != WHITE_LISTED_IP_ADDRS.end())
		return true;
	return false;
}


bool GargoylePscandHandler::is_in_ports_entries(int s) {

	ports_iter = std::find(IGNORE_PORTS.begin(), IGNORE_PORTS.end(), s);
	if (ports_iter != IGNORE_PORTS.end())
		return true;
	return false;
}


void GargoylePscandHandler::add_to_white_listed_entries(std::string s) {
	if (!is_white_listed_ip_addr(s))
		WHITE_LISTED_IP_ADDRS.push_back(s);
}


void GargoylePscandHandler::add_to_ports_entries(int s) {
	if (!is_in_ports_entries(s))
		IGNORE_PORTS.push_back(s);
}


void GargoylePscandHandler::main_port_scan_check(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {
	
	/*
	std::cout << "IP: " << src_ip << std::endl;
	std::cout << "SZ: " << tcp_flags.size() << std::endl;
	std::cout << "DST PORT: " << dst_port << std::endl << std::endl;
	*/

	clear_three_way_check_dat();
	three_way_check_dat << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port;
	//three_way_check_dat = "{}:{}->{}:{}".format(src_ip, str(src_port), dst_ip, str(dst_port))
	clear_reverse_three_way_check_dat();
	reverse_three_way_check_dat << dst_ip << ":" << dst_port << "->" << src_ip << ":" << src_port;
	//reverse_three_way_check_dat = "{}:{}->{}:{}".format(dst_ip, str(dst_port), src_ip, str(src_port))
	clear_src_ip_dst_ip_dat();
	src_ip_dst_ip_dat << src_ip << "->" << dst_ip;
	//src_ip_dst_ip_dat = "{}->{}".format(src_ip, dst_ip)
	clear_reverse_src_ip_dst_ip_dat();
	reverse_src_ip_dst_ip_dat << dst_ip << "->" << src_ip;
	//reverse_src_ip_dst_ip_dat = dst_ip + "->" + src_ip

	size_t tcp_flags_sz = tcp_flags.size();
	
	
	if (tcp_flags_sz == 0) {
		
		int null_scan_ret = null_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "null_scan_ret: " << null_scan_ret << std::endl;

		if (null_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "NULL port scan detected");
			return;
		}
		
	} else if (tcp_flags_sz == 1) {
		
		int fin_scan_ret = fin_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "fin_scan_ret: " << fin_scan_ret << std::endl;

		if (fin_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "FIN port scan detected");
			return;
		}
		
	} else if (tcp_flags_sz == 3) {
		
		int xmas_scan_ret = xmas_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);
		
		if (xmas_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "XMAS port scan detected");
			return;
		}
		
	}
	
	
	
	/*
	if (tcp_flags.size() == 3) {
		
		int xmas_scan_ret = xmas_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);
		
		if (xmas_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "XMAS port scan detected");
			return;
		}
	}
	*/
	
	/*
	//int fin_scan_ret;
	//if (xmas_scan_ret == 1) {
	//	fin_scan_ret = fin_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);
	if (tcp_flags.size() == 1) {
		
		int fin_scan_ret = fin_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "fin_scan_ret: " << fin_scan_ret << std::endl;

		if (fin_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "FIN port scan detected");
			return;
		}
	}
	*/

	/*
	//int null_scan_ret;
	//if (fin_scan_ret == 1) {
	//	null_scan_ret = null_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);
	if (tcp_flags.size() == 0) {
		
		int null_scan_ret = null_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "null_scan_ret: " << null_scan_ret << std::endl;

		if (null_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "NULL port scan detected");
			return;
		}
	}
	*/

	/*
	 * if we are here that means that none of the
	 * previous checks yielded anything, but we will
	 * keep track of the data in SCANNED_PORTS_CNT_DICT anyway
	 * 
	 * But we ignore locally bound ip addr's if that flag is set
	 */
	if (IGNORE_WHITE_LISTED_IP_ADDRS) {
		if (!is_white_listed_ip_addr(src_ip)) {
			add_to_scanned_ports_dict(src_ip, dst_port);
		}
	}

	//std::cout << "WTF1 -" << three_way_check_dat.str() << std::endl << reverse_three_way_check_dat.str() << std::endl << src_ip_dst_ip_dat.str() << std::endl << reverse_src_ip_dst_ip_dat.str() << "WTF2" << std::endl;

}


void GargoylePscandHandler::add_to_scanned_ports_dict(std::string the_ip, int the_port) {

	/*
	display_local_ip_addr();
	display_scanned_ports_dict();
	 */

	/*
	 * SCANNED_PORTS_CNT_DICT example: 
	 * 	192.168.1.115:64 :: 2 :: 1482869817
	 * 	192.168.1.117:5558 :: 11 :: 1482869646
	 * 	192.168.1.117:5559 :: 4 :: 1482869673
	 * 
	 * 
	 * structure is:
	 * 
	 * 	key = ip:port
	 * 	value = hit_count:last_timestamp
	 */

	if (IGNORE_WHITE_LISTED_IP_ADDRS) {
		if (is_white_listed_ip_addr(the_ip) == true) {
			return;
		}
	}


	if (the_ip.size() > 0 && the_port > 0) {

		/*
		 * we ignore ephemeral ports as blocking them will disrupt
		 * legitimate functionality on the running host
		 */
		//if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {
		if (!ignore_this_port(the_port)) {

			int tstamp = (int) time(NULL);

			std::ostringstream tkey;
			tkey << the_ip << ":" << the_port;

			if (is_in_scanned_ports_cnt_dict(tkey.str())) {

				std::pair <int,int> foo;
				foo = SCANNED_PORTS_CNT_DICT[tkey.str()];
				//std::cout << foo.first << " - " << foo.second << std::endl;

				//std::cout << "REPLACING - " << tkey.str() << std::endl;

				std::pair <int, int> cnt_tstamp;
				cnt_tstamp = std::make_pair (foo.first + 1, tstamp);

				SCANNED_PORTS_CNT_DICT[tkey.str()] = cnt_tstamp;

			} else {

				//std::cout << "ADDING - " << tkey.str() << std::endl;

				std::pair <int, int> cnt_tstamp;
				cnt_tstamp = std::make_pair (1, tstamp);

				SCANNED_PORTS_CNT_DICT.insert(std::make_pair(tkey.str(), cnt_tstamp));
			}
		}
	}
}


void GargoylePscandHandler::set_ignore_local_ip_addrs(bool val) {
	IGNORE_WHITE_LISTED_IP_ADDRS = val;
}


void GargoylePscandHandler::set_ephemeral_low(size_t val) {
	if (val)
		EPHEMERAL_LOW = val;
}


void GargoylePscandHandler::set_ephemeral_high(size_t val) {
	if (val)
		EPHEMERAL_HIGH = val;	
}


void GargoylePscandHandler::clear_three_way_check_dat() {
	three_way_check_dat.str("");
	three_way_check_dat.clear();
}


void GargoylePscandHandler::clear_reverse_three_way_check_dat() {
	reverse_three_way_check_dat.str("");
	reverse_three_way_check_dat.clear();
}


void GargoylePscandHandler::clear_src_ip_dst_ip_dat() {
	src_ip_dst_ip_dat.str("");
	src_ip_dst_ip_dat.clear();
}


void GargoylePscandHandler::clear_reverse_src_ip_dst_ip_dat() {
	reverse_src_ip_dst_ip_dat.str("");
	reverse_src_ip_dst_ip_dat.clear();
}


void GargoylePscandHandler::display_scanned_ports_dict() {

	std::map< std::string, std::pair <int, int> >::iterator it = SCANNED_PORTS_CNT_DICT.begin();
	while(it != SCANNED_PORTS_CNT_DICT.end()) {
		std::cout << it->first << " :: " << it->second.first << " :: " << it->second.second << std::endl;
		it++;
	}
	std::cout << std::endl << std::endl;
}


void GargoylePscandHandler::display_local_ip_addr() {

	//local_ip_iter

	//std::cout << "IP_ADDR: " << LOCAL_IP_ADDRS.size() << std::endl;
	for (std::vector<std::string>::const_iterator i = WHITE_LISTED_IP_ADDRS.begin(); i != WHITE_LISTED_IP_ADDRS.end(); ++i) {
		std::cout << *i << " ";
	}
	std::cout << std::endl << std::endl;
}


void GargoylePscandHandler::display_hot_ports() {
	
	for (std::vector<int>::const_iterator i = HOT_PORTS.begin(); i != HOT_PORTS.end(); ++i) {
			std::cout << *i << " ";
		}
		std::cout << std::endl << std::endl;
}


void GargoylePscandHandler::set_chain_name(std::string s) {
	if (s.size() > 0)
		CHAIN_NAME = s;
}


void GargoylePscandHandler::add_block_rule(std::string the_ip, int detection_type) {

	if (the_ip.size() > 0) {

		// don't process internally bound ip addresses
		if (IGNORE_WHITE_LISTED_IP_ADDRS) {
			if (is_white_listed_ip_addr(the_ip) == true) {
				if (is_in_black_listed_hosts(the_ip)) {
					BLACK_LISTED_HOSTS.erase(the_ip);
				}
				return;
			}
		}

		std::set<std::string> ip_tables_entries;
		std::set<std::string>::iterator it;

		/*
		const char *tok1 = ">";
		char *token1;
		char *token1_save;
		*/
		const char *tok1 = "\n";
		char *token1;
		char *token1_save;

		/*
		int resp;
		size_t dst_buf_sz = SMALL_DEST_BUF;
		char *l_hosts = (char*) malloc(dst_buf_sz+1);
		size_t dst_buf_sz1 = LOCAL_BUF_SZ;
		char *host_ip = (char*) malloc(dst_buf_sz1+1);
		*/
		
		int added_host_ix = 0;
		int tstamp;
		
		size_t d_buf_sz = DEST_BUF_SZ * 2;
		char *l_hosts = (char*) malloc(d_buf_sz);
		*l_hosts = 0;
		
		size_t dst_buf_sz1 = LOCAL_BUF_SZ;
		char *host_ip = (char*) malloc(dst_buf_sz1+1);
		*host_ip = 0;
		
		const char *dash_dash = "--  ";
		size_t dash_dash_len = 4;
		const char *w_space = " ";
		char *s_lchains3;
		char *s_lchains4;

		// whats active in iptables?		
		iptables_list_chain(GARGOYLE_CHAIN_NAME, l_hosts, d_buf_sz, IPTABLES_SUPPORTS_XLOCK);
		if (l_hosts) {
			token1 = strtok_r(l_hosts, tok1, &token1_save);
			while (token1 != NULL) {

				s_lchains3 = strstr (token1, dash_dash);
				if (s_lchains3) {
					
					size_t position1 = s_lchains3 - token1;
					s_lchains4 = strstr (token1 + position1 + dash_dash_len, w_space);
					size_t position2 = s_lchains4 - token1;

					*host_ip = 0;
					bayshoresubstring(position1 + dash_dash_len, position2, token1, host_ip, 16);
					if (host_ip) {
						
						ip_tables_entries.insert(host_ip);
					
					}
				}
				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}		
		

		if (ip_tables_entries.count(the_ip) == 0) {
			/*
			 * !! ENFORCE - if ip in question has been flagged as doing
			 * something blatantly stupid then block this bitch
			 */
			//added_host_ix = do_block_actions(the_ip, detection_type);
			added_host_ix = do_block_actions(the_ip, detection_type, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);

			if (is_in_black_listed_hosts(the_ip) == true) {
				BLACK_LISTED_HOSTS.erase(the_ip);
			}
		}
		free(l_hosts);
		free(host_ip);
	}
}



int GargoylePscandHandler::add_ip_to_hosts_table(std::string the_ip) {

	int added_host_ix;
	added_host_ix = 0;

	if (the_ip.size() > 0) {

		// add blacklisted ip to db
		/* 
		 * if add_host is successful then it returns
		 * the ix of the DB row it added. Otherwise
		 * it returns 0 (zero) or -1. if -1 is returned then
		 * there is probably an existing record for the
		 * ip addr in question, so try to get its ix
		 * value via get_host
		 */
		added_host_ix = add_host(the_ip.c_str(), DB_LOCATION.c_str());
		// already exists
		if (added_host_ix == -1) {
			// get existing index
			added_host_ix = get_host_ix(the_ip.c_str(), DB_LOCATION.c_str());
		}
	}	
	return added_host_ix;
}


int GargoylePscandHandler::xmas_scan(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	if (!ignore_this_port(dst_port) || !is_white_listed_ip_addr(src_ip)) {
		if((tcp_flags.size() == 3) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 1) != tcp_flags.end()) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 8) != tcp_flags.end()) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 32) != tcp_flags.end())) { // flags = FIN,URG,PSH - len flags = 3


			if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
				add_block_rule(src_ip, 3);
				
				int host_ix = add_ip_to_hosts_table(src_ip);
				if (host_ix > 0) {
					add_to_hosts_port_table(src_ip, dst_port, 1, DB_LOCATION);
				}
			}

			add_to_scanned_ports_dict(dst_ip, src_port);

			if (!is_in_black_listed_hosts(src_ip)) {
				BLACK_LISTED_HOSTS.insert(src_ip);
			}
			return 0;
		}
	}
	return 1;
}


int GargoylePscandHandler::fin_scan(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	if (!ignore_this_port(dst_port) || !is_white_listed_ip_addr(src_ip)) {
		if (!is_in_three_way_handshake(three_way_check_dat.str())) {

			if(tcp_flags.size() == 1 && tcp_flags[0] == 1) { // flags = FIN - len flags = 1

				if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
					add_block_rule(src_ip, 2);
					
					int host_ix = add_ip_to_hosts_table(src_ip);
					if (host_ix > 0) {
						add_to_hosts_port_table(src_ip, dst_port, 1, DB_LOCATION);
					}
				}

				add_to_scanned_ports_dict(dst_ip, src_port);

				if (!is_in_black_listed_hosts(src_ip)) {
					BLACK_LISTED_HOSTS.insert(src_ip);
				}
				return 0;	
			}
		}
	}
	return 1;
}


int GargoylePscandHandler::null_scan(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	if (!ignore_this_port(dst_port) || !is_white_listed_ip_addr(src_ip)) {
		if(tcp_flags.size() == 0) {

			if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
				
				add_block_rule(src_ip, 1);
				
				int host_ix = add_ip_to_hosts_table(src_ip);
				if (host_ix > 0) {
					add_to_hosts_port_table(src_ip, dst_port, 1, DB_LOCATION);
				}
			}

			add_to_scanned_ports_dict(dst_ip, src_port);
			
			if (!is_in_black_listed_hosts(src_ip)) {
				BLACK_LISTED_HOSTS.insert(src_ip);
			}
			return 0;
		}
	}
	return 1;
}


bool GargoylePscandHandler::is_in_ephemeral_range(int the_port) {

	if (the_port > 0) {
		//std::cout << "ELOW " << EPHEMERAL_LOW << " EHIGH " << EPHEMERAL_HIGH << std::endl;
		if (the_port >= EPHEMERAL_LOW && the_port <= EPHEMERAL_HIGH) {
			return true;
		}
	}
	return false;
}


/*
 * true = ignore this port
 * false = do not ignore this port
 */
bool GargoylePscandHandler::ignore_this_port(int the_port) {

	//std::cout << "Checking: " << the_port << std::endl;

	if (the_port <= 0) {
		//std::cout << "LESS THAN ZERO" << std::endl;
		return true;
	}
	if (the_port > 0) {
		if (is_in_ephemeral_range(the_port) == true) {
			//std::cout << "IN EPHEMERAL RANGE" << std::endl;
			return true;
		}
		if (is_in_ports_entries(the_port) == true) {
			//std::cout << "IN ENTRIES" << std::endl;
			return true;
		}
	}
	return false;
}


void GargoylePscandHandler::add_block_rules() {
	
	srand((int)time(0));

	/*
	 *
	 * there are 2 phases to this function:
	 * 
	 * - phase 1 processes ip addr's that are in list BLACK_LISTED_HOSTS and
	 *   then removes them from that list
	 *   
	 * - phase 2 process data from map SCANNED_PORTS_CNT_DICT where the structure is
	 * 
	 *   {'ip_addr:port_number':{'hit_count,time_stamp'}}
	 *   
	 *   example:
	 *   
	 *   {'201.172.17.35:23':{'1:1479688559'}}, ...
	 * 
	 */

	std::set<std::string> ip_tables_entries;
	std::set<std::string>::iterator it;

	/*
	const char *tok1 = ">";
	char *token1;
	char *token1_save;

	int resp;
	size_t dst_buf_sz = SMALL_DEST_BUF;
	char *l_hosts = (char*) malloc(dst_buf_sz+1);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1+1);
	*/
	
	const char *tok1 = "\n";
	char *token1;
	char *token1_save;
	
	size_t d_buf_sz = DEST_BUF_SZ * 2;
	char *l_hosts = (char*) malloc(d_buf_sz);
	*l_hosts = 0;
	
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1+1);
	*host_ip = 0;
	
	const char *dash_dash = "--  ";
	size_t dash_dash_len = 4;
	const char *w_space = " ";
	char *s_lchains3;
	char *s_lchains4;

	int added_host_ix;
	added_host_ix = 0;
	int tstamp;

	// whats active in iptables?
	iptables_list_chain(GARGOYLE_CHAIN_NAME, l_hosts, d_buf_sz, IPTABLES_SUPPORTS_XLOCK);
	
	if (l_hosts) {
		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {

			s_lchains3 = strstr (token1, dash_dash);
			if (s_lchains3) {
				
				size_t position1 = s_lchains3 - token1;
				s_lchains4 = strstr (token1 + position1 + dash_dash_len, w_space);
				size_t position2 = s_lchains4 - token1;

				*host_ip = 0;
				bayshoresubstring(position1 + dash_dash_len, position2, token1, host_ip, 16);
				if (host_ip) {
					
					ip_tables_entries.insert(host_ip);
				
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	
	

	/*
	 * PHASE 1
	 * 
	 * process the ip addr is list BLACK_LISTED_HOSTS - no analysis needed
	 * these just get blocked
	 */
	for (std::set<std::string>::iterator it=BLACK_LISTED_HOSTS.begin(); it!=BLACK_LISTED_HOSTS.end(); ++it) {

		// don't process internally bound ip addresses
		if (IGNORE_WHITE_LISTED_IP_ADDRS) {
			if (is_white_listed_ip_addr(*it) == true) {
				BLACK_LISTED_HOSTS.erase(*it);
				break;
			}
		}
		// don't process ip addrs that already exist
		// in an active iptables rule
		if (ip_tables_entries.count(*it) != 0) {
			BLACK_LISTED_HOSTS.erase(*it);
			break;
		}

		// add blacklisted ip to db
		// and get host ix
		//added_host_ix = add_ip_to_hosts_table(*it);
		tstamp = (int)time(NULL);
		added_host_ix = 0;

		if (ip_tables_entries.count(*it) == 0) {

			/*
			 * !! ENFORCE - if ip in question is in BLACK_LISTED_HOSTS
			 * and we have reached this code path then block this bitch
			 */
			//added_host_ix = do_block_actions(*it, 0);
			added_host_ix = do_block_actions(*it, 0, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);

			ip_tables_entries.insert(*it);
		} else {
			// exists in iptables but we need to put
			// some data in the DB
			added_host_ix = get_host_ix((*it).c_str(), DB_LOCATION.c_str());
			if (added_host_ix == 0)
				added_host_ix = add_ip_to_hosts_table(*it);
		}

		// add to DB
		if (added_host_ix > 0) {
			add_detected_host(added_host_ix, tstamp, DB_LOCATION.c_str());
		}

		BLACK_LISTED_HOSTS.erase(*it);   
	}

	/*
	 * PHASE 2
	 */
	//display_scanned_ports_dict();
	std::string current_key;
	std::string the_ip;
	int the_port;
	int the_cnt;
	std::map<std::string, int> LOCAL_IP_ROW_CNT;
	
	size_t limit_cnt = 0;
	if (SCANNED_PORTS_CNT_DICT.size() > 0) {

		while(limit_cnt <= PROCESSING_LIMIT) {

			std::map< std::string, std::pair <int, int> >::iterator s_port_it = SCANNED_PORTS_CNT_DICT.begin();			
			std::advance(s_port_it, rand() % SCANNED_PORTS_CNT_DICT.size());

	
			//std::cout << s_port_it->first << " :: " << s_port_it->second.first << " :: " << s_port_it->second.second << std::endl;
			current_key = "";
			the_ip = "";
			the_port = 0;
			the_cnt = 0;
			tstamp = (int)time(NULL);
			added_host_ix = 0;
	
			current_key = s_port_it->first;
			std::size_t pos = (s_port_it->first).find(":");
			the_ip = (s_port_it->first).substr(0, pos);
			the_port = atoi(((s_port_it->first).substr(pos + 1, (s_port_it->first).size())).c_str());
			the_cnt = s_port_it->second.first;
	
			/*
			 * populate this to process when this while
			 * loop is done
			 */
			if(LOCAL_IP_ROW_CNT.find(the_ip) != LOCAL_IP_ROW_CNT.end()) {
				int curr_cnt = LOCAL_IP_ROW_CNT[the_ip];
				LOCAL_IP_ROW_CNT[the_ip] = curr_cnt + 1;
			} else {
				LOCAL_IP_ROW_CNT.insert(std::make_pair(the_ip, 1));
			}

			if (the_ip.size() > 0 && the_cnt > 0) {
				// add non blacklisted ip to db
				added_host_ix = add_ip_to_hosts_table(the_ip);
	
				if (the_cnt >= PH_SINGLE_PORT_SCAN_THRESHOLD) {
	
					if (ip_tables_entries.count(the_ip) == 0) {
	
						//do_block_actions(the_ip, 7);
						
						do_block_actions(the_ip, 7, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);
	
						ip_tables_entries.insert(the_ip);
					}
					
					if (is_in_scanned_ports_cnt_dict(current_key)) {
						SCANNED_PORTS_CNT_DICT.erase(current_key);
					}
					break;
					
				} else {
				
					//syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%d\"", "host_ix", added_host_ix);
					
					if (added_host_ix > 0 && !is_white_listed_ip_addr(the_ip)) {
						add_to_hosts_port_table(the_ip, the_port, the_cnt, DB_LOCATION);
					}
					
					/*
					 * do some output to syslog in case
					 * this data is being used for analytics
					 */
					if (SYSLOG_ALL_DETECTIONS) {
						do_report_action_output(the_ip, the_port, the_cnt, tstamp);
					}
				}
			}
			//std::cout << "IP: " << the_ip << " - port " << the_port << " - CNT " << the_cnt << std::endl;
	
			if (is_in_scanned_ports_cnt_dict(current_key)) {
				SCANNED_PORTS_CNT_DICT.erase(current_key);
			}

			if (limit_cnt == PROCESSING_LIMIT || SCANNED_PORTS_CNT_DICT.size() == 0)
				break;
			
			s_port_it++;
			limit_cnt++;
		}
	}

	if (LOCAL_IP_ROW_CNT.size() > 0) {
		std::map<std::string, int>::iterator loc_ip_it = LOCAL_IP_ROW_CNT.begin();
		while(loc_ip_it != LOCAL_IP_ROW_CNT.end()) {
	
			//std::cout << "VIOLATOR: " << loc_ip_it->first << " - CNT: " << loc_ip_it->second << std::endl;
	
			if (loc_ip_it->second >= PH_SINGLE_IP_SCAN_THRESHOLD) {
	
				if (ip_tables_entries.count(loc_ip_it->first) == 0) {
	
					//do_block_actions(loc_ip_it->first, 6);
					
					do_block_actions(loc_ip_it->first, 6, DB_LOCATION, IPTABLES_SUPPORTS_XLOCK, ENFORCE);
	
					ip_tables_entries.insert(loc_ip_it->first);	
				}
			}
			loc_ip_it++;
		}
	}
	
	free(l_hosts);
	free(host_ip);
	
	if (LOCAL_IP_ROW_CNT.size() > 0)
		LOCAL_IP_ROW_CNT.clear();
}


void GargoylePscandHandler::set_enforce_mode(bool b_val) {
	if (b_val || !b_val)
		ENFORCE = b_val;
}


void GargoylePscandHandler::set_single_ip_scan_threshold(size_t t_val) {
	if (t_val > 0) {
		PH_SINGLE_IP_SCAN_THRESHOLD = t_val;
	}
}


void GargoylePscandHandler::set_single_port_scan_threshold(size_t t_val) {
	if (t_val > 0) {
		PH_SINGLE_PORT_SCAN_THRESHOLD = t_val;
	}
}

void GargoylePscandHandler::refresh_white_listed_entries() {

    WHITE_LISTED_IP_ADDRS.push_back("0.0.0.0");
    
    /////////////////////////////////////////////////////
    // get default gateway
	FILE *gw_fp;
	char *gw_dot;
	char *default_gway = (char*) malloc(1024);
	
	const char *gw_tok1 = " ";
	char *gw_token1;
	char *gw_token1_save;
	
	gw_fp = popen("ip route | grep default", "r");
	if (gw_fp) {
		while (fgets(default_gway, 1024, gw_fp) != NULL) {
			//std::cout << "--- " << default_gway << " --- " << strlen(default_gway) << std::endl;
			gw_token1 = strtok_r(default_gway, gw_tok1, &gw_token1_save);
			while (gw_token1 != NULL) {
				gw_dot = strstr (gw_token1, ".");
				if (gw_dot) {
					add_to_white_listed_entries(gw_token1);
				}
				gw_token1 = strtok_r(NULL, gw_tok1, &gw_token1_save);
			}
		}
	}
	free(default_gway);
	pclose(gw_fp);
    /////////////////////////////////////////////////////
    //for get_local_ip_addrs    
    FILE *fp;
	
	char *inet;
	char *dot;
	char *f_slash;
	
	char *ip_addrs = (char*) malloc(1024);
	
	const char *tok1 = " ";
	char *token1;
	char *token1_save;
	
	const char *tok2 = "/";
	char *token2;
	char *token2_save;
	
	int iter_cnt;

    //get_local_ip_addrs
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
							if (iter_cnt == 0) {
								//add_to_ip_entries(token2);
                                add_to_white_listed_entries(token2);
							}
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
    /////////////////////////////////////////////////////
    //for get_white_list_addrs
    const char *tok3 = ">";
	char *token3;
	char *token3_save;
	
	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

    //get_white_list_addrs
	size_t resp = get_hosts_to_ignore_all(l_hosts, dst_buf_sz, DB_LOCATION.c_str());
	if (resp == 0) {

		token3 = strtok_r(l_hosts, tok3, &token3_save);
		while (token3 != NULL) {
			
			if (atoi(token3) > 0) {

				get_host_by_ix(atoi(token3), host_ip, dst_buf_sz1, DB_LOCATION.c_str());

				if (strcmp(host_ip, "") != 0) {
                    //add_to_ip_entries(host_ip);
                    add_to_white_listed_entries(host_ip);
				}
			}
			token3 = strtok_r(NULL, tok3, &token3_save);
		}
	}
	free(l_hosts);
	free(host_ip);
    /////////////////////////////////////////////////////
}


void GargoylePscandHandler::process_ignore_ip_list() {

	const char *tok1 = ">";
	char *token1;
	char *token1_save;

	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);
	
	
	std::stringstream ss_orig;
	int l_cnt_orig = 1;
	int v_cnt_orig = WHITE_LISTED_IP_ADDRS.size();
	for (std::vector<std::string>::const_iterator ii = WHITE_LISTED_IP_ADDRS.begin(); ii != WHITE_LISTED_IP_ADDRS.end(); ++ii) {
		if (l_cnt_orig == v_cnt_orig)
			ss_orig << *ii;
		else
			ss_orig << *ii << ",";
		l_cnt_orig++;
	}
	std::string white_list_orig = ss_orig.str();
	

	WHITE_LISTED_IP_ADDRS.clear();
    refresh_white_listed_entries();

	size_t resp = get_hosts_to_ignore_all(l_hosts, dst_buf_sz, DB_LOCATION.c_str());
	
	if (resp == 0) {

		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {
			
			if (atoi(token1) > 0) {
			
				int host_ix = atoi(token1);
				get_host_by_ix(host_ix, host_ip, dst_buf_sz1, DB_LOCATION.c_str());
				
				if (strcmp(host_ip, "") != 0) {
					add_to_white_listed_entries(host_ip);
				
				
					/*
					 * this is ugly but ....
					 * extra cleanup check in case we
					 * aggressively blocked (race condition)
					 * an ip addr that has been whitelisted
					 */
					size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, host_ip, IPTABLES_SUPPORTS_XLOCK);
					if(rule_ix > 0) {
						
						size_t row_ix = get_detected_hosts_row_ix_by_host_ix(host_ix, DB_LOCATION.c_str());
						
						if (row_ix > 0) {

							// delete all records for this host_ix from hosts_ports_hits table
							remove_host_ports_all(host_ix, DB_LOCATION.c_str());
							
							// delete row from detected_hosts
							remove_detected_host(row_ix, DB_LOCATION.c_str());
							
							// reset last_seen to 1972
							update_host_last_seen(host_ix, DB_LOCATION.c_str());
							
							iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix, IPTABLES_SUPPORTS_XLOCK);

							do_unblock_action_output(host_ip, (int) time(NULL));
						}
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	free(l_hosts);
	free(host_ip);
	
	std::stringstream ss;
	int l_cnt = 1;
	int v_cnt = WHITE_LISTED_IP_ADDRS.size();
	for (std::vector<std::string>::const_iterator i = WHITE_LISTED_IP_ADDRS.begin(); i != WHITE_LISTED_IP_ADDRS.end(); ++i) {
		//std::cout << *i << std::endl;
		if (l_cnt == v_cnt)
			ss << *i;
		else
			ss << *i << ",";
		l_cnt++;
	}

	std::string white_list_new = ss.str();	
	if (levenshtein(white_list_orig.c_str(), white_list_new.c_str()) > 0) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s %s", "ignoring IP addr's:", (white_list_new.c_str()));
	}
}


void GargoylePscandHandler::set_iptables_supports_xlock(size_t support_xlock) {
	IPTABLES_SUPPORTS_XLOCK = support_xlock;
}


void GargoylePscandHandler::set_db_location(const char *db_loc) {
	if (db_loc) {
		DB_LOCATION = db_loc;
	}
}


bool GargoylePscandHandler::is_in_hot_ports(int the_port) {
	
	std::vector<int>::const_iterator hot_ports_iter = std::find(HOT_PORTS.begin(), HOT_PORTS.end(), the_port);
	if (hot_ports_iter != HOT_PORTS.end())
		return true;
	return false;
	
}


void GargoylePscandHandler::add_to_hot_ports_list(int the_port) {
	if (the_port > 0) {
		if (!is_in_hot_ports(the_port)) {
			HOT_PORTS.push_back(the_port);
		}
	}
}
/////////////////////////////////////////////////////////////////////////////////
