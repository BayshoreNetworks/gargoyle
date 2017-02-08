/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
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
#include "string_functions.h"

int FLAGS_LIST[] = {128, 64, 32, 16, 8, 4, 2, 1};

/*
 * when ADD_RULES_KNOWN_SCAN_AGGRESSIVE is true
 * automatic blocks will take place when known
 * techniques (NULL, FIN, XMAS, etc) are
 * detected
 */
bool ADD_RULES_KNOWN_SCAN_AGGRESSIVE = true;

bool DEBUG = true;

int BASE_TIME;
//int PROCESS_TIME_CHECK = 120;
int PROCESS_TIME_CHECK = 60;
size_t PH_SINGLE_IP_SCAN_THRESHOLD = 6;
size_t PH_SINGLE_PORT_SCAN_THRESHOLD = 5;
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


static uint16_t checksum(const uint16_t* buf, unsigned int nbytes)
{
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

/////////////////////////////////////////////////////////////////////////////////
void CompoundHandler::add_handler(PacketHandler& handler) {
	_handlers.push_back(&handler);
}


int CompoundHandler::handle_packet(Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) {
	for (list_t::iterator it = _handlers.begin(); it != _handlers.end(); ++it)
	{
		int ret = (*it)->handle_packet(queue, nfmsg, nfad);
		if (ret < 0)
			return ret;
	}
	return 0;
}
/////////////////////////////////////////////////////////////////////////////////
GargoylePscandHandler::GargoylePscandHandler() {
	BASE_TIME = (int) time(NULL);
	ENFORCE = true;
	PH_SINGLE_IP_SCAN_THRESHOLD = 6;
	PH_SINGLE_PORT_SCAN_THRESHOLD = 5;
}

int GargoylePscandHandler::handle_packet(Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad)
{
	int id = 0;

	//printf("%s", _prefix.c_str());

	struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	struct nfqnl_msg_packet_hw* hwph = nfq_get_packet_hw(nfad);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);
		/*
		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		 */
	}
	u_int32_t mark = nfq_get_nfmark(nfad);
	/*
	if (mark)
		printf("mark=%u ", mark);
	 */
	u_int32_t ifi = nfq_get_indev(nfad);
	/*
	if (ifi)
		printf("indev=%u ", ifi);
	 */
	ifi = nfq_get_outdev(nfad);
	/*
	if (ifi)
		printf("outdev=%u ", ifi);
	 */
	ifi = nfq_get_physindev(nfad);
	/*
	if (ifi)
		printf("physindev=%u ", ifi);
	 */
	ifi = nfq_get_physoutdev(nfad);
	/*
	if (ifi)
		printf("physoutdev=%u ", ifi);
	 */
	unsigned char *data;
	int ret = nfq_get_payload(nfad, &data);
	/*
	if (ret >= 0)
		printf("payload_len=%d ", ret);
	 */
	if ((unsigned int)ret >= sizeof(struct iphdr))
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

			// DO WE IGNORE THIS DST IP?

			// we don't ignore this port
			if (ignore_this_port(dst_port) == false) {

				/*
				 * in_addr - a statically allocated buffer, which subsequent calls overwrite
				 * so it can't be used twice in a function, have to write out results and
				 * do again
				 */
				struct in_addr src_addr = {ip->saddr};
				std::string s_src(inet_ntoa(src_addr));
				struct in_addr dst_addr = {ip->daddr};
				std::string s_dst(inet_ntoa(dst_addr));

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

				//twh_it = THREE_WAY_HANDSHAKE.find(testdata);
				bool is_in = THREE_WAY_HANDSHAKE.find(testdata) != THREE_WAY_HANDSHAKE.end();
				if (is_in == false)
					three_way_check(s_src,src_port,s_dst,dst_port,seq_num,ack_num,tcp_flags);

				main_port_scan_check(s_src,src_port,s_dst,dst_port,seq_num,ack_num,tcp_flags);
			}
		} // end of TCP handling

		// UDP
		// TODO

		///////////////////////////////////////////////////////////////////////////////
		/*
		 * process to run at certain intervals (2 minutes currently)
		 * this is what flushes data from mempory and blocks stuff
		 * if appropriate
		 */
		if (((int)time(NULL) - BASE_TIME) >= PROCESS_TIME_CHECK) {
			//std::cout << "TIME CHECK" << BASE_TIME << std::endl;
			
			// are there any new white list entries in the DB?
			process_ignore_ip_list();

			add_block_rules();
			BASE_TIME = (int)time(NULL);
		}
		///////////////////////////////////////////////////////////////////////////////
	}
	// let packets go through here
	queue.setVerdict(id, NF_ACCEPT, 0, NULL);
	return 0;
}



void GargoylePscandHandler::three_way_check(
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


bool GargoylePscandHandler::is_in_half_scan_dict(std::string s) {

	if(HALF_SCAN_DICT.find(s) != HALF_SCAN_DICT.end())
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


bool GargoylePscandHandler::is_in_ip_entries(std::string s) {


	std::vector<std::string>::const_iterator local_ip_iter;
	local_ip_iter = std::find(LOCAL_IP_ADDRS.begin(), LOCAL_IP_ADDRS.end(), s);
	if (local_ip_iter != LOCAL_IP_ADDRS.end())
		return true;
	return false;

	/*
	for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
		std::cout << *i << " - " << s << " - " << (*i).compare(s) << std::endl;
		if ((*i).compare(s) == 0)
			return true;
	}
	return false;
	 */
}


bool GargoylePscandHandler::is_in_ports_entries(int s) {

	ports_iter = std::find(IGNORE_PORTS.begin(), IGNORE_PORTS.end(), s);
	if (ports_iter != IGNORE_PORTS.end())
		return true;
	return false;
}



void GargoylePscandHandler::add_to_ip_entries(std::string s) {
	if (is_in_ip_entries(s) == false)
		LOCAL_IP_ADDRS.push_back(s);
}


void GargoylePscandHandler::add_to_ports_entries(int s) {
	if (is_in_ports_entries(s) == false)
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

	int half_connect_ret;
	half_connect_ret = half_connect_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

	//std::cout << "half_connect_ret: " << half_connect_ret << std::endl;
	if (half_connect_ret == 0 || half_connect_ret == 2) {

		if (half_connect_ret == 2) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "Half Connect (SYN scan) port scan detected");
		}
		if (half_connect_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", "Generic port scan (half connection) detected - attempt to connect to closed port", (three_way_check_dat.str()).c_str());
		}
		return;
	}

	int full_connect_ret;
	full_connect_ret = 1;
	if (half_connect_ret == 1) {
		full_connect_ret = full_connect_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		if (full_connect_ret == 0 || full_connect_ret == 2) {
			if (full_connect_ret == 2) {
				syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (reverse_three_way_check_dat.str()).c_str(), "FULL Connect port scan detected");
			}
			if (full_connect_ret == 0) {
				syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", "Generic port scan (full connection) detected - attempt to connect to closed port", (reverse_three_way_check_dat.str()).c_str());
			}
			return;
		}
	}


	int xmas_scan_ret;
	if (full_connect_ret == 1) {
		xmas_scan_ret = xmas_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "xmas_scan_ret: " << xmas_scan_ret << std::endl;

		if (xmas_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "XMAS port scan detected");
			return;
		}
	}

	int fin_scan_ret;
	if (xmas_scan_ret == 1) {
		fin_scan_ret = fin_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "fin_scan_ret: " << fin_scan_ret << std::endl;

		if (fin_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "FIN port scan detected");
			return;
		}
	}


	int null_scan_ret;
	if (fin_scan_ret == 1) {
		null_scan_ret = null_scan(src_ip,src_port,dst_ip,dst_port,seq_num,ack_num,tcp_flags);

		//std::cout << "null_scan_ret: " << null_scan_ret << std::endl;

		if (null_scan_ret == 0) {
			syslog(LOG_INFO | LOG_LOCAL6, "%s - %s", (three_way_check_dat.str()).c_str(), "NULL port scan detected");
			return;
		}
	}


	/*
	 * if we are here that means that none of the
	 * previous checks yielded anything, but we will
	 * keep track of the data in SCANNED_PORTS_CNT_DICT anyway
	 * 
	 * But we ignore locally bound ip addr's if that flag is set
	 */
	if (IGNORE_LOCAL_IP_ADDRS) {
		if (is_in_ip_entries(src_ip) == false) {
			add_to_scanned_ports_dict(src_ip, dst_port);
		}
	}

	//std::cout << "WTF1 -" << three_way_check_dat.str() << std::endl << reverse_three_way_check_dat.str() << std::endl << src_ip_dst_ip_dat.str() << std::endl << reverse_src_ip_dst_ip_dat.str() << "WTF2" << std::endl;


}


/*
 * return 0 = "Generic port scan (full connection) detected - attempt to connect to closed port"
 * return 1 = nothing discovered here
 * return 2 = "Full Connect port scan detected"
 */
int GargoylePscandHandler::full_connect_scan(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	// TODO

	/*
	if (is_in_three_way_handshake(three_way_check_dat.str())) {

		if ((tcp_flags.size() == 2) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 4) != tcp_flags.end()) && 
				(std::find(tcp_flags.begin(), tcp_flags.end(), 16) != tcp_flags.end())) { // flags = ACK,RST - len flags = 2

		}

	} else {

	}

	 */

	return 1;
}



/*
 * return 0 = "Generic port scan (half connection) detected - attempt to connect to closed port"
 * return 1 = nothing discovered here
 * return 2 = "Half Connect (SYN scan) port scan detected"
 */
int GargoylePscandHandler::half_connect_scan(
		std::string src_ip,
		int src_port,
		std::string dst_ip,
		int dst_port,
		int seq_num,
		int ack_num,
		std::vector<int> tcp_flags) {

	if (ignore_this_port(dst_port) == false) {
		if (seq_num > 0 && ack_num == 0 && tcp_flags.size() == 1 && tcp_flags[0] == 2) { // flags = SYN - len flags = 1 - seq_num > 0 - ack_num = 0

			std::ostringstream key1;
			key1 << src_ip_dst_ip_dat.str() << "_" << seq_num;
			std::ostringstream val1;
			val1 << src_ip_dst_ip_dat.str() << "_SYN_ACK_" << seq_num << "_" << ack_num;
			HALF_SCAN_DICT.insert(std::make_pair(key1.str(), val1.str()));
			//HALF_SCAN_DICT["{}_{}".format(src_ip_dst_ip_dat, str(seq_num))] = "{}_SYN_ACK_{}_{}".format(src_ip_dst_ip_dat, str(seq_num), str(ack_num))

		} else if ((tcp_flags.size() == 2) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 4) != tcp_flags.end()) && 
				(std::find(tcp_flags.begin(), tcp_flags.end(), 16) != tcp_flags.end())) { // flags = ACK,RST - len flags = 2

			std::ostringstream key1;
			key1 << reverse_src_ip_dst_ip_dat.str() << "_" << (ack_num - 1);

			if (is_in_half_scan_dict(key1.str())) {

				HALF_SCAN_DICT.erase(key1.str());

				if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE)
					add_block_rule(dst_ip, 4);
				add_to_scanned_ports_dict(dst_ip, src_port);

				if (is_in_black_listed_hosts(dst_ip) == false)
					BLACK_LISTED_HOSTS.insert(dst_ip);

				return 0;
			}
		} else if((tcp_flags.size() == 2) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 2) != tcp_flags.end()) && 
				(std::find(tcp_flags.begin(), tcp_flags.end(), 16) != tcp_flags.end())) { // flags = SYN,ACK - len flags = 2

			std::ostringstream key1;
			key1 << reverse_src_ip_dst_ip_dat.str() << "_" << (ack_num - 1);

			if (is_in_half_scan_dict(key1.str())) {

				HALF_SCAN_DICT.erase(key1.str());

				std::ostringstream key2;
				key2 << reverse_src_ip_dst_ip_dat.str() << "_" << ack_num;
				std::ostringstream val1;
				val1 << src_ip_dst_ip_dat.str() << "_RST_" << seq_num << "_" << ack_num;
				HALF_SCAN_DICT.insert(std::make_pair(key2.str(), val1.str()));
			}
		} else if (tcp_flags.size() == 1 && tcp_flags[0] == 4) { // flags = RST - len flags = 1

			std::ostringstream key1;
			key1 << src_ip_dst_ip_dat.str() << "_" << seq_num;

			if (is_in_half_scan_dict(key1.str())) {

				if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE)
					add_block_rule(dst_ip, 4);
				add_to_scanned_ports_dict(dst_ip, src_port);

				if (is_in_black_listed_hosts(dst_ip) == false)
					BLACK_LISTED_HOSTS.insert(dst_ip);

				return 2;
			}
		}
	}
	return 1;
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

	if (IGNORE_LOCAL_IP_ADDRS) {
		if (is_in_ip_entries(the_ip) == true) {
			return;
		}
	}


	if (the_ip.size() > 0 && the_port > 0) {

		/*
		 * we ignore ephemeral ports as blocking them will disrupt
		 * legitimate functionality on the running host
		 */
		if (the_port < EPHEMERAL_LOW || the_port > EPHEMERAL_HIGH) {

			int tstamp = (int) time(NULL);

			if (is_in_ports_entries(the_port) == false) {

				//std::cout << "WTFWTFWTF" << std::endl;

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
}


void GargoylePscandHandler::set_ignore_local_ip_addrs(bool val) {
	IGNORE_LOCAL_IP_ADDRS = val;
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
	for (std::vector<std::string>::const_iterator i = LOCAL_IP_ADDRS.begin(); i != LOCAL_IP_ADDRS.end(); ++i) {
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
		if (IGNORE_LOCAL_IP_ADDRS) {
			if (is_in_ip_entries(the_ip) == true) {
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


		/*
		// whats active in iptables?
		resp = get_detected_hosts_all_active_unprocessed_host_ix(l_hosts, dst_buf_sz);
		if (resp == 0) {
			token1 = strtok_r(l_hosts, tok1, &token1_save);
			while (token1 != NULL) {

				*host_ip = 0;
				get_host_by_ix(atoi(token1), host_ip, dst_buf_sz1);

				//std::cout << "A: " << host_ip << std::endl;

				ip_tables_entries.insert(host_ip);

				token1 = strtok_r(NULL, tok1, &token1_save);
			}
		}
		*/
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
			added_host_ix = do_block_actions(the_ip, detection_type);

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
		added_host_ix = add_host(the_ip.c_str());
		// already exists
		if (added_host_ix == -1) {
			// get existing index
			added_host_ix = get_host_ix(the_ip.c_str());
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

	if (ignore_this_port(dst_port) == false || is_in_ip_entries(src_ip) == false) {
		if((tcp_flags.size() == 3) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 1) != tcp_flags.end()) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 8) != tcp_flags.end()) &&
				(std::find(tcp_flags.begin(), tcp_flags.end(), 32) != tcp_flags.end())) { // flags = FIN,URG,PSH - len flags = 3


			if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
				add_block_rule(src_ip, 3);
				
				int host_ix = add_ip_to_hosts_table(src_ip);
				if (host_ix > 0)
					add_to_hosts_port_table(host_ix, dst_port, 1);
			}

			add_to_scanned_ports_dict(dst_ip, src_port);

			if (is_in_black_listed_hosts(src_ip) == false) {
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

	if (ignore_this_port(dst_port) == false || is_in_ip_entries(src_ip) == false) {
		if (is_in_three_way_handshake(three_way_check_dat.str()) == false) {

			if(tcp_flags.size() == 1 && tcp_flags[0] == 1) { // flags = FIN - len flags = 1

				if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
					add_block_rule(src_ip, 2);
					
					int host_ix = add_ip_to_hosts_table(src_ip);
					if (host_ix > 0)
						add_to_hosts_port_table(host_ix, dst_port, 1);
				}

				add_to_scanned_ports_dict(dst_ip, src_port);

				if (is_in_black_listed_hosts(src_ip) == false) {
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

	if (ignore_this_port(dst_port) == false || is_in_ip_entries(src_ip) == false) {
		if(tcp_flags.size() == 0) {

			if (ADD_RULES_KNOWN_SCAN_AGGRESSIVE) {
				
				add_block_rule(src_ip, 1);
				
				int host_ix = add_ip_to_hosts_table(src_ip);
				if (host_ix > 0) {
					add_to_hosts_port_table(host_ix, dst_port, 1);
				}
			}

			add_to_scanned_ports_dict(dst_ip, src_port);
			
			if (is_in_black_listed_hosts(src_ip) == false) {
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


bool GargoylePscandHandler::ignore_this_addr(std::string the_ip) {



	return false;
}


void GargoylePscandHandler::add_block_rules() {

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

	/*
	 * get current list of blocked ip's from the DB
	 * 
	 * seems faster this way cause iptables queries are
	 * very expensive
	 */
	// whats active in iptables?
	/*
	resp = get_detected_hosts_all_active_unprocessed_host_ix(l_hosts, dst_buf_sz);
	if (resp == 0) {
		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {

			*host_ip = 0;
			get_host_by_ix(atoi(token1), host_ip, dst_buf_sz1);

			ip_tables_entries.insert(host_ip);

			//std::cout << "IP: " << host_ip << " - STRLEN: " << strlen(host_ip) << std::endl;

			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	*/
	
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
		if (IGNORE_LOCAL_IP_ADDRS) {
			if (is_in_ip_entries(*it) == true) {
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
			added_host_ix = do_block_actions(*it, 0);

			ip_tables_entries.insert(*it);
		} else {
			// exists in iptables but we need to put
			// some data in the DB
			added_host_ix = get_host_ix((*it).c_str());
			if (added_host_ix == 0)
				added_host_ix = add_ip_to_hosts_table(*it);
		}

		// add to DB
		if (added_host_ix > 0) {
			add_detected_host(added_host_ix, tstamp);
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

	std::map< std::string, std::pair <int, int> >::iterator s_port_it = SCANNED_PORTS_CNT_DICT.begin();
	while(s_port_it != SCANNED_PORTS_CNT_DICT.end()) {

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

					do_block_actions(the_ip, 7);

					ip_tables_entries.insert(the_ip);
				}
			}
			
			//syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%d\"", "host_ix", added_host_ix);
			
			if (added_host_ix > 0 && is_in_ip_entries(the_ip) == false) {
				add_to_hosts_port_table(added_host_ix, the_port, the_cnt);
			}

			/*
			 * do some output to syslog in case
			 * this data is being used for analytics
			 */
			syslog(LOG_INFO | LOG_LOCAL6, "%s=\"%s\" %s=\"%d\" %s=\"%d\" %s=\"%d\"",
					VIOLATOR_SYSLOG, the_ip.c_str(), "port", the_port, "hits", the_cnt, TIMESTAMP_SYSLOG, tstamp);
		}
		//std::cout << "IP: " << the_ip << " - port " << the_port << " - CNT " << the_cnt << std::endl;

		SCANNED_PORTS_CNT_DICT.erase(current_key);
		s_port_it++;
	}

	std::map<std::string, int>::iterator loc_ip_it = LOCAL_IP_ROW_CNT.begin();
	while(loc_ip_it != LOCAL_IP_ROW_CNT.end()) {

		//std::cout << "VIOLATOR: " << loc_ip_it->first << " - CNT: " << loc_ip_it->second << std::endl;

		if (loc_ip_it->second >= PH_SINGLE_IP_SCAN_THRESHOLD) {

			if (ip_tables_entries.count(loc_ip_it->first) == 0) {

				do_block_actions(loc_ip_it->first, 6);

				ip_tables_entries.insert(loc_ip_it->first);	
			}
		}
		loc_ip_it++;
	}

	free(l_hosts);
	free(host_ip);
	if (LOCAL_IP_ROW_CNT.size() > 0)
		LOCAL_IP_ROW_CNT.clear();
}


void GargoylePscandHandler::add_to_hosts_port_table(int added_host_ix, int the_port, int the_cnt) {

	/*
	 * call get_host_port_hit to see if the ip addr/port combo
	 * already exists in the DB. if it does then call the update
	 * function, otherwise add the data into a new record
	 */
	if (added_host_ix > 0 && the_port > 0 && the_cnt > 0) {

		int resp;
		//number of hits registered in the DB
		resp = get_host_port_hit(added_host_ix, the_port);

		// new record
		if (resp == 0) {
			add_host_port_hit(added_host_ix, the_port, the_cnt);
		} else if (resp >= 1) {
			int u_cnt = resp + the_cnt;
			update_host_port_hit(added_host_ix, the_port, u_cnt);
		}
	}
}


int GargoylePscandHandler::do_block_actions(std::string the_ip, int detection_type) {

	int host_ix;
	host_ix = 0;

	host_ix = get_host_ix(the_ip.c_str());
	if (host_ix == 0)
		host_ix = add_ip_to_hosts_table(the_ip);

	//syslog(LOG_INFO | LOG_LOCAL6, "%d-%s=\"%d\" %s=\"%d\"", ENFORCE, "host_ix", host_ix, "size", the_ip.size());
	
	if (the_ip.size() > 0 and host_ix > 0) {
		
		// we dont ignore this ip
		if (is_in_ip_entries(the_ip) == false) {

			size_t ret;
			int tstamp;
			tstamp = (int) time(NULL);
	
			if (ENFORCE == true)
				ret = iptables_add_drop_rule_to_chain(CHAIN_NAME.c_str(), the_ip.c_str(), IPTABLES_SUPPORTS_XLOCK);
	
			if (detection_type > 0) {
				syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\" %s=\"%d\"",
						BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(), DETECTION_TYPE_SYSLOG,
						detection_type, TIMESTAMP_SYSLOG, tstamp);
			} else {
				syslog(LOG_INFO | LOG_LOCAL6, "%s-%s=\"%s\" %s=\"%d\"",
						BLOCKED_SYSLOG, VIOLATOR_SYSLOG, the_ip.c_str(), TIMESTAMP_SYSLOG, tstamp);
			}
	
			// add to DB
			add_detected_host(host_ix, tstamp);
		}
	}
	return host_ix;
}


void GargoylePscandHandler::set_enforce_mode(bool b_val) {
	if (b_val == true || b_val == false)
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


void GargoylePscandHandler::process_ignore_ip_list() {

	const char *tok1 = ">";
	char *token1;
	char *token1_save;

	size_t dst_buf_sz = SMALL_DEST_BUF + 1;
	char *l_hosts = (char*) malloc(dst_buf_sz);
	size_t dst_buf_sz1 = LOCAL_BUF_SZ;
	char *host_ip = (char*) malloc(dst_buf_sz1 + 1);

	size_t resp = get_hosts_to_ignore_all(l_hosts, dst_buf_sz);
	
	if (resp == 0) {

		token1 = strtok_r(l_hosts, tok1, &token1_save);
		while (token1 != NULL) {
			
			if (atoi(token1) > 0) {
			
				int host_ix = atoi(token1);
				get_host_by_ix(host_ix, host_ip, dst_buf_sz1);
				
				if (strcmp(host_ip, "") != 0) {
					add_to_ip_entries(host_ip);
				
				
					/*
					 * this is ugly but ....
					 * extra cleanup check in case we
					 * aggressively blocked (race condition)
					 * an ip addr that has been whitelisted
					 */
					size_t rule_ix = iptables_find_rule_in_chain(GARGOYLE_CHAIN_NAME, host_ip, IPTABLES_SUPPORTS_XLOCK);
					if(rule_ix > 0) {
						
						size_t row_ix = get_detected_hosts_row_ix_by_host_ix(host_ix);
						
						if (row_ix > 0) {

							// delete all records for this host_ix from hosts_ports_hits table
							remove_host_ports_all(host_ix);
							
							// delete row from detected_hosts
							remove_detected_host(row_ix);
							
							// reset last_seen to 1972
							update_host_last_seen(host_ix);
							
							iptables_delete_rule_from_chain(GARGOYLE_CHAIN_NAME, rule_ix, IPTABLES_SUPPORTS_XLOCK);
						}
					}
				}
			}
			token1 = strtok_r(NULL, tok1, &token1_save);
		}
	}
	free(l_hosts);
	free(host_ip);
}



void GargoylePscandHandler::set_iptables_supports_xlock(size_t support_xlock) {
	IPTABLES_SUPPORTS_XLOCK = support_xlock;
}
/////////////////////////////////////////////////////////////////////////////////


