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
#ifndef _PACKETHANDLERS_H__
#define _PACKETHANDLERS_H__


#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sstream>

#ifdef __cplusplus
extern "C" {
#endif
#include <libnetfilter_log/libnetfilter_log.h>
#ifdef __cplusplus
}
#endif


/* 
 * This handler recv's packets from the NetFilter
 * Queue and interacts with the DB and iptables
 */
class GargoylePscandHandler
{
	public:
	GargoylePscandHandler();
	
	// netfilter callback
	static int packet_handle(struct nflog_g_handle *, struct nfgenmsg *, struct nflog_data *, void *);
	
	void add_to_white_listed_entries(std::string);
	void add_to_ports_entries(int);
	void add_to_hot_ports_list(int);
	void set_ignore_local_ip_addrs(bool);
	void set_ephemeral_low(size_t);
	void set_ephemeral_high(size_t);
	void set_chain_name(std::string);
	void set_enforce_mode(bool);
	void set_single_ip_scan_threshold(size_t);
	void set_single_port_scan_threshold(size_t);
	void set_iptables_supports_xlock(size_t);
	void set_db_location(const char *);
	

	protected:
	
	void three_way_check(std::string, int, std::string, int, int, int, std::vector<int>);
	void main_port_scan_check(std::string, int, std::string, int, int, int, std::vector<int>);
	void add_to_scanned_ports_dict(std::string, int);
	void add_block_rule(std::string, int);
	void add_block_rules();

	void refresh_white_listed_entries();
	void process_ignore_ip_list();
	void clear_three_way_check_dat();
	void clear_reverse_three_way_check_dat();
	void clear_src_ip_dst_ip_dat();
	void clear_reverse_src_ip_dst_ip_dat();
	
	void display_scanned_ports_dict();
	void display_local_ip_addr();
	void display_hot_ports();
	
	int half_connect_scan(std::string, int, std::string, int, int, int, std::vector<int>);
	int full_connect_scan(std::string, int, std::string, int, int, int, std::vector<int>);
	int xmas_scan(std::string, int, std::string, int, int, int, std::vector<int>);
	int fin_scan(std::string, int, std::string, int, int, int, std::vector<int>);
	int null_scan(std::string, int, std::string, int, int, int, std::vector<int>);
	int add_ip_to_hosts_table(std::string);
	
	bool is_in_waiting(std::string);
	bool is_in_black_listed_hosts(std::string);
	bool is_white_listed_ip_addr(std::string);
	bool is_in_ports_entries(int);
	bool is_in_scanned_ports_cnt_dict(std::string);
	bool is_in_three_way_handshake(std::string);
	bool is_in_ephemeral_range(int);
	bool ignore_this_port(int);
	bool is_in_hot_ports(int);
	
	private:
	
	bool IGNORE_WHITE_LISTED_IP_ADDRS;
	int EPHEMERAL_LOW;
	int EPHEMERAL_HIGH;
	std::string CHAIN_NAME;
	bool ENFORCE;
	size_t PH_SINGLE_IP_SCAN_THRESHOLD;
	size_t PH_SINGLE_PORT_SCAN_THRESHOLD;
	size_t IPTABLES_SUPPORTS_XLOCK;
	std::string DB_LOCATION;
	
	std::ostringstream three_way_check_dat;
	std::ostringstream reverse_three_way_check_dat;
	std::ostringstream src_ip_dst_ip_dat;
	std::ostringstream reverse_src_ip_dst_ip_dat;
	
	std::vector<std::string> WHITE_LISTED_IP_ADDRS;
	std::vector<int> IGNORE_PORTS;
	std::vector<int>::const_iterator ports_iter;
	std::vector<int> HOT_PORTS;
	
	std::set<std::string> THREE_WAY_HANDSHAKE;
	std::set<std::string>::iterator twh_it;
	std::set<std::string> WAITING;
	std::set<std::string> BLACK_LISTED_HOSTS;
	
	std::map< std::string, std::pair <int, int> > SCANNED_PORTS_CNT_DICT;
};



#endif // _PACKETHANDLERS_H__
