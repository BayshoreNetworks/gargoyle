/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Shared memory database
 *
 * Copyright (c) 2016 - 2018, Bayshore Networks, Inc.
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

#ifndef DATA_BASE_H
#define DATA_BASE_H

#include "shared_memory_table.h"
#include <string>
#include <time.h>

#define LENGTH_IPV4	16

struct Black_IP_List_Record{
	uint32_t ix;
	uint32_t host_ix;
	time_t timestamp;
}__attribute__((packed));

struct Detected_Hosts_Record{
	uint32_t ix;
	uint32_t host_ix;
	time_t timestamp;
}__attribute__((packed));

struct Hosts_Ports_Hits_Record{
	uint32_t ix;
	uint32_t host_ix;
	uint32_t port_number;
	uint32_t hit_count;
}__attribute__((packed));

struct Hosts_Record{
	uint32_t ix;
	char host[LENGTH_IPV4];
	time_t first_seen;
	time_t last_seen;
}__attribute__((packed));

struct Ignore_IP_List_Record{
	uint32_t ix;
	uint32_t host_ix;
	time_t timestamp;
}__attribute__((packed));


class Black_IP_List_Table : public SharedMemoryTable<Black_IP_List_Record>{
	public:
		Black_IP_List_Table(std::string name, size_t size);
		static Black_IP_List_Table *CREATE(std::string name, size_t size);
		int32_t INSERT(Black_IP_List_Record entry);
		int32_t DELETE(const std::string &query);
		int32_t SELECT(char * result, const std::string &query);
        int32_t UPDATE(const Black_IP_List_Record &entry);
        uint32_t getPositionByKey(const uint32_t key);
};

class Detected_Hosts_Table : public SharedMemoryTable<Detected_Hosts_Record>{
	public:
		Detected_Hosts_Table(std::string name, size_t size);
		static Detected_Hosts_Table *CREATE(std::string name, size_t size);
		int32_t INSERT(Detected_Hosts_Record entry);
		int32_t DELETE(const std::string &query);
		int32_t SELECT(char * result, const std::string &query);
        int32_t UPDATE(const Detected_Hosts_Record &entry);
        uint32_t getPositionByKey(const uint32_t key);
};

class Hosts_Ports_Hits_Table : public SharedMemoryTable<Hosts_Ports_Hits_Record>{
	public:
		Hosts_Ports_Hits_Table(std::string name, size_t size);
		static Hosts_Ports_Hits_Table *CREATE(std::string name, size_t size);
		int32_t INSERT(Hosts_Ports_Hits_Record entry);
		int32_t DELETE(const std::string &query);
		int32_t SELECT(char * result, const std::string &query);
        int32_t UPDATE(const Hosts_Ports_Hits_Record &entry);
        uint32_t getPositionByKey(const uint32_t key);
};

class Hosts_Table : public SharedMemoryTable<Hosts_Record>{
	private:
		static const unsigned NUMBER_FIELDS_TABLE {4};
		enum {ix, host, first_seen, last_seen};
		const std::string FIELDS[NUMBER_FIELDS_TABLE] = {"ix", "host", "first_seen", "last_seen"};
	public:
		Hosts_Table(std::string name, size_t size);
		static Hosts_Table *CREATE(std::string name, size_t size);
		int32_t INSERT(Hosts_Record entry);
		int32_t DELETE(const std::string &query);
		int32_t SELECT(char * result, const std::string &query);
        int32_t UPDATE(const Hosts_Record &entry);
        uint32_t getPositionByKey(const uint32_t key);
};

class Ignore_IP_List_Table : public SharedMemoryTable<Ignore_IP_List_Record>{
	public:
		Ignore_IP_List_Table(std::string name, size_t size);
		static Ignore_IP_List_Table *CREATE(std::string name, size_t size);
		int32_t INSERT(Ignore_IP_List_Record entry);
		int32_t DELETE(const std::string &query);
		int32_t SELECT(char * result, const std::string &query);
        int32_t UPDATE(const Ignore_IP_List_Record &entry);
        uint32_t getPositionByKey(const uint32_t key);
};

struct DataBase{
	enum {black_ip_list_table, detected_hosts_table, hosts_ports_hits_table,
		hosts_table, ignore_ip_list_table};
	static const int TABLES_NUMBER = 5;
	const std::string TABLES_NAME[TABLES_NUMBER] = {"black_ip_list_table", "detected_hosts_table",
			"hosts_ports_hits_table", "hosts_table", "ignore_ip_list_table"};
	DataBase();
	~DataBase();
	Black_IP_List_Table *black_ip_list;
	Detected_Hosts_Table *detected_hosts;
	Hosts_Ports_Hits_Table *hosts_ports_hits;
	Hosts_Table *hosts;
	Ignore_IP_List_Table *ignore_ip_list;
	static DataBase *create();
	void cleanTables(const std::string &);
};

#endif
