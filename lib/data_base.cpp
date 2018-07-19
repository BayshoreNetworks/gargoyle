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

#include "data_base.h"
#include "gargoyle_config_vals.h"


#include <string>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <list>

using namespace std;


DataBase::DataBase(){
	black_ip_list = Black_IP_List_Table::CREATE(GARGOYLE_BLACK_IP_LIST_TABLE_NAME, GARGOYLE_BLACK_IP_LIST_TABLE_SIZE);
 	detected_host = Detected_Hosts_Table::CREATE(GARGOYLE_DETECTED_HOSTS_TABLE_NAME, GARGOYLE_DETECTED_HOSTS_TABLE_SIZE);
	hosts_ports_hits = Hosts_Ports_Hits_Table::CREATE(GARGOYLE_HOSTS_PORTS_HITS_TABLE_NAME, GARGOYLE_HOSTS_PORTS_HITS_TABLE_SIZE);
	hosts = Hosts_Table::CREATE(GARGOYLE_HOSTS_TABLE_NAME, GARGOYLE_HOSTS_TABLE_SIZE);
	ignore_ip_list = Ignore_IP_List_Table::CREATE(GARGOYLE_IGNORE_IP_LIST_TABLE_NAME, GARGOYLE_IGNORE_IP_LIST_TABLE_SIZE);
}

DataBase::~DataBase(){
	if(black_ip_list != nullptr){
		delete black_ip_list;
	}

	if(detected_host != nullptr){
		delete detected_host;
	}

	if(hosts_ports_hits != nullptr){
		delete hosts_ports_hits;
	}

	if(hosts != nullptr){
		delete hosts;
	}

	if(ignore_ip_list != nullptr){
		delete ignore_ip_list;
	}
}

DataBase *DataBase::create(){
	DataBase *config = new DataBase();
	return config;
}

void DataBase::cleanTables(const string &tables){
	if(tables == "all" || tables == TABLES_NAME[black_ip_list_table]){
		black_ip_list->TRUNCATE();
	}

	if(tables == "all" || tables == TABLES_NAME[detected_host_table]){
		detected_host->TRUNCATE();
	}

	if(tables == "all" || tables == TABLES_NAME[hosts_ports_hits_table]){
		hosts_ports_hits->TRUNCATE();
	}

	if(tables == "all" || tables == TABLES_NAME[hosts_table]){
		hosts->TRUNCATE();
	}

	if(tables == "all" || tables == TABLES_NAME[ignore_ip_list_table]){
		ignore_ip_list->TRUNCATE();
	}
}

/*
 * CREATE TABLE black_ip_list (ix INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
 * host_ix INTEGER NOT NULL UNIQUE, timestamp INTEGER NOT NULL, FOREIGN KEY(host_ix)
 * REFERENCES hosts_table (ix));
 */
Black_IP_List_Table::Black_IP_List_Table(string name, size_t size):SharedMemoryTable(name, size){}

Black_IP_List_Table *Black_IP_List_Table::CREATE(string name, size_t size){
	Black_IP_List_Table *config = new Black_IP_List_Table(name, size);
	if(config->init() < 0){
		delete config;
		config = nullptr;
	}
	return config;
}

int32_t Black_IP_List_Table::INSERT(Black_IP_List_Record &entry){
	int32_t status;
	if((status = lock()) == 0){
		if(compareAndExpand() < 0){
			status = -1;
		}else{
			Black_IP_List_Record *match = std::find_if(begin(), end(), [entry](const Black_IP_List_Record &record){return record.host_ix == entry.host_ix;});
			if(!isIn(match)){
				if(entry.ix == 0){
					entry.ix = size() == 0 ? 1 : size();
				}
				status = pushBack(entry);
			}else{
				status = -1;
			}
		}
		unlock();
	}
	return status;
}

int32_t Black_IP_List_Table::DELETE(const std::string &query){
	cout << "DELETE" << endl;
	return 0;
}

int32_t Black_IP_List_Table::SELECT(char *result, const string &query){
	int32_t status = 0;
	if(query.find("SELECT host_ix FROM black_ip_list") != std::string::npos){
		Black_IP_List_Record record;
		if(lock() == 0){
			for(int i=0; i<size(); i++){
				status = getRecordByPos(record, i);
				sprintf(result, "%s%u>", result, record.host_ix);
				if(status == -1){
					break;
				}
			}
			unlock();
		}
	}
	return status;
}

int32_t Black_IP_List_Table::UPDATE(const Black_IP_List_Record &entry){
	return 0;
}

/*
 * CREATE TABLE detected_hosts (ix INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, host_ix INTEGER NOT NULL UNIQUE,
 *  timestamp TEXT NOT NULL, FOREIGN KEY(host_ix) REFERENCES hosts_table (ix));
 */
Detected_Hosts_Table::Detected_Hosts_Table(string name, size_t size):SharedMemoryTable(name, size){}

Detected_Hosts_Table *Detected_Hosts_Table::CREATE(string name, size_t size){
	Detected_Hosts_Table *config = new Detected_Hosts_Table(name, size);
	if(config->init() < 0){
		delete config;
		config = nullptr;
	}
	return config;
}

int32_t Detected_Hosts_Table::INSERT(Detected_Hosts_Record &entry){
	int32_t status;
	if((status = lock()) == 0){
		if(compareAndExpand() < 0){
			status = -1;
		}else{
			// host_ix is UNIQUE
			Detected_Hosts_Record *match = std::find_if(begin(), end(), [entry](const Detected_Hosts_Record &record){return record.host_ix == entry.host_ix;});
			if(!isIn(match)){
				if(entry.ix == 0){
					entry.ix = size() == 0 ? 1 : size();
				}
				status = pushBack(entry);
			}else{
				status = -1;
			}
		}
		unlock();
	}
	return status;
}

int32_t Detected_Hosts_Table::DELETE(const std::string &query){
	int32_t status = 0;
	if(query.find("DELETE FROM detected_hosts WHERE ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string value(query, ++pos, query.length() - pos);
		uint32_t ix = atol(value.c_str());
		if(lock() != 0){
			status = deleteRecordByPos(ix);
			unlock();
		}
	}

	if(query.find("DELETE FROM detected_hosts") != std::string::npos){
		if(lock() != 0){
			deleteAll();
			unlock();
		}
	}
	return status;
}

int32_t Detected_Hosts_Table::SELECT(char *result, const string &query){
	int32_t status = -1;
	if(query.find("SELECT ix FROM detected_hosts WHERE host_ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string host_ix_str(query, ++pos, query.length() - pos);
		int host_ix = atol(host_ix_str.c_str());
		if(lock() == 0){
			Detected_Hosts_Record *match = std::find_if(begin(), end(), [host_ix](Detected_Hosts_Record record){return record.host_ix == host_ix;});
			if(isIn(match)){
				sprintf(result, "%u", match->ix);
				status = 0;
			}
			unlock();
		}
	}
	return status;
}

int32_t Detected_Hosts_Table::UPDATE(const Detected_Hosts_Record &entry){
	return 0;
}

/*
 * CREATE TABLE hosts_ports_hits(ix INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, host_ix INTEGER NOT NULL,
 *  port_number INTEGER NOT NULL, hit_count INTEGER NOT NULL, FOREIGN KEY(host_ix) REFERENCES hosts_table (ix));
 */
Hosts_Ports_Hits_Table::Hosts_Ports_Hits_Table(string name, size_t size):SharedMemoryTable(name, size){}

Hosts_Ports_Hits_Table *Hosts_Ports_Hits_Table::CREATE(string name, size_t size){
	Hosts_Ports_Hits_Table *config = new Hosts_Ports_Hits_Table(name, size);
	if(config->init() < 0){
		delete config;
		config = nullptr;
	}
	return config;
}

int32_t Hosts_Ports_Hits_Table::INSERT(Hosts_Ports_Hits_Record &entry){
	int32_t status;
	if((status = lock()) == 0){
		if(compareAndExpand() < 0){
			status = -1;
		}else{
			if(entry.ix == 0){
				entry.ix = size() == 0 ? 1 : size();
			}
			status = pushBack(entry);
		}
		unlock();
	}
	return status;
}

int32_t Hosts_Ports_Hits_Table::DELETE(const std::string &query){
	int32_t status = 0;
	if(query.find("DELETE FROM hosts_ports_hits WHERE host_ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string value(query, ++pos, query.length() - pos);
		uint32_t host_ix = atol(value.c_str());
		if(lock() != 0){
			uint32_t i = 0;
			Hosts_Ports_Hits_Record record;
			while(i != size()){
				if((status = getRecordByPos(record, i)) == -1){
					status = -1;
					break;
				}
				if(record.host_ix == host_ix){
					if((status = deleteRecordByPos(record.ix)) != 0){
						status = -1;
						break;
					}
				}else{
					i++;
				}
			}
			unlock();
		}
	}
	return status;
}
int32_t Hosts_Ports_Hits_Table::SELECT(char *result, const string &query){
	int32_t status = -1;

	if(query.find("SELECT hit_count FROM hosts_ports_hits WHERE host_ix=") != std::string::npos){
		if(query.find("AND port_number=") != std::string::npos){
			size_t posFirst = query.find_first_of("=");
			size_t posAND = query.find(" AND");
			size_t posLast = query.find_last_of("=");
			string host_ix_str(query, ++posFirst, --posAND - posFirst);
			string port_number_str(query, ++posLast, query.length() - posFirst - --posAND);
			uint32_t host_ix = stoul(host_ix_str.c_str());
			uint32_t the_port = stoul(port_number_str.c_str());
			if(lock() == 0){
				Hosts_Ports_Hits_Record *match = std::find_if(begin(), end(), [host_ix, the_port](const Hosts_Ports_Hits_Record &record)
						{return (host_ix == record.host_ix) && (the_port == record.port_number);});
				if(isIn(match)){
					sprintf(result, "%u", match->hit_count);
					status = 0;
				}
				unlock();
			}
		}
	}

	if(query.find("SELECT SUM(hit_count) FROM hosts_ports_hits WHERE host_ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string value(query, ++pos, query.length() - pos);
		uint32_t ix = stoul(value);
		Hosts_Ports_Hits_Record record;
		int sum = 0;
		if(lock() == 0){
			for(int i=0; i<size(); i++){
				if((status = getRecordByPos(record, i)) != -1){
					sum += record.hit_count;
				}else{
					status = -1;
					break;
				}
			}
			if(status == 0){
				memcpy(result, &sum, sizeof(sum));
				status = 0;
			}
			unlock();
		}
	}

	if(query == "SELECT DISTINCT port_number FROM hosts_ports_hits"){
		if(lock() == 0){
			status = 0;
			Hosts_Ports_Hits_Record record;
			list<uint32_t> listPorts;
			for(int i=0; i<size(); i++){
				if((status = getRecordByPos(record, i)) != -1){
					listPorts.push_back(record.port_number);
				}else{
					status = -1;
					break;
				}
			}
			listPorts.sort();
			listPorts.unique();
			for(auto it=listPorts.begin(); it!=listPorts.end(); it++){
				sprintf(result, "%s%u>", result, *it);
			}
			unlock();
		}
	}

	if(query.find("SELECT COUNT(*) FROM hosts_ports_hits WHERE host_ix=") != std::string::npos){
		if(lock() == 0){
			size_t pos = query.find_first_of("=");
			string value(query, ++pos, query.length() - pos);
			uint32_t host_ix = stoul(value);
			Hosts_Ports_Hits_Record record;
			int count = 0;
			for(int i=0; i<size(); i++){
				if((status = getRecordByPos(record, i)) != -1){
					count = record.host_ix == host_ix ? count + 1 : count;
				}else{
					status = -1;
					break;
				}
			}
			sprintf(result, "%d", count);
			unlock();
		}
	}

	if(query.find("SELECT * FROM hosts_ports_hits WHERE port_number=") != std::string::npos){
		if(lock() == 0){
			size_t posFirst = query.find_first_of("=");
			size_t posAND = query.find(" AND");
			size_t posLast = query.find_last_of("=");
			string port_number_str(query, ++posFirst, --posAND - posFirst);
			string hit_count_str(query, ++posLast, query.length() - posFirst - --posAND);
			uint32_t port_number = stoul(port_number_str.c_str());
			uint32_t hit_count = stoul(hit_count_str.c_str());
			Hosts_Ports_Hits_Record record;
			for(int i=0; i<size(); i++){
				if((status = getRecordByPos(record, i)) != -1){
					if(record.port_number == port_number && record.hit_count == hit_count){
						sprintf(result, "%s%u:%u:%u:%u>", record.ix, record.host_ix, record.port_number, record.hit_count);					}
				}else{
					status = -1;
					break;
				}
			}

			unlock();
		}
	}
	return status;
}

int32_t Hosts_Ports_Hits_Table::UPDATE(const Hosts_Ports_Hits_Record &entry){
	int32_t status = -1;
	if(lock() == 0){
		Hosts_Ports_Hits_Record *match = std::find_if(begin(), end(), [entry](const Hosts_Ports_Hits_Record &record)
						{return (entry.host_ix == record.host_ix) && (entry.port_number == record.port_number);});
		if(isIn(match)){
			match->hit_count = entry.hit_count;
			insertById(*match, match->ix);
		}
		unlock();
	}
	return status;
}

/*
 * CREATE TABLE hosts_table (ix INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
 * 		host TEXT NOT NULL UNIQUE, first_seen INTEGER, last_seen INTEGER);
 */
Hosts_Table::Hosts_Table(string name, size_t size):SharedMemoryTable(name, size){}

Hosts_Table *Hosts_Table::CREATE(string name, size_t size){
	Hosts_Table *config = new Hosts_Table(name, size);
	if(config->init() < 0){
		delete config;
		config = nullptr;
	}
	return config;
}

int32_t Hosts_Table::INSERT(Hosts_Record &entry){
	int32_t status;
	if((status = lock()) == 0){
		if(compareAndExpand() < 0){
			status = -1;
		}else{
			// host is UNIQUE
			Hosts_Record *match = std::find_if(begin(), end(), [entry](const Hosts_Record &record){return !strcmp(record.host, entry.host);});
			if(!isIn(match)){
				if(entry.ix == 0){
					entry.ix = size() == 0 ? 1 : size();
				}
				status = pushBack(entry);
			}else{
				status = -1;
			}
		}
		unlock();
	}
	return status;
}

int32_t Hosts_Table::DELETE(const std::string &query){
	return 0;
}

int32_t Hosts_Table::SELECT(char *result, const string &query){
	int32_t status = -1;
	if(query.find("SELECT ix FROM hosts_table WHERE host=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string ip(query, ++pos, query.length() - pos);
		if(lock() == 0){
			Hosts_Record *match = std::find_if(begin(), end(), [ip](Hosts_Record record){return !strcmp(record.host, ip.c_str());});
			if(isIn(match)){
				sprintf(result, "%u", match->ix);
				status = 0;
			}
			unlock();
		}
	}

	if(query.find("SELECT host FROM hosts_table WHERE ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string value(query, ++pos, query.length() - pos);
		uint32_t ix = stoul(value);
		if(lock() == 0){
			Hosts_Record *match = std::find_if(begin(), end(), [ix](Hosts_Record record){return record.ix == ix;});
			if(isIn(match)){
				memcpy(result, &match->host, strlen(match->host));
				status = 0;
			}
			unlock();
		}
	}

	if(query.find("SELECT * FROM host_table WHERE ix=") != std::string::npos){
		size_t pos = query.find_first_of("=");
		string value(query, ++pos, query.length() - pos);
		uint32_t ix = stoul(value);
		if(lock() == 0){
			Hosts_Record record;
			if((status = getRecordByPos(record, ix)) != -1){
				sprintf(result, "%u:%s:%u:%u", record.ix, record.host, record.first_seen, record.last_seen);
				status = 0;
			}
 			unlock();
		}
	}

	if(query == "SELECT * FROM hosts_table"){
		if(lock() == 0){
			Hosts_Record record;
			status = 0;
			for(int i=0; i<size(); i++){
				if((status = getRecordByPos(record, ix)) != -1){
					sprintf(result, "%s%u:%s:%u:%u>", result, record.ix, record.host, record.first_seen, record.last_seen);
				}else{
					status = -1;
					break;
				}
			}
			unlock();
		}
	}



	return status;
}

int32_t Hosts_Table::UPDATE(const Hosts_Record &entry){
	int32_t status = -1;
	if(lock() == 0){
		Hosts_Record *match = std::find_if(begin(), end(), [entry](const Hosts_Record &record)
						{return entry.ix == record.ix;});
		if(isIn(match)){
			match->last_seen = entry.last_seen;
			insertById(*match, match->ix);
		}
		unlock();
	}
	return status;
}

/*
 * CREATE TABLE ignore_ip_list(ix INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, host_ix INTEGER NOT NULL UNIQUE,
 *  timestamp INTEGER NOT NULL, FOREIGN KEY(host_ix) REFERENCES hosts_table (ix));
 */
Ignore_IP_List_Table::Ignore_IP_List_Table(string name, size_t size):SharedMemoryTable(name, size){}

Ignore_IP_List_Table *Ignore_IP_List_Table::CREATE(string name, size_t size){
	Ignore_IP_List_Table *config = new Ignore_IP_List_Table(name, size);
	if(config->init() < 0){
		delete config;
		config = nullptr;
	}
	return config;
}

int32_t Ignore_IP_List_Table::INSERT(Ignore_IP_List_Record &entry){
	int32_t status;
	if((status = lock()) == 0){
		if(compareAndExpand() < 0){
			status = -1;
		}else{
			// host_ix is UNIQUE
			Ignore_IP_List_Record *match = std::find_if(begin(), end(), [entry](const Ignore_IP_List_Record &record){return record.host_ix == entry.host_ix;});
			if(!isIn(match)){
				if(entry.ix == 0){
					entry.ix = size() == 0 ? 1 : size();
				}
				status = pushBack(entry);
			}else{
				status = -1;
			}
		}
		unlock();
	}
	return status;
}

int32_t Ignore_IP_List_Table::DELETE(const std::string &query){
	return 0;
}

int32_t Ignore_IP_List_Table::SELECT(char *result, const string &query){
	int32_t status = 0;
	if(query.find("SELECT host_ix FROM ignore_ip_list") != std::string::npos){
		Ignore_IP_List_Record record;
		if(lock() == 0){
			for(int i=0; i<size(); i++){
				status = getRecordByPos(record, i);
				sprintf(result, "%s%u>", result, record.host_ix);
				if(status == -1){
					break;
				}
			}
			unlock();
		}
	}
	return status;
}

int32_t Ignore_IP_List_Table::UPDATE(const Ignore_IP_List_Record &entry){
	return 0;
}

