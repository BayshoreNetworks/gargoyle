#include <cstdlib>
#include <ctime>
#include <csignal>
#include <cstring>

#include <iostream>
#include <algorithm>

#include "data_base.h"

#define LENGTH_RESULT_QUERY 10000
#define MAX_ENTRIES 11

using namespace std;

DataBase *db;

void handler(int i){
	if(db != nullptr){
		delete db;
	}
}


int main(int argc, char *argv[], char *env[]){
    int32_t status;
    char result[LENGTH_RESULT_QUERY];

    signal(SIGINT, handler);
    signal(SIGKILL, handler);
    signal(SIGSEGV, handler);
    signal(SIGTSTP, handler);

    if((db = DataBase::create()) == nullptr){
        cerr << "Error when creating database" << endl;
        exit(1);
    }

    // Host_table
    Hosts_Record recordHostsTable;
    memset(&recordHostsTable, 0, sizeof(recordHostsTable));
    memset(result, 0, LENGTH_RESULT_QUERY);
    db->hosts->DELETE("DELETE FROM hosts_table");

    for(int i=1; i<MAX_ENTRIES; i++){
    	sprintf(recordHostsTable.host, "192.168.1.%d", i);
    	recordHostsTable.first_seen = time(nullptr);
    	recordHostsTable.last_seen = time(nullptr);
    	db->hosts->INSERT(recordHostsTable);
    }

    if((status = db->hosts->SELECT(result, "SELECT * FROM hosts_table")) != -1){
    	cout << "SELECT * FROM hosts_table" << endl;
    	cout << "ix:host:first_seen:last_seen"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT ix FROM hosts_table WHERE host=192.168.1.2")) != -1){
    	cout << "SELECT ix FROM hosts_table WHERE host=192.168.1.2" << endl;
    	cout << "ix"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT * FROM hosts_table WHERE ix=9")) != -1){
    	cout << "SELECT * FROM hosts_table WHERE ix=9" << endl;
    	cout << "ix:host:first_seen:last_seen"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT host FROM hosts_table WHERE ix=9")) != -1){
    	cout << "SELECT host FROM hosts_table WHERE ix=9" << endl;
    	cout << "host"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT * FROM hosts_table WHERE ix=6")) != -1){
    	cout << "SELECT * FROM hosts_table WHERE ix=6" << endl;
    	cout << "ix:host:first_seen:last_seen"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    recordHostsTable.ix = 6;
    recordHostsTable.last_seen = 1111111;
    if((status = db->hosts->UPDATE(recordHostsTable)) != -1){
    	cout << "UPDATE host SET last_seen=" << recordHostsTable.last_seen << " WHERE ix=" << recordHostsTable.ix << endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT * FROM hosts_table WHERE ix=6")) != -1){
    	cout << "SELECT * FROM hosts_table WHERE ix=6" << endl;
    	cout << "ix:host:first_seen:last_seen"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->DELETE("DELETE FROM hosts_table")) != -1){
    	cout << "DELETE FROM hosts_table" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts->SELECT(result, "SELECT * FROM hosts_table")) != -1){
    	cout << "SELECT * FROM hosts_table" << endl;
    	cout << "ix:host:first_seen:last_seen"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    // Hosts_Ports_Hits
    Hosts_Ports_Hits_Record recordHostsPortsHitsTable;
    memset(&recordHostsPortsHitsTable, 0, sizeof(recordHostsTable));
    memset(result, 0, LENGTH_RESULT_QUERY);
    db->hosts_ports_hits->DELETE("DELETE FROM hosts_ports_hits");

    for(int i=1; i<MAX_ENTRIES; i++){
    	recordHostsPortsHitsTable.host_ix = i;
    	if(i<6){
        	recordHostsPortsHitsTable.host_ix = 6;
    		recordHostsPortsHitsTable.port_number = 80;
    	}else{
        	recordHostsPortsHitsTable.host_ix = 3;
    		recordHostsPortsHitsTable.port_number = 8080;
    	}
    	recordHostsPortsHitsTable.hit_count = i*i*i;
    	db->hosts_ports_hits->INSERT(recordHostsPortsHitsTable);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT DISTINCT port_number FROM hosts_ports_hits")) != -1){
    	cout << "SELECT DISTINCT port_number FROM hosts_ports_hits" << endl;
    	cout << "port_number"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT DISTINCT host_ix FROM hosts_ports_hits")) != -1){
    	cout << "SELECT DISTINCT host_ix FROM hosts_ports_hits" << endl;
    	cout << "host_ix"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT hit_count FROM hosts_ports_hits WHERE host_ix=3 AND port_number=8080")) != -1){
    	cout << "SELECT hit_count FROM hosts_ports_hits WHERE host_ix=3 AND port_number=8080" << endl;
    	cout << "hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT SUM(hit_count) FROM hosts_ports_hits WHERE host_ix=3")) != -1){
    	cout << "SELECT SUM(hit_count) FROM hosts_ports_hits WHERE host_ix=3" << endl;
    	cout << "SUM(hit_count)"<< endl;
    	cout << atoi(result) << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT COUNT(*) FROM hosts_ports_hits WHERE host_ix=3")) != -1){
    	cout << "SELECT COUNT(*) FROM hosts_ports_hits WHERE host_ix=3" << endl;
    	cout << "COUNT(*)"<< endl;
    	cout << atoi(result) << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits WHERE port_number=8080 AND hit_count>=500")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits WHERE port_number=8080 AND hit_count>=500" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    recordHostsPortsHitsTable.host_ix = 3;
    recordHostsPortsHitsTable.port_number = 8080;
    recordHostsPortsHitsTable.hit_count = 1000;
    if((status = db->hosts_ports_hits->UPDATE(recordHostsPortsHitsTable)) != -1){
    	cout << "UPDATE hosts_ports_hits SET hit_count=1000 WHERE host_ix=3 AND port_number=8080" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits WHERE port_number=8080 AND hit_count>=500")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits WHERE port_number=8080 AND hit_count>=500" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->DELETE("DELETE FROM hosts_ports_hits WHERE host_ix=3")) != -1){
    	cout << "DELETE FROM hosts_ports_hits WHERE host_ix=3" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->DELETE("DELETE FROM hosts_ports_hits")) != -1){
    	cout << "DELETE FROM hosts_ports_hits" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->hosts_ports_hits->SELECT(result, "SELECT * FROM hosts_ports_hits")) != -1){
    	cout << "SELECT * FROM hosts_ports_hits" << endl;
    	cout << "ix:host_ix:port_number:hit_count"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    // Ignore_IP_List
    Ignore_IP_List_Record recordIgnoreIPListTable;
    memset(&recordIgnoreIPListTable, 0, sizeof(recordIgnoreIPListTable));
    memset(result, 0, LENGTH_RESULT_QUERY);
    db->ignore_ip_list->DELETE("DELETE FROM ignore_ip_list");

    for(int i=1; i<MAX_ENTRIES; i++){
    	recordIgnoreIPListTable.host_ix = i*i*i;
    	recordIgnoreIPListTable.timestamp = i*i*i*i;
    	db->ignore_ip_list->INSERT(recordIgnoreIPListTable);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT * FROM ignore_ip_list")) != -1){
    	cout << "SELECT * FROM ignore_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT host_ix FROM ignore_ip_list")) != -1){
    	cout << "SELECT host_ix FROM ignore_ip_list" << endl;
    	cout << "host_ix"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT host_ix FROM ignore_ip_list WHERE host_ix=1")) != -1){
    	cout << "SELECT host_ix FROM ignore_ip_list WHERE host_ix=1" << endl;
    	cout << "host_ix"<< endl;
    	cout << atoi(result) << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT * FROM ignore_ip_list")) != -1){
    	cout << "SELECT * FROM ignore_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->DELETE("DELETE FROM ignore_ip_list WHERE host_ix=1")) != -1){
    	cout << "DELETE FROM ignore_ip_list WHERE host_ix=1" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT * FROM ignore_ip_list")) != -1){
    	cout << "SELECT * FROM ignore_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->DELETE("DELETE FROM ignore_ip_list")) != -1){
    	cout << "DELETE FROM ignore_ip_list" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->ignore_ip_list->SELECT(result, "SELECT * FROM ignore_ip_list")) != -1){
    	cout << "SELECT * FROM ignore_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    // Black_IP_List
    Black_IP_List_Record recordBlackIPListTable;
    memset(&recordBlackIPListTable, 0, sizeof(recordBlackIPListTable));
    memset(result, 0, LENGTH_RESULT_QUERY);
    db->black_ip_list->DELETE("DELETE FROM black_ip_list");

    for(int i=1; i<MAX_ENTRIES; i++){
    	recordBlackIPListTable.host_ix = i*i*i*i;
    	recordBlackIPListTable.timestamp = i*i*i*i*i;
    	db->black_ip_list->INSERT(recordBlackIPListTable);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT * FROM black_ip_list")) != -1){
    	cout << "SELECT * FROM black_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT host_ix FROM black_ip_list")) != -1){
    	cout << "SELECT host_ix FROM black_ip_list" << endl;
    	cout << "host_ix"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT host_ix FROM black_ip_list WHERE host_ix=1")) != -1){
    	cout << "SELECT host_ix FROM black_ip_list WHERE host_ix=1" << endl;
    	cout << "host_ix"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT * FROM black_ip_list")) != -1){
    	cout << "SELECT * FROM black_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->DELETE("DELETE FROM black_ip_list WHERE host_ix=16")) != -1){
    	cout << "DELETE FROM black_ip_list WHERE host_ix=16" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT * FROM black_ip_list")) != -1){
    	cout << "SELECT * FROM black_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->DELETE("DELETE FROM black_ip_list")) != -1){
    	cout << "DELETE FROM black_ip_list" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->black_ip_list->SELECT(result, "SELECT * FROM black_ip_list")) != -1){
    	cout << "SELECT * FROM black_ip_list" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    // Detected_Hosts_Table
    Detected_Hosts_Record recordDetectedHostsTable;
    memset(&recordDetectedHostsTable, 0, sizeof(recordDetectedHostsTable));
    memset(result, 0, LENGTH_RESULT_QUERY);
    db->detected_hosts->DELETE("DELETE FROM detected_hosts");
    for(int i=1; i<MAX_ENTRIES; i++){
    	recordDetectedHostsTable.host_ix = i*i*i*i*i;
    	recordDetectedHostsTable.timestamp = i*i*i*i*i*i*i;
    	db->detected_hosts->INSERT(recordDetectedHostsTable);
    }

    if((status = db->detected_hosts->SELECT(result, "SELECT * FROM detected_hosts")) != -1){
    	cout << "SELECT * FROM detected_hosts" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->detected_hosts->SELECT(result, "SELECT ix FROM detected_hosts WHERE host_ix=32")) != -1){
    	cout << "SELECT ix FROM detected_hosts WHERE host_ix=32" << endl;
    	cout << "ix"<< endl;
    	cout << atoi(result) << endl;
    }else{
    	exit(1);
    }

    if((status = db->detected_hosts->DELETE("DELETE FROM detected_hosts WHERE ix=10")) != -1){
    	cout << "DELETE FROM detected_hosts WHERE ix=10" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->detected_hosts->SELECT(result, "SELECT * FROM detected_hosts")) != -1){
    	cout << "SELECT * FROM detected_hosts" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

    if((status = db->detected_hosts->DELETE("DELETE FROM detected_hosts")) != -1){
    	cout << "DELETE FROM detected_hosts" << endl << endl;
    }else{
    	exit(1);
    }

    if((status = db->detected_hosts->SELECT(result, "SELECT * FROM detected_hosts")) != -1){
    	cout << "SELECT * FROM detected_hosts" << endl;
    	cout << "ix:host_ix:timestamp"<< endl;
    	string outputFormated = result;
    	std::replace(outputFormated.begin(), outputFormated.end(), '>', '\n');
    	cout << outputFormated << endl;
    }else{
    	exit(1);
    }

	return 0;
}
