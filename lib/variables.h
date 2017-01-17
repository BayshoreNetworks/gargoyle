#include <iostream>
#include <fstream>
#include <map>
#include <cstring>
#include <stdlib.h>
using namespace std;

class Variables{
public:
	void get_vals(){
		string line;
		long val = 0;
		char *temp;
		string filename = "test.txt";
		ifstream infile(filename.c_str());
		if(infile){
			while(getline(infile,line)){
				size_t pos = line.find(":");
				this->key_vals[line.substr(0,pos)] = line.substr(pos+1).c_str();
			} 		
		}
		else{
			cerr << "Couldn't open " << filename << " for reading\n";
		}
	}
	string get_chain_name(){
		return key_vals["chain_name"].c_str();
	}
	int get_port_scan_threshold(){
		return atoi(key_vals["port_scan_threshold"].c_str());
	}
	int get_single_ip_scan_threshold(){
		return atoi(key_vals["single_ip_scan_threshold"].c_str());
	int get_overall_port_scan_threshold(){
		return atoi(key_vals["overall_port_scan_threshold"].c_str());
	}
	int get_last_seen_delta(){
		return atoi(key_vals["last_seen_delta"].c_str());
	}
	int get_lockout_time(){
		return atoi(key_vals["lockout_time"].c_str());
	}
private:
	map<string,string> key_vals;
};
