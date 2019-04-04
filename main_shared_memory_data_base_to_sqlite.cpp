/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * main dumping periodically shared memory data base to sqlite
 *
 * Copyright (c) 2016 - 2019, Bayshore Networks, Inc.
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
#include <map>

#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>

#include "sqlite_wrapper_api.h"
#include "singleton.h"
#include "gargoyle_config_vals.h"
#include "config_variables.h"
#include "string_functions.h"
#include "ip_addr_controller.h"
#include "shared_config.h"
#include "system_functions.h"
#include "data_base.h"

using namespace std;

const char *GARG_ANALYSIS_PROGNAME = "Gargoyle Shared Memory Data Base to Sqlite";

bool ENFORCE = true;
bool DEBUG = false;

char DB_LOCATION[SQL_CMD_MAX+1];

DataBase *data_base_shared_memory = nullptr;

volatile sig_atomic_t stop;

void handle_signal(int signum) {
    stop = 1;
    syslog(LOG_INFO | LOG_LOCAL6, "%s: %d, %s", SIGNAL_CAUGHT_SYSLOG, signum, PROG_TERM_SYSLOG);

    if(data_base_shared_memory != nullptr){
        delete data_base_shared_memory;
    }
    exit(0);
}

void sqlite_remove_all_by_table(const char *db, const char *table){
    if(sqlite_remove_all(db, table) != 0){
        cerr << "Error deleting records in " << table << endl;
        exit(1);
    }
}

int main(int argc, char *argv[]) {

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGSEGV, handle_signal);

    if (geteuid() != 0) {
        cerr << endl << "Root privileges are necessary for this to run ..." << endl << endl;
        return 1;
    }

    /*
     * in order to keep stuff lean and mean I
     * am doing this manually here and not
     * using a lib that parses command line args,
     * maybe we replace this in the future ...
     */
    if (argc != 2) {
        cerr << endl << GARG_ANALYSIS_PROGNAME << " - Argument errors, exiting ..." << endl << endl;
        cerr << endl << "Usage: ./gargoyle_shared_memory_data_base_to_sqlite <-s | --shared_memory>" << endl << endl;
        exit(1);
    }else{
        string arg_one = argv[1];
        if((case_insensitive_compare(arg_one.c_str(), "-s")) || (case_insensitive_compare(arg_one.c_str(), "--shared_memory"))){
            data_base_shared_memory = DataBase::create();
        }else{
            cerr << endl << "Usage: ./gargoyle_shared_memory_data_base_to_sqlite <-s | --shared_memory>" << endl << endl;
            exit(1);
        }
    }

    // Get config data
    bool enforce_mode = true;
    size_t shared_memory_data_base_to_sqlite_time;

    const char *config_file;
    config_file = getenv("GARGOYLE_CONFIG");
    if (config_file == NULL){
        config_file = ".gargoyle_config";
    }
    ConfigVariables cvv;
    if(cvv.get_vals(config_file) == 0) {
        enforce_mode = cvv.get_enforce_mode();
        shared_memory_data_base_to_sqlite_time = cvv.get_shared_memory_data_base_to_sqlite_time();
        if(shared_memory_data_base_to_sqlite_time == -1){
            cerr << "None shared_memory_data_base_to_sqlite_time key in " << config_file << endl;
            exit(1);
        }
    }

    /*
     * Get location for the DB file
     */
    const char *gargoyle_db_file;
    gargoyle_db_file = getenv("GARGOYLE_DB");
    if (gargoyle_db_file == NULL) {
        snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", GARGOYLE_DEFAULT_ROOT_PATH, DB_PATH);
    } else {
        snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", gargoyle_db_file);
    }

    if (!does_file_exist(DB_LOCATION)) {
        syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s - %s", DB_FILE_SYSLOG, DB_LOCATION, DOESNT_EXIST_SYSLOG, CANNOT_CONTINUE_SYSLOG);
        return 1;
    }

    if (DEBUG) {
        syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG, "Using DB:", DB_LOCATION);
    }

    const char *gargoyle_debug_flag;
    gargoyle_debug_flag = getenv("GARGOYLE_DEBUG_FLAG");
    if (gargoyle_debug_flag != NULL) {
        DEBUG = true;
    }

    string query;
    char result[DEST_BUF_SZ];
    const char *tok1 = ">", *tok2 = ":";
    char *token1, *token1_save, *token2, *token2_save;
    int iter_cnt;
    Hosts_Record host_record;
    Detected_Hosts_Record detected_hosts_record;
    Hosts_Ports_Hits_Record hosts_port_hit_record;
    Ignore_IP_List_Record ignore_ip_list_record;
    Black_IP_List_Record black_ip_list_record;

    while(true){
        // hosts_table
        sqlite_remove_all_by_table(gargoyle_db_file, HOSTS_TABLE);
        query = "SELECT * FROM hosts_table";
        data_base_shared_memory->hosts->SELECT(result, query);

        token1 = strtok_r(result, tok1, &token1_save);
        while (token1 != NULL) {
            iter_cnt = 0;
            token2 = strtok_r(token1, tok2, &token2_save);
            while (token2 != NULL) {
                if (iter_cnt == 0) {
                    host_record.ix = atoll(token2);
                } else if (iter_cnt == 1) {
                    snprintf(host_record.host, LENGTH_IPV4, "%s", token2);
                } else if (iter_cnt == 2) {
                    host_record.first_seen = atoll(token2);
                } else if (iter_cnt == 3) {
                    host_record.last_seen = atoll(token2);
                }
                iter_cnt++;
                token2 = strtok_r(NULL, tok2, &token2_save);
            }
            token1 = strtok_r(NULL, tok1, &token1_save);
            if(sqlite_add_host_all(host_record.ix, host_record.host, host_record.first_seen, host_record.last_seen, gargoyle_db_file) != 0){
                syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                        "Error in writing periodical of shared memory database to SQLite table ", HOSTS_TABLE);
                exit(1);
            }
        }

        if(gargoyle_debug_flag){
            syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                    "Writing periodical of shared memory database to SQLite table ", HOSTS_TABLE);
        }

        // detected_hosts
        sqlite_remove_all_by_table(gargoyle_db_file, DETECTED_HOSTS_TABLE);
        query = "SELECT * FROM detected_hosts";
        data_base_shared_memory->detected_hosts->SELECT(result, query);

        token1 = strtok_r(result, tok1, &token1_save);
        while (token1 != NULL) {
            iter_cnt = 0;
            token2 = strtok_r(token1, tok2, &token2_save);
            while (token2 != NULL) {
                if (iter_cnt == 0) {
                    detected_hosts_record.ix = atoll(token2);
                } else if (iter_cnt == 1) {
                    detected_hosts_record.host_ix = atoll(token2);
                } else if (iter_cnt == 2) {
                    detected_hosts_record.timestamp = atoll(token2);
                }
                iter_cnt++;
                token2 = strtok_r(NULL, tok2, &token2_save);
            }
            token1 = strtok_r(NULL, tok1, &token1_save);
            if(sqlite_add_all_by_table(detected_hosts_record.ix, detected_hosts_record.host_ix, detected_hosts_record.timestamp,
                    gargoyle_db_file, DETECTED_HOSTS_TABLE) != 0){
                syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                        "Error in writing periodical of shared memory database to SQLite table ", DETECTED_HOSTS_TABLE);
                exit(1);
            }
        }

        if(gargoyle_debug_flag){
            syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                    "Writing periodical of shared memory database to SQLite table ", DETECTED_HOSTS_TABLE);
        }

        // hosts_ports_hits
        sqlite_remove_all_by_table(gargoyle_db_file, HOSTS_PORTS_HITS_TABLE);
        query = "SELECT * FROM hosts_ports_hits";
        data_base_shared_memory->hosts_ports_hits->SELECT(result, query);

        token1 = strtok_r(result, tok1, &token1_save);
        while (token1 != NULL) {
            iter_cnt = 0;
            token2 = strtok_r(token1, tok2, &token2_save);
            while (token2 != NULL) {
                if (iter_cnt == 0) {
                    hosts_port_hit_record.ix = atoll(token2);
                } else if (iter_cnt == 1) {
                    hosts_port_hit_record.host_ix = atoll(token2);
                } else if (iter_cnt == 2) {
                    hosts_port_hit_record.port_number = atoll(token2);
                } else if (iter_cnt == 3){
                    hosts_port_hit_record.hit_count = atoll(token2);
                }
                iter_cnt++;
                token2 = strtok_r(NULL, tok2, &token2_save);
            }
            token1 = strtok_r(NULL, tok1, &token1_save);
            if(sqlite_add_host_port_hit_all(hosts_port_hit_record.ix, hosts_port_hit_record.host_ix,
                    hosts_port_hit_record.port_number, hosts_port_hit_record.hit_count, gargoyle_db_file) != 0){
                syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                        "Error in writing periodical of shared memory database to SQLite table ", HOSTS_PORTS_HITS_TABLE);
                exit(1);
            }
        }

        if(gargoyle_debug_flag){
            syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                    "Writing periodical of shared memory database to SQLite table ", HOSTS_PORTS_HITS_TABLE);
        }

        // ignore_ip_list
        sqlite_remove_all_by_table(gargoyle_db_file, IGNORE_IP_LIST_TABLE);
        query = "SELECT * FROM ignore_ip_list";
        data_base_shared_memory->ignore_ip_list->SELECT(result, query);

        token1 = strtok_r(result, tok1, &token1_save);
        while (token1 != NULL) {
            iter_cnt = 0;
            token2 = strtok_r(token1, tok2, &token2_save);
            while (token2 != NULL) {
                if (iter_cnt == 0) {
                    ignore_ip_list_record.ix = atoll(token2);
                } else if (iter_cnt == 1) {
                    ignore_ip_list_record.host_ix = atoll(token2);
                } else if (iter_cnt == 2) {
                    ignore_ip_list_record.timestamp = atoll(token2);
                }
                iter_cnt++;
                token2 = strtok_r(NULL, tok2, &token2_save);
            }
            token1 = strtok_r(NULL, tok1, &token1_save);
            if(sqlite_add_all_by_table(ignore_ip_list_record.ix, ignore_ip_list_record.host_ix,
                    ignore_ip_list_record.timestamp, gargoyle_db_file, IGNORE_IP_LIST_TABLE) != 0){
                syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                        "Error in writing periodical of shared memory database to SQLite table ", IGNORE_IP_LIST_TABLE);
                exit(1);
            }
        }

        if(gargoyle_debug_flag){
            syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                    "Writing periodical of shared memory database to SQLite table ", IGNORE_IP_LIST_TABLE);
        }

        // black_ip_list
        sqlite_remove_all_by_table(gargoyle_db_file, BLACK_LIST_TABLE);
        query = "SELECT * FROM black_ip_list";
        data_base_shared_memory->black_ip_list->SELECT(result, query);

        token1 = strtok_r(result, tok1, &token1_save);
        while (token1 != NULL) {
            iter_cnt = 0;
            token2 = strtok_r(token1, tok2, &token2_save);
            while (token2 != NULL) {
                if (iter_cnt == 0) {
                    black_ip_list_record.ix = atoll(token2);
                } else if (iter_cnt == 1) {
                    black_ip_list_record.host_ix = atoll(token2);
                } else if (iter_cnt == 2) {
                    black_ip_list_record.timestamp = atoll(token2);
                }
                iter_cnt++;
                token2 = strtok_r(NULL, tok2, &token2_save);
            }
            token1 = strtok_r(NULL, tok1, &token1_save);
            if(sqlite_add_all_by_table(black_ip_list_record.ix, black_ip_list_record.host_ix,
                    black_ip_list_record.timestamp, gargoyle_db_file, BLACK_LIST_TABLE) != 0){
                syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                        "Error in writing periodical of shared memory database to SQLite table ", BLACK_LIST_TABLE);
                exit(1);
            }
        }

        if(gargoyle_debug_flag){
            syslog(LOG_INFO | LOG_LOCAL6, "%s %s %s", GARGOYLE_DEBUG,
                    "Writing periodical of shared memory database to SQLite table ", BLACK_LIST_TABLE);
        }

        sleep(shared_memory_data_base_to_sqlite_time);
    }

    return 0;
}
