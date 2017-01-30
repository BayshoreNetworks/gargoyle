/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Wrapper to sqlite as a shared lib
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
#include <string.h>
#include <syslog.h>
#include <sqlite3.h>
#include <time.h>
#include <unistd.h>

#include "sqlite_wrapper_api.h"
	

/*
 * 
 * for all functions here:
 * 
 * return 0 = ok
 * return 1 = not ok (i.e error opening DB or getting/setting the location of the DB file)
 * return -1/2 = not ok (insert / update / delete errs)
 */


/////////////////////////////////////////////////////////////////////////////////////
/*
 * returns host value (ip addr) by writing
 * data to dst
 */
int get_host_by_ix(int the_ix, char *dst, size_t sz_dst) {

	//size_t DEST_LEN = 20;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	/*
	char dest[DEST_LEN];
	char l_buf[DEST_LEN];
	char sql[SQL_CMD_MAX];
	*/
    char *dest = (char*) malloc (LOCAL_BUF_SZ);
    char *l_buf = (char*) malloc (LOCAL_BUF_SZ);
    char *sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_host_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		
		free(l_buf);
		free(sql);
		free(dest);
		    	
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE ix = ?1", HOSTS_TABLE);
	//sqlite3_prepare_v2(db, "SELECT * FROM hosts_table WHERE ix = ?1;", -1, &stmt, NULL);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_ix);

	*dest = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		//printf("%d:%s:%d:%d", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
		snprintf(dest, LOCAL_BUF_SZ, "%s", sqlite3_column_text(stmt, 1));
	}
	size_t dest_set_len = strlen(dest);
	dest[dest_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	if (dest_set_len+1 > sz_dst) {
		
		free(l_buf);
		free(sql);
		free(dest);
    	
        return 1;
	}
    memcpy (dst, dest, dest_set_len+1);
	//strcpy(dst, dest);
    
	free(l_buf);
	free(sql);
	free(dest);

	return 0;
}


int get_host_all_by_ix(int the_ix, char *dst, size_t sz_dst) {

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	char dest[LOCAL_BUF_SZ];
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_host_all_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE ix = ?1", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_ix);

	*dest = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		// one row only
		snprintf(dest, LOCAL_BUF_SZ, "%d:%s:%d:%d", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
	}
	size_t dest_set_len = strlen(dest);
	dest[dest_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, dest);
	if (dest_set_len+1 > sz_dst) {
	    	
		return 1;
	}
	memcpy (dst, dest, dest_set_len+1);

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
int get_total_hit_count_one_host_by_ix(int the_ix) {

	int return_val;
	return_val = 0;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_total_hit_count_one_host_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return -1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT COUNT(*) FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		return_val = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return return_val;
}


int get_one_host_hit_count_all_ports(int ip_addr_ix) {

	int return_val;
	return_val = 0;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_one_host_hit_count_all_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT hit_count FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		return_val += sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return return_val;
}


int get_host_ix(const char *the_ip) {

	int ret;
	ret = 0;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_host_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT ix FROM %s WHERE host = ?1", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_text(stmt, 1, the_ip, -1, 0);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return ret;
}


int get_host_port_hit(int ip_addr_ix, int the_port) {

	int ret;
	ret = 0;
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return -1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT hit_count FROM %s WHERE host_ix = ?1 AND port_number = ?2", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, the_port);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return ret;	
}

/////////////////////////////////////////////////////////////////////////////////////
int add_host_port_hit(int ip_addr_ix, int the_port, int add_cnt) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [add_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,port_number,hit_count) VALUES (?1,?2,?3)", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, the_port);
	sqlite3_bind_int(stmt, 3, add_cnt);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		//printf("ERROR inserting data from function [add_host_port_hit]: %s\n", sqlite3_errmsg(db));
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR inserting data from function [add_host_port_hit]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}


int add_host(const char *the_ip) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	int ret;
	//ret = 0;
	int now;
	//now = 0;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [add_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host,first_seen,last_seen) VALUES (?1,?2,?3)", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_text(stmt, 1, the_ip, -1, 0);
	now = (int)time(NULL);
	sqlite3_bind_int(stmt, 2, now);
	sqlite3_bind_int(stmt, 3, now);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		//printf("ERROR inserting data from function [add_host]: %s\n", sqlite3_errmsg(db));
		//syslog(LOG_INFO | LOG_LOCAL6, "ERROR inserting data from function [add_host]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return -1;
	}

	ret = sqlite3_last_insert_rowid(db);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return ret;
}


/*
int add_detected_host(int ip_addr_ix, int tstamp) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [add_detected_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,timestamp,active,processed) VALUES (?1,?2,1,0)", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, tstamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR inserting data from function [add_detected_host]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;	
}
*/


size_t add_detected_host(size_t ip_addr_ix, size_t tstamp) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [add_detected_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,timestamp) VALUES (?1,?2)", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, tstamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR inserting data from function [add_detected_host]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;	
}


size_t remove_detected_host(size_t ip_addr_ix) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [remove_detected_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE host_ix = ?1", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR deleting data from function [remove_detected_host]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;	
}



size_t remove_detected_hosts_all() {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [remove_detected_hosts_all]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR deleting data from function [remove_detected_hosts_all]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;	
}

/////////////////////////////////////////////////////////////////////////////////////
/*
int modify_host_set_processed_ix(int the_ix) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [modify_host_set_processed_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "UPDATE %s SET active=0, processed=1 WHERE ix = ?1", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR updating data from function [modify_host_set_processed_ix]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}
*/


int update_host_port_hit(int ip_addr_ix, int the_port, int add_cnt) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char sql[SQL_CMD_MAX];

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [update_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "UPDATE %s SET hit_count = ?1 WHERE host_ix = ?2 AND port_number = ?3", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, add_cnt);
	sqlite3_bind_int(stmt, 2, ip_addr_ix);
	sqlite3_bind_int(stmt, 3, the_port);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR updating data from function [update_host_port_hit]: %s", sqlite3_errmsg(db));
		
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
int get_all_host_one_port_threshold(int the_port, int threshold, char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_all_host_one_port_threshold]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE port_number = ?1 AND hit_count >= ?2", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_port);
	sqlite3_bind_int(stmt, 2, threshold);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}


/*
int get_detected_hosts_all_active_unprocessed_ix(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_detected_hosts_all_active_unprocessed_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE active = 1 AND processed = 0", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d>", sqlite3_column_int(stmt, 0));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}
*/


int get_one_host_all_ports(int ip_addr_ix, char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_one_host_all_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		//printf("%d:%s:%d:%d", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {
		
    	free(l_buf);
    	free(sql);
    	free(final_set);
    	
        return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}


int get_hosts_all(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[MEDIUM_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (MEDIUM_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_hosts_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%s:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3));
		strncat(final_set, l_buf, MEDIUM_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {
		
    	free(l_buf);
    	free(sql);
    	free(final_set);
    	
        return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}


int get_unique_list_of_ports(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_unique_list_of_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT DISTINCT port_number FROM  %s", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d>", sqlite3_column_int(stmt, 0));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {
		
    	free(l_buf);
    	free(sql);
    	free(final_set);
    	
        return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}



size_t get_detected_hosts_all(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_detected_hosts_all_active_unprocessed]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);       
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if (final_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}





/*
int get_detected_hosts_all_active_unprocessed(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_detected_hosts_all_active_unprocessed]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE active = 1 AND processed = 0", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		//printf("%d:%d:%d:%d:%d\n", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3), sqlite3_column_int(stmt, 4));
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2), sqlite3_column_int(stmt, 3), sqlite3_column_int(stmt, 4));
		//strncat(final_set, l_buf, sizeof(final_set)-strlen(final_set)-1);
		//strncat(final_set, ">", sizeof(final_set)-strlen(final_set)-1);
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);       
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	//strcpy(dst, final_set);
	if (final_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}
*/

/*
int get_detected_hosts_all_active_unprocessed_host_ix(char *dst, size_t sz_dst) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	//char final_set[SMALL_DEST_BUF];
	//char l_buf[LOCAL_BUF_SZ];
	//char sql[SQL_CMD_MAX];

	char *final_set;
	final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_detected_hosts_all_active_unprocessed_host_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT host_ix FROM %s WHERE active = 1 AND processed = 0", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d>", sqlite3_column_int(stmt, 0));
		strncat(final_set, l_buf, SMALL_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	if (final_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(final_set);

		return 1;
	}
	memcpy (dst, final_set, final_set_len+1);

	free(l_buf);
	free(sql);
	free(final_set);

	return 0;
}
*/


int get_detected_hosts_row_ix_by_host_ix(size_t ip_addr_ix) {
	
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
    	return 1;
    } else {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	int return_val = 0;

	char *sql = (char*) malloc (SQL_CMD_MAX);

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [get_detected_hosts_row_ix_by_host_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(sql);

		return 1;
	}

	//snprintf (sql, SQL_CMD_MAX, "SELECT ix FROM %s WHERE host_ix = ?1 AND active = 1 AND processed = 0", DETECTED_HOSTS_TABLE);
	snprintf (sql, SQL_CMD_MAX, "SELECT ix FROM %s WHERE host_ix = ?1", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		return_val = sqlite3_column_int(stmt, 0);
	}
	
	sqlite3_finalize(stmt);
	sqlite3_close(db);

	free(sql);

	return return_val;
}
/////////////////////////////////////////////////////////////////////////////////////

