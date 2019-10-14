/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Wrapper to sqlite as a shared lib
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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sqlite3.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "sqlite_wrapper_api.h"
#include "gargoyle_config_vals.h"

struct{
	int is_database_single_connection_mutex_creator;
	// Time in millisecond while the daemon is trying to perform the operation into the database
	// If this time is -1, the database only supports a connection
	int sqlite_locked_try_for_time;
	int fd;
	pthread_mutex_t *single_connection_mutex;
}database_properties;

void set_sqlite_properties(int time){
	database_properties.single_connection_mutex = NULL;
	if(time >= 0){
		database_properties.sqlite_locked_try_for_time = time;
	}else{
		database_properties.sqlite_locked_try_for_time = -1;
		database_properties.is_database_single_connection_mutex_creator = 0;

		database_properties.fd = shm_open("/gargoyle_mutex_shm_sqlite", O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	    if(database_properties.fd < 0 && errno == EEXIST) {
	    	database_properties.is_database_single_connection_mutex_creator = 0;
	    	database_properties.fd = shm_open("/gargoyle_mutex_shm_sqlite", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	    }else if(database_properties.fd > 0) {
	    	// Creator
	    	database_properties.is_database_single_connection_mutex_creator = 1;
	        if(ftruncate(database_properties.fd, sizeof(pthread_mutex_t)) < 0) {
	        	syslog(LOG_INFO | LOG_LOCAL6, "ERROR creating mutex (ftruncate) for SQLite DB");
	            return;
	        }
	    }

	    database_properties.single_connection_mutex = (pthread_mutex_t *)mmap(NULL,
	    		sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE,MAP_SHARED, database_properties.fd, 0);

	    if(database_properties.is_database_single_connection_mutex_creator){
	    	if(pthread_mutex_init(database_properties.single_connection_mutex, NULL) != 0){
	        	syslog(LOG_INFO | LOG_LOCAL6, "ERROR creating mutex (pthread_mutex_init) for SQLite DB");
	            return;
	    	}
	    }

	    if(database_properties.single_connection_mutex == NULL){
        	syslog(LOG_INFO | LOG_LOCAL6, "ERROR creating mutex (mmap) for SQLite DB");
            return;
	    }
	}
}

void delete_sqlite_properties(){
	if(database_properties.single_connection_mutex != NULL){
		munmap(database_properties.single_connection_mutex, sizeof(pthread_mutex_t));
	}

	if(database_properties.is_database_single_connection_mutex_creator){
		shm_unlink("/gargoyle_mutex_shm_sqlite");
	}

	if(-1 != database_properties.fd){
		close(database_properties.fd);
	}
}

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
int sqlite_get_host_by_ix(int the_ix, char *dst, size_t sz_dst, const char *db_loc) {

	//size_t DEST_LEN = 20;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

    char *dest = (char*) malloc (LOCAL_BUF_SZ);
    char *l_buf = (char*) malloc (LOCAL_BUF_SZ);
    char *sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {

		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_host_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(dest);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}

		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}

	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s WHERE ix = ?1", HOSTS_TABLE);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	if (dest_set_len+1 > sz_dst) {

		free(l_buf);
		free(sql);
		free(dest);

        return 1;
	}
    memcpy (dst, dest, dest_set_len+1);

	free(l_buf);
	free(sql);
	free(dest);

	return 0;
}


int sqlite_get_host_all_by_ix(int the_ix, char *dst, size_t sz_dst, const char *db_loc) {

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	char dest[LOCAL_BUF_SZ];
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_host_all_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	if (dest_set_len+1 > sz_dst) {

		return 1;
	}
	memcpy (dst, dest, dest_set_len+1);

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
int sqlite_get_total_hit_count_one_host_by_ix(int the_ix, const char *db_loc) {

	int return_val;
	return_val = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_total_hit_count_one_host_by_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT COUNT(*) FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, the_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		return_val = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return return_val;
}


int sqlite_get_one_host_hit_count_all_ports(int ip_addr_ix, const char *db_loc) {

	int return_val;
	return_val = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_one_host_hit_count_all_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT hit_count FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		return_val += sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return return_val;
}


int sqlite_get_host_ix(const char *the_ip, const char *db_loc) {

	int ret;
	ret = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_host_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT ix FROM %s WHERE host = ?1", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_text(stmt, 1, the_ip, -1, 0);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}


int sqlite_get_host_port_hit(int ip_addr_ix, int the_port, const char *db_loc) {

	int ret;
	ret = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}

/////////////////////////////////////////////////////////////////////////////////////
int sqlite_add_host_port_hit(int ip_addr_ix, int the_port, int add_cnt, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,port_number,hit_count) VALUES (?1,?2,?3)", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, the_port);
	sqlite3_bind_int(stmt, 3, add_cnt);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s inserting data from function [sqlite_add_host_port_hit] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
int sqlite_add_host_port_hit_all(int ix, int ip_addr_ix, int the_port, int add_cnt, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (ix, host_ix,port_number,hit_count) VALUES (?1,?2,?3,?4)", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ix);
	sqlite3_bind_int(stmt, 2, ip_addr_ix);
	sqlite3_bind_int(stmt, 3, the_port);
	sqlite3_bind_int(stmt, 4, add_cnt);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s inserting data from function [sqlite_add_host_port_hit] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}

int sqlite_add_host(const char *the_ip, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	int ret;
	//ret = 0;
	int now;
	//now = 0;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	ret = sqlite3_last_insert_rowid(db);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}

int sqlite_add_host_all(uint32_t ix, const char *the_ip, time_t first_seen, time_t last_seen, const char *db_loc){

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	int ret = 0;
	int now;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_host_all]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (ix, host,first_seen,last_seen) VALUES (?1,?2,?3,?4)", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ix);
	sqlite3_bind_text(stmt, 2, the_ip, -1, 0);
	sqlite3_bind_int(stmt, 3, first_seen);
	sqlite3_bind_int(stmt, 4, last_seen);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		//printf("ERROR inserting data from function [add_host]: %s\n", sqlite3_errmsg(db));
		//syslog(LOG_INFO | LOG_LOCAL6, "ERROR inserting data from function [add_host]: %s", sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}


size_t sqlite_add_detected_host(size_t ip_addr_ix, size_t tstamp, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_detected_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,timestamp) VALUES (?1,?2)", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, tstamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		//syslog(LOG_INFO | LOG_LOCAL6, "%s inserting data from function [add_detected_host] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}

size_t sqlite_remove_detected_host(size_t row_ix, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_detected_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE ix = ?1", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, row_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_detected_host] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}



size_t sqlite_remove_detected_hosts_all(const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_detected_hosts_all]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_detected_hosts_all] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}



size_t sqlite_remove_host_ports_all(size_t ip_addr_ix, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_host_ports_all]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE host_ix = ?1", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	syslog(LOG_INFO | LOG_LOCAL6, "[sqlite_remove_host_ports_all] prepare_v2 %s failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	syslog(LOG_INFO | LOG_LOCAL6, "[sqlite_remove_host_ports_all] bind %s failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_host_ports_all] failed with this msg: %s para la query %s", INFO_SYSLOG, sqlite3_errmsg(db), sql);

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}



size_t sqlite_add_host_to_ignore(size_t ip_addr_ix, size_t tstamp, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [add_host_to_ignore]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,timestamp) VALUES (?1,?2)", IGNORE_IP_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, tstamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s inserting data from function [sqlite_add_host_to_ignore] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}


size_t sqlite_remove_host(size_t ip_addr_ix, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_host]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE ix = ?1", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_host] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;

}

/////////////////////////////////////////////////////////////////////////////////////

int sqlite_update_host_port_hit(int ip_addr_ix, int the_port, int add_cnt, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_update_host_port_hit]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "UPDATE %s SET hit_count = ?1 WHERE host_ix = ?2 AND port_number = ?3", HOSTS_PORTS_HITS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, add_cnt);
	sqlite3_bind_int(stmt, 2, ip_addr_ix);
	sqlite3_bind_int(stmt, 3, the_port);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		//syslog(LOG_INFO | LOG_LOCAL6, "%s updating data from function [update_host_port_hit] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}
	return 0;
}



size_t sqlite_update_host_last_seen(size_t ip_addr_ix, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	/*
	int now = (int)time(NULL);
	int minus_48 = now - 172800;
	*/
	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_update_host_last_seen]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "UPDATE %s SET last_seen = ?1 WHERE ix = ?2", HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	// 01/01/1972 00:00:00 UTC
	sqlite3_bind_int(stmt, 1, 63072000);
	sqlite3_bind_int(stmt, 2, ip_addr_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s updating data from function [sqlite_update_host_last_seen] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;

}


/////////////////////////////////////////////////////////////////////////////////////
int sqlite_get_all_host_one_port_threshold(int the_port, int threshold, char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
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

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_all_host_one_port_threshold]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


int sqlite_get_one_host_all_ports(int ip_addr_ix, char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
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

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_one_host_all_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


int sqlite_get_hosts_all(char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
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

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_hosts_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


int sqlite_get_unique_list_of_ports(char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
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

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_unique_list_of_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


size_t sqlite_get_detected_hosts_all(char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_detected_hosts_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


size_t sqlite_get_detected_hosts_row_ix_by_host_ix(size_t ip_addr_ix, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	size_t return_val = 0;

	char *sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_detected_hosts_row_ix_by_host_ix]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(sql);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	free(sql);

	return return_val;
}


size_t sqlite_get_hosts_to_ignore_all(char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_hosts_to_ignore_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT host_ix FROM %s", IGNORE_IP_LIST_TABLE);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


int sqlite_get_all_ignore_or_black_ip_list(char *dst, size_t sz_dst, const char *db_loc, const char *table) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set;
	final_set = (char*) malloc (MEDIUM_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_all_ignore_or_black_ip_list]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s", table);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2));
		strncat(final_set, l_buf, MEDIUM_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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

size_t sqlite_get_unique_list_of_hosts_ix(char *dst, size_t sz_dst, const char *db_loc) {

	char cwd[SQL_CMD_MAX/2];
	char DB_LOCATION[SQL_CMD_MAX+1];
	if (db_loc) {
		snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
	} else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
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

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_unique_list_of_ports]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT DISTINCT host_ix FROM  %s", HOSTS_PORTS_HITS_TABLE);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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

/////////////////////////////////////////////////////////////////////////////////////

/*
 * return the host_ix for existing entries in the
 * ignore ip table, otherwise returns zero meaning
 * the ip addr in question is not white listed
 */
int sqlite_is_host_ignored(int ip_addr_ix, const char *db_loc) {

	int ret;
	ret = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_is_host_ignored]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT host_ix FROM %s WHERE host_ix = ?1", IGNORE_IP_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}


int sqlite_is_host_detected(int ip_addr_ix, const char *db_loc) {

	int ret;
	ret = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_is_host_detected]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT ix FROM %s WHERE host_ix = ?1", DETECTED_HOSTS_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}


int sqlite_remove_host_to_ignore(int ip_addr_ix, const char *db_loc) {

	char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_host_to_ignore]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE host_ix = ?1", IGNORE_IP_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_host_to_ignore] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}


size_t sqlite_add_host_to_blacklist(size_t ip_addr_ix, size_t tstamp, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_host_to_blacklist]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (host_ix,timestamp) VALUES (?1,?2)", BLACK_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);
	sqlite3_bind_int(stmt, 2, tstamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s inserting data from function [sqlite_add_host_to_blacklist] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}


size_t sqlite_get_hosts_blacklist_all(char *dst, size_t sz_dst, const char *db_loc) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set = (char*) malloc (SMALL_DEST_BUF);
	char *l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_hosts_blacklist_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT host_ix FROM %s", BLACK_LIST_TABLE);
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

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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


int sqlite_is_host_blacklisted(int ip_addr_ix, const char *db_loc) {

	int ret;
	ret = 0;

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_is_host_blacklisted]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT host_ix FROM %s WHERE host_ix = ?1", BLACK_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		ret = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}


int sqlite_remove_host_from_blacklist(int ip_addr_ix, const char *db_loc) {

	char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_host_from_blacklist]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s WHERE host_ix = ?1", BLACK_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ip_addr_ix);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_host_from_blacklist] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}


int sqlite_get_black_ip_list_all(char *dst, size_t sz_dst, const char *db_loc){

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	char *final_set;
	final_set = (char*) malloc (MEDIUM_DEST_BUF);
	char *l_buf;
	l_buf = (char*) malloc (LOCAL_BUF_SZ);
	char *sql;
	sql = (char*) malloc (SQL_CMD_MAX);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_get_black_ip_list_all]: %s", DB_LOCATION, sqlite3_errmsg(db));

		free(l_buf);
		free(sql);
		free(final_set);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "SELECT * FROM %s", BLACK_LIST_TABLE);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	*final_set = 0;
	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		snprintf(l_buf, LOCAL_BUF_SZ, "%d:%d:%d>", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1), sqlite3_column_int(stmt, 2));
		strncat(final_set, l_buf, MEDIUM_DEST_BUF-strlen(final_set)-1);
	}
	size_t final_set_len = strlen(final_set);
	final_set[final_set_len] = '\0';

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

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

void sqlite_reset_autoincrement(const char *table_name, const char *db_loc) {

	char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_reset_autoincrement]: %s", DB_LOCATION, sqlite3_errmsg(db));
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	// UPDATE SQLITE_SEQUENCE SET SEQ= 'value' WHERE NAME='table_name';
	snprintf (sql, SQL_CMD_MAX, "UPDATE sqlite_sequence SET seq = 0 WHERE name = ?1");
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_text(stmt, 1, table_name, -1, 0);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s reset auto-increment from function [sqlite_reset_autoincrement] failed with this msg: %s", INFO_SYSLOG, sqlite3_errmsg(db));

		sqlite3_finalize(stmt);
		sqlite3_close(db);
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	// A only connection to the database

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}
}


size_t sqlite_remove_all(const char *db_loc, const char *table) {

    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_remove_all]: %s with the table %s", DB_LOCATION, sqlite3_errmsg(db), table);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "DELETE FROM %s", table);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		syslog(LOG_INFO | LOG_LOCAL6, "%s deleting data from function [sqlite_remove_all] failed with this msg: %s for the table %s", INFO_SYSLOG, sqlite3_errmsg(db), table);

		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 2;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return 0;
}

size_t sqlite_add_all_by_table(uint32_t ix, uint32_t host_ix, time_t timestamp, const char *db_loc, const char *table){
    char cwd[SQL_CMD_MAX/2];
    char DB_LOCATION[SQL_CMD_MAX+1];
    if (db_loc) {
    	snprintf (DB_LOCATION, SQL_CMD_MAX, "%s", db_loc);
    } else {
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			return 1;
		} else {
			snprintf (DB_LOCATION, SQL_CMD_MAX, "%s%s", cwd, DB_PATH);
		}
    }

	int ret = 0;
	int now;

	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;
	char sql[SQL_CMD_MAX];

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_lock(database_properties.single_connection_mutex);
	}

	rc = sqlite3_open(DB_LOCATION, &db);
	if (rc != SQLITE_OK) {
		syslog(LOG_INFO | LOG_LOCAL6, "ERROR opening SQLite DB '%s' from function [sqlite_add_all_by_table]: %s", DB_LOCATION, sqlite3_errmsg(db));
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return 1;
	}

	if(database_properties.sqlite_locked_try_for_time >= 0){
		sqlite3_busy_timeout(db, database_properties.sqlite_locked_try_for_time);
	}
	snprintf (sql, SQL_CMD_MAX, "INSERT INTO %s (ix, host_ix, timestamp) VALUES (?1,?2,?3)", table);
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	sqlite3_bind_int(stmt, 1, ix);
	sqlite3_bind_int(stmt, 2, host_ix);
	sqlite3_bind_int(stmt, 3, timestamp);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		if(database_properties.single_connection_mutex != NULL){
			pthread_mutex_unlock(database_properties.single_connection_mutex);
		}
		return -1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	// A only connection to the database
	if(database_properties.single_connection_mutex != NULL){
		pthread_mutex_unlock(database_properties.single_connection_mutex);
	}

	return ret;
}
