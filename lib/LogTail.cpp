/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * configuration object for sharing IP addresses between processes
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

#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <string.h>

#include <string>
#include <iostream>

#include "LogTail.h"

LogTail::LogTail() : _fin(NULL) {
}

LogTail::LogTail(const std::string& name) : _name(name) , _fin(NULL) {
}

LogTail::LogTail(const char* name) : _name(name) , _fin(NULL) {
}

LogTail::~LogTail() {
	if (NULL!=_fin) fclose(_fin);
}

bool LogTail::Initialize() {
	struct stat st;
	if (stat(_name.c_str(), &st)) {
		return false;
	}

	if (!S_ISREG(st.st_mode)) {
		// For now - only regular files. No links allowed
		return false;
	}
	return true;
}
    
bool LogTail::Initialize(const std::string& name) {
	_name = name;
	return Initialize();
}

bool LogTail::Process(volatile bool & stop) {
	_pre();
	while (!stop) {
		if (!_consume_file(stop)) break;
		if (!_wait_file(stop)) break;
	}
	_post();
	return true;
}

void LogTail::_pre(off_t loc) {
	_fin = fopen(_name.c_str(), "rt");
	if (NULL!=_fin) {
		fseek(_fin, loc, SEEK_SET);
	}
}

void LogTail::_post() {
	fclose(_fin);
	_fin = NULL;
}

bool LogTail::_consume_file(volatile bool & stop) {
	const int lineMax = 1024;
	std::string line(lineMax, '\0');

	while (!stop) {
		char * cp = fgets((char*)line.data(), line.size(), _fin);
		if (NULL==cp) {
			break; // EOF reached
		}
		OnLine(line);
	}
	return !stop;
}

bool LogTail::_wait_file(volatile bool & stop) {
	int fd = inotify_init();
	if (-1==fd) return false;

	int wd = inotify_add_watch(fd, _name.c_str(), IN_MODIFY|IN_MOVE_SELF|IN_CLOSE_WRITE);
	if (-1==wd) {
		close(fd);
		return false;
	}

	struct pollfd fds;

	fds.fd = fileno(_fin);
	fds.events = POLLIN;

	if (fseek(_fin, 0, SEEK_CUR)) {
		return false;
	}

	off_t loc = ftell(_fin);
	bool done = false;
	while (!done) {
		int poll_num = poll(&fds, 1, -1);
		if (poll_num > 0) {
			/* use 1 page */
			char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
			const struct inotify_event *event;
			int i;
			ssize_t len;
			char *ptr;

			for (;!done;) {
				len = read(fd, buf, sizeof buf);
				if (len == -1 && errno != EAGAIN) {
					break;
				}

				if (len <= 0)
					break;

				uint32_t reset_mask = IN_MOVE_SELF|IN_DELETE_SELF|IN_DELETE;
				uint32_t follow_mask = IN_MODIFY|IN_CLOSE_WRITE;

				/* Loop over all events in the buffer */
				for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {

					event = (const struct inotify_event *) ptr;
					if (event->mask & follow_mask) {
						//std::cerr << "follow" << std::endl;
						struct stat st;
						if (0==stat(_name.c_str(), &st) && S_ISREG(st.st_mode)) 
							loc = (loc>st.st_size?0:loc);
						else loc = 0;
						done = true;
						break;
					}
					if (event->mask & reset_mask) {
						//std::cerr << "re-open" << std::endl;
						loc = 0;
						done = true;
						break;
					}
				}
			}
		}
	}

	inotify_rm_watch(fd, wd);
	close(fd);

	_post();
	loc!=0?OnFollow():OnRewind();
	struct timespec tv = { .tv_sec = 1, .tv_nsec = 0};
	nanosleep(&tv, NULL);
	_pre(loc);
	return true;
}
