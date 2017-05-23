/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * Functionality to ensure a given process is a singleton
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

#include <cstring>

class SingletonProcess {
public:
	SingletonProcess(uint16_t port0) :
			socket_fd(-1), rc(1), port(port0) {
		socket_fd = -1;
	}

	~SingletonProcess() {
		if (socket_fd != -1) {
			close(socket_fd);
		}
	}

	bool operator()() {
		if (socket_fd == -1 || rc) {
			socket_fd = -1;
			rc = 1;

			if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
				throw std::runtime_error(
						std::string("Could not create socket: ")
								+ strerror(errno));
			} else {
				struct sockaddr_in name;
				name.sin_family = AF_INET;
				name.sin_port = htons(port);
				name.sin_addr.s_addr = htonl(INADDR_ANY);
				rc = bind(socket_fd, (struct sockaddr *) &name, sizeof(name));
			}
		}
		return (socket_fd != -1 && rc == 0);
	}

	std::string GetLockFileName() {
		std::ostringstream stm ;
		stm << "port " << port;
		return stm.str();
		//return "port " + std::to_string(port);
	}

private:
	int socket_fd;
	int rc;
	uint16_t port;
};

