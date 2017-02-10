/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * netfilter queue handling code
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
#include "nf_queue.h"

#include <iostream>

#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>


Queue::Queue(const Library& lib, u_int16_t num, PacketHandler& packetHandler) : _packetHandler(packetHandler)
{
	_handle = nfq_create_queue(lib._handle, num, _callback, this);
	if (!_handle)
		std::cout << "Cannot create queue" << std::endl;
	
	if (nfq_set_mode(_handle, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		nfq_destroy_queue(_handle);
		std::cout << "Cannot set COPY_PACKET mode" << std::endl;
	}
	//std::cout << "[NF QUEUE] created" << std::endl;
}


Queue::~Queue()
{
	nfq_destroy_queue(_handle);
	//std::cout << "[NF QUEUE] destroyed" << std::endl;
}


int Queue::_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
	Queue* queue = reinterpret_cast<Queue*>(data);
	return queue->_packetHandler.handle_packet(*queue, nfmsg, nfad);
}


void Queue::setVerdict(u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char *buf)
{
	nfq_set_verdict(_handle, id, verdict, data_len, buf);
}


Library::Library()
{
	_handle = nfq_open();
	if (!_handle)
		std::cout << "Cannot open queue" << std::endl;
	//std::cout << "[NF LIB] - CONSTRUCTOR - created" << std::endl;
}


Library::~Library()
{
	nfq_close(_handle);
	//std::cout << "[NF LIB] - DESTRUCTOR - destroyed" << std::endl;
}


void Library::bind(u_int16_t protocolFamily)
{
	if (nfq_unbind_pf(_handle, protocolFamily) < 0)
		std::cout << "Cannot unbind protocol family" << std::endl;
	
	if (nfq_bind_pf(_handle, protocolFamily) < 0)
		std::cout << "Cannot bind protocol family" << std::endl;
}


void Library::loop()
{
	// Block INT signals
	{
		sigset_t intmask;
		sigemptyset(&intmask);
		sigaddset(&intmask, SIGINT);
		if (sigprocmask(SIG_BLOCK, &intmask, NULL) == -1)
			std::cout << "Cannot block INT signal" << std::endl;
	}
	
	// Ignore INT signals
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_flags = 0;
		sa.sa_handler = _sigint;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGINT, &sa, NULL) == -1)
			std::cout << "Cannot set INT handler" << std::endl;
	}
	
	sigset_t emptymask;
	sigemptyset(&emptymask);
	
	char buf[4096] __attribute__ ((aligned));
	//char buf[4096];
	int fd = nfq_fd(_handle);
	fd_set rfds;
	
	for (;;)
	{
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
		if (pselect(fd+1, &rfds, NULL, NULL, NULL, &emptymask) <= 0) {
			//std::cout << "BREAK @ pselect" << std::endl;
			break;
			//continue;
		}
		
		if (!FD_ISSET(fd, &rfds)) {
			//std::cout << "BREAK @ FD_ISSET" << std::endl;
			break;
			//continue;
		}
		
		//int rv = recv(fd, buf, sizeof(buf), 0);
		int rv = TEMP_FAILURE_RETRY(recv(fd, buf, sizeof(buf), 0));
		if (rv < 0) {
			//std::cout << "BREAK @ recv - returned - " << rv << std::endl;
			//break;
			continue;
		}
		
		nfq_handle_packet(_handle, buf, rv);
	}
}


