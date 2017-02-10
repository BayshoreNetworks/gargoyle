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
#ifndef _NETFILTERQUEUE_H__
#define _NETFILTERQUEUE_H__

#include <string>

#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


// http://www.netfilter.org/projects/libnetfilter_queue/doxygen/group__LibrarySetup.html
class Library
{
public:
	/* opens a connection with nfq */
	Library();

	/* closes connection with nfq */
	~Library();

	/* binds nfq to a specific address/protocol family (e.g. AF_INET) */
	void bind(u_int16_t protocolFamily);

	/* processes packets, exits when interrupted with a SIGINT */
	void loop();

private:
	struct nfq_handle* _handle;
	friend class Queue;

	static void _sigint(int sig) {}
};

class Queue; //Forward Declare the Queue class

/* 
 * Abstract packet handler. This class is responsible for inspecting
 * packets, making block (iptables) decisions, interacting with the DB,
 * and setting a packet verdict.
 */
class PacketHandler
{
public:
	virtual int handle_packet(Queue& queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad) = 0;
};

/* packet handling pipeline */
class Queue
{
public:
	/*
	 * Creates a new nfq queue identified by #num using the specified
	 * packet handling pipeline.
	 */
	Queue(const Library& lib, u_int16_t num, PacketHandler& packetHandler);

	/* destroys the nfq queue */
	~Queue();

	void setVerdict(u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char *buf);

private:
	struct nfq_q_handle* _handle;

	PacketHandler& _packetHandler;

	static int _callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);
};

#endif // _NETFILTERQUEUE_H__
