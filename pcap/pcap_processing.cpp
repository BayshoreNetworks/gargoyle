/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Several functions involved in the processing of pcap
 *
 * Copyright (c) 2017 - 2018, Bayshore Networks, Inc.
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

#include "../packet_handler.h"

#include <time.h>
#include <pcap/pcap.h>
#include <string>
#include <iostream>
#include <iomanip>

namespace pcap_processing{

	/*********************************************************************************************
	* get_pcap_precision()
	* It determines precision time between packets (*.pcapng can have nanosecond precision)	
	**********************************************************************************************/	
	std::string get_pcap_precision(uint64_t time){
		return  time/1000000 > 0 ? "nanoseconds" : "microseconds";
	}


	/*********************************************************************************************
	* process_messages_in_pcap()
	* Proccess all messages in a [cap | pcap | pcapng] file 
	**********************************************************************************************/
	bool process_messages_in_pcap(pcap_t *fdPcap, GargoylePscandHandler &gargoyleHandler, bool debug){
		const unsigned char *packet {nullptr};
		int pcapPacketNumber = 0, ret;
		std::string precisionBetweenPackets;

		struct pcap_pkthdr *header {nullptr};
		struct tm *time {nullptr};
		struct timeval previousTimeStamp{0, 0}, packetTimeStamp, timeBetweenPackets;
		struct timespec nanosecondsBetweenPackets;
		
		while((ret = pcap_next_ex(fdPcap, &header, &packet)) >= 0){
			if(pcapPacketNumber == 0){
				// Could be nanosecond precision though pcap_pkthdr maintains struct timeval instead of struct timespec
				precisionBetweenPackets = pcap_processing::get_pcap_precision(header->ts.tv_usec);
			}

			packetTimeStamp.tv_sec = header->ts.tv_sec;
			packetTimeStamp.tv_usec = header->ts.tv_usec;
			time = localtime(&packetTimeStamp.tv_sec);

			packetTimeStamp.tv_usec = precisionBetweenPackets == "microseconds" ? packetTimeStamp.tv_usec : packetTimeStamp.tv_usec/1000;

			if(debug){
				std::cout << "Extract packet " << ++pcapPacketNumber << " " << setfill('0') << setw(2) << time->tm_hour << ":"
						<< setw(2) << time->tm_min << ":" << setw(2) << time->tm_sec << ":" << setw(3) << packetTimeStamp.tv_usec << std::endl;
			}

			if(previousTimeStamp.tv_sec == 0 && previousTimeStamp.tv_usec == 0){
				timeBetweenPackets.tv_sec = 0;
				timeBetweenPackets.tv_usec = 0;
			}else{
				timeBetweenPackets.tv_sec = packetTimeStamp.tv_sec - previousTimeStamp.tv_sec;
				timeBetweenPackets.tv_usec = packetTimeStamp.tv_usec - previousTimeStamp.tv_usec;
			}

			// we sleep between package and package
			if(precisionBetweenPackets == "microseconds"){
				usleep(timeBetweenPackets.tv_sec*1000000 + timeBetweenPackets.tv_usec);
			}else{
				uint64_t nanoseconds = timeBetweenPackets.tv_sec*1000000000 + timeBetweenPackets.tv_usec;
				nanosecondsBetweenPackets.tv_sec = nanoseconds/1000000000;
				nanosecondsBetweenPackets.tv_nsec = nanoseconds % 1000000000;
				nanosleep(&nanosecondsBetweenPackets, NULL);
			}
			GargoylePscandHandler::packet_handler_pcap(const_cast<unsigned char *>(packet), header->caplen, &gargoyleHandler);
			previousTimeStamp.tv_sec = packetTimeStamp.tv_sec;
			previousTimeStamp.tv_usec = packetTimeStamp.tv_usec;
		}
		// According to pcap_next_ex documentation, it returns 1 if the packet was read without problems
		return ret == 1;
	}

	
};

