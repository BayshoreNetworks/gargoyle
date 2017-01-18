/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle Port Scan Detector
 * 
 * Config values for use across all gargoyle daemons/progs
 *
 * Copyright (c) 2017, Bayshore Networks, Inc.
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
#ifndef __gargoyleconfig__H_
#define __gargoyleconfig__H_


#ifdef __cplusplus
extern "C" {
#endif



//const char *GARGOYLE_VERSION = "1.0";
#define GARGOYLE_VERSION "1.0"
//const char *GARGOYLE_CHAIN_NAME = "GARGOYLE_Input_Chain";
#define GARGOYLE_CHAIN_NAME "GARGOYLE_Input_Chain"
#define IPTABLES_INPUT_CHAIN "INPUT"
//const char *IPTABLES = "iptables";
#define IPTABLES "iptables"
//const char *NFQUEUE = "NFQUEUE";
#define NFQUEUE "NFQUEUE"
#define NFQUEUE_NUM_LINE "NFQUEUE num 5"

//static const char *VIOLATOR_SYSLOG = "violator";
#define BLOCKED_SYSLOG "blocked"
#define VIOLATOR_SYSLOG "violator"
#define DETECTION_TYPE_SYSLOG "detection_type"
#define TIMESTAMP_SYSLOG "timestamp"
#define SIGNAL_CAUGHT_SYSLOG "Signal caught"
#define PROG_TERM_SYSLOG "program terminating"
#define ALREADY_RUNNING "process already running. See"


#ifdef __cplusplus
}
#endif


#endif // __gargoyleconfig__H_
