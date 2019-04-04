/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Wrapper to iptables as a shared lib
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
#ifndef __gargoyleiptableswrapper__H_
#define __gargoyleiptableswrapper__H_


#include <stdio.h>
#include <stdint.h>

#define DEST_BUF_SZ 524288
#define CMD_BUF_SZ 100

#ifdef __cplusplus
extern "C" {
#endif


size_t iptables_create_new_chain(const char *, size_t);
size_t iptables_flush_chain(const char *, size_t);
size_t iptables_list_chain(const char *, char *, size_t, size_t);
size_t iptables_list_chain_with_line_numbers(const char *, char *, size_t, size_t);
size_t iptables_list_all_with_line_numbers(char *, size_t, size_t);
size_t iptables_list_all(char *, size_t, size_t);
size_t iptables_delete_chain(const char *, size_t);
size_t iptables_delete_rule_from_chain(const char *, size_t, size_t);
size_t iptables_add_drop_rule_to_chain(const char *, const char *, size_t);
size_t iptables_insert_chain_rule_to_chain_at_index(const char *, const char *, const char *, size_t);
size_t iptables_find_rule_in_chain(const char *, const char *, size_t);
size_t iptables_find_rule_in_chain_two_criteria(const char *, const char *, const char *, size_t);
size_t iptables_insert_nfqueue_rule_to_chain_at_index(const char *, size_t, size_t);
size_t iptables_supports_xlock();
size_t iptables_list_chain_table(const char *, const char *, char *, size_t, size_t);
size_t iptables_insert_nflog_rule_to_chain_at_index(const char *, size_t, size_t);


#ifdef __cplusplus
}
#endif


#endif // __gargoyleiptableswrapper__H_
