/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 *
 * Wrapper to iptables as a shared lib
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
#ifndef __stringfunctions__H_
#define __stringfunctions__H_

#include <vector>

#include <stdio.h>
#include <stdint.h>

#define DEST_BUF_SZ 524288
#define CMD_BUF_SZ 100




#ifdef __cplusplus


bool case_insensitive_char_compare(char a, char b) {
	return(toupper(a) == toupper(b));
}

bool case_insensitive_compare(const std::string& s1, const std::string& s2) {
	return((s1.size() == s2.size()) && equal(s1.begin(), s1.end(), s2.begin(), case_insensitive_char_compare));
}


extern "C" {
#endif


void *bayshoresubstring(size_t start, size_t stop, const char *src, char *dst, size_t size)
{
	if (!dst) return NULL;
	int count = stop - start;
	if ( count >= --size ) {
		count = size;
	}
	sprintf(dst, "%.*s", count, src + start);
	return dst;
}


void tokenize_string (
		const std::string &str,
		std::vector<std::string> &tokens,
		const std::string &delimiters) {

    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos = str.find_first_of(delimiters, lastPos);

    while (std::string::npos != pos || std::string::npos != lastPos)
    {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
}


std::string get_file_name(const std::string& s) {

	std::vector<std::string> tokens;

	tokenize_string(s, tokens, "/");

	if (tokens.size())
		return tokens[tokens.size() - 1];
	else
		return "";

}


#ifdef __cplusplus
}
#endif


#endif // __stringfunctions__H_
