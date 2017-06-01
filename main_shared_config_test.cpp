/*****************************************************************************
 *
 * GARGOYLE_PSCAND: Gargoyle - Protection for Linux
 * 
 * command line program that provides an interactive test harness for verifying shared IP config
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
#define DEBUG

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>
using namespace std;

#include "shared_config.h"
#include <assert.h>

#define CONFIG_NAME "/testregion"
#define CONFIG_SIZE 200

#define MAIN_CHECK(x, res)       \
    if((x) < 0) {                \
        res = 1;                 \
    } else {                     \
        res = 0;                 \
    }

static char *g_prog_name = NULL;
SharedIpConfig *g_shared_config = NULL;

void deleteConfig() {
    if(g_shared_config) {
        delete g_shared_config;
        g_shared_config;
        exit(0);
    }
}

void sigintHandler(int sig) {
    deleteConfig();
}

void handleHelp() {
    printf("\n");
    printf("Syntax:\n");
    printf("\n");
    printf("  %s <command>\n", g_prog_name);
    printf("    Commands\n");
    printf("\n");
    printf("      contains <ip>            - validates that <ip> is in the shared region\n");
    printf("      add <ip>                 - adds <ip> to the shared config\n");
    printf("      remove <ip>              - removes <ip> from the shared config\n");
    printf("      size                     - show the number of ip elements\n");
    //printf("      print                    - print the entire table of IPs\n");
    printf("      batch <start> <count>    - write <count> ip's starting at <start> word\n");
    printf("      validate <start> <count> - validate that <count> ip's starting at <start> word are in the region\n");
    printf("      daemon                   - accesses the config region. runs in an infinite loop so we can retain state\n");
    printf("\n");
}

void initConfig() {
    printf("Creating config '%s'\n", CONFIG_NAME);
    g_shared_config = SharedIpConfig::Create(CONFIG_NAME, CONFIG_SIZE);
    assert(g_shared_config);
}

int32_t handleContains(int count, char **arg) {
    initConfig();
    bool result;

    if(count != 1) {
        handleHelp();
        return -1;
    }

    assert(!g_shared_config->Contains(string(arg[0]), &result));

    if(result) {
        printf("Found\n");
    } else {
        printf("Not Found\n");
    }

    return 0;
}

/*int32_t handlePrint(int count, char **arg) {
    initConfig();

    for(int ix = 0; ix < g_shared_config->Size(); ix++) {
        string ip_addr;
        assert(!g_shared_config->ElementAt(ix, ip_addr));
        printf("%s\n", ip_addr.c_str());
    }
    return 0;
}*/

int32_t handleRemove(int count, char **arg) {
    initConfig();

    if(count != 1) {
        handleHelp();
        return -1;
    }

    printf("Removing element '%s'\n", arg[0]);
    assert(!g_shared_config->Remove(string(arg[0])));
    return 0;
}

int32_t handleAdd(int count, char **arg) {
    initConfig();

    if(count != 1) {
        handleHelp();
        return -1;
    }

    printf("Adding IP address: %s\n", arg[0]);
    assert(!g_shared_config->Add(string(arg[0])));
    return 0;
}

int32_t handleBatch(int count, char **arg) {
    in_addr_t start;
    int32_t batch_count = 0;

    initConfig();

    if(count != 2) {
        handleHelp();
        return -1;
    }

    start = strtol(arg[0], NULL, 10);
    batch_count = strtol(arg[1], NULL, 10);

    printf("Writing count '%d' IP addresses starting at '0x%08x'\n", batch_count, start);
    for(int32_t i = 0; i < batch_count; i++) {
        in_addr addr;
        addr.s_addr =  start + i;
        printf("IP:%s\n", string(inet_ntoa(addr)).c_str());
        assert(!g_shared_config->Add(string(inet_ntoa(addr))));
        usleep(1000 * (random() % 100));
    }
    return 0;
}

int32_t handleValidate(int count, char **arg) {
    in_addr_t start;
    int32_t batch_count = 0;

    initConfig();

    if(count != 2) {
        handleHelp();
        return -1;
    }

    start = strtol(arg[0], NULL, 10);
    batch_count = strtol(arg[1], NULL, 10);

    printf("Validating count '%d' IP addresses starting at '0x%08x'\n", batch_count, start);

    for(int32_t i = 0; i < batch_count; i++) {
        bool result = false;
        string ip1;
        in_addr addr;
        addr.s_addr = start + i;
        ip1 = string(inet_ntoa(addr));
        assert(!g_shared_config->Contains(ip1, &result));
        if(!result) {
            printf("IP Address '%s' does not exist\n", ip1.c_str());
            return 0;
        }
    }

    printf("OK\n");
    return 0;
}
int32_t handleDaemon(int count, char **arg) {
    initConfig();
    while(1) {
        printf("Sleeping\n");
        sleep(-1);
    }
    return 0;
}

int32_t handleSize(int count, char **arg) {
    initConfig();
    printf("Number of IP entries: %ld\n", g_shared_config->Size());
    return 0;
}
int main(int argc, char *argv[]) {
    char **arg = NULL;
    int res = 0;

    assert(!signal(SIGINT, sigintHandler));

    arg = &argv[0];
    argc--;

    g_prog_name = *arg;

    if(argc < 1) {
        handleHelp();
        return 0;
    }

    arg++;

    if(!strcmp(*arg, "contains")) {
        MAIN_CHECK(handleContains(--argc, ++arg), res);
    //} else if(!strcmp(*arg, "print")) {
    //    MAIN_CHECK(handlePrint(--argc, ++arg));
    } else if(!strcmp(*arg, "add")) {
        MAIN_CHECK(handleAdd(--argc, ++arg), res);
    } else if(!strcmp(*arg, "daemon")) {
        MAIN_CHECK(handleDaemon(--argc, ++arg), res);
    } else if(!strcmp(*arg, "size")) {
        MAIN_CHECK(handleSize(--argc, ++arg), res);
    } else if(!strcmp(*arg, "remove")) {
        MAIN_CHECK(handleRemove(--argc, ++arg), res);
    } else if(!strcmp(*arg, "batch")) {
        MAIN_CHECK(handleBatch(--argc, ++arg), res);
    } else if(!strcmp(*arg, "validate")) {
        MAIN_CHECK(handleValidate(--argc, ++arg), res);
    } else {
        printf("Unrecognized command '%s'\n", *arg);
        handleHelp();
    }

    deleteConfig();

    return res;
}

