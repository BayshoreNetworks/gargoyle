#****************************************************************************
#
#
# Makefile
#
# Copyright (c) 2016, Bayshore Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that
# the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#****************************************************************************/

include ../defaults.mk

CFLAGS=-fpic --sysroot=$(SYSROOT)

ifneq ($(NETFILTER_INCLUDE_PATH),)
CFLAGS+=-I$(NETFILTER_INCLUDE_PATH)
endif

ifneq ($(NETFILTER_LIBRARY_PATH),)
LDFLAGS+=-L$(NETFILTER_LIBRARY_PATH)
endif

IPTABLES_LIBNAME=libgargoyleiptableswrapper
IPTABLES_LIBFILE=$(IPTABLES_LIBNAME).so
IPTABLES_STATLIBFILE=$(IPTABLES_LIBNAME).a
MAJOR_VERSION=1
IPTABLES_LIBSONAME=$(IPTABLES_LIBFILE).$(MAJOR_VERSION)

SQLITE_LIBNAME=libgargoylesqlitewrapper
SQLITE_LIBFILE=$(SQLITE_LIBNAME).so
SQLITE_STATLIBFILE=$(SQLITE_LIBNAME).a
MAJOR_VERSION=1
SQLITE_LIBSONAME=$(SQLITE_LIBFILE).$(MAJOR_VERSION)

DEL_FILE=rm -rf

IPTABLESLIBOBJS=iptables_wrapper_api.o

SQLITELIBOBJS=sqlite_wrapper_api.o


all: $(IPTABLES_LIBFILE) $(SQLITE_LIBFILE)

lib: $(IPTABLES_LIBFILE) $(SQLITE_LIBFILE)

clean:
	-$(DEL_FILE) $(IPTABLESLIBOBJS) *~
	-$(DEL_FILE) $(IPTABLES_LIBFILE)
	-$(DEL_FILE) $(IPTABLES_STATLIBFILE)
	-$(DEL_FILE) $(IPTABLES_LIBSONAME)
	-$(DEL_FILE) $(SQLITELIBOBJS) *~
	-$(DEL_FILE) $(SQLITE_LIBFILE)
	-$(DEL_FILE) $(SQLITE_STATLIBFILE)
	-$(DEL_FILE) $(SQLITE_LIBSONAME)
	

$(IPTABLES_LIBFILE): $(IPTABLESLIBOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(IPTABLESLIBOBJS) -o $(IPTABLES_LIBFILE)
	$(STRIP) $(IPTABLES_LIBFILE)
	ln -fs $(IPTABLES_LIBFILE) $(IPTABLES_LIBSONAME)
	$(AR) -ru $(IPTABLES_STATLIBFILE) $(IPTABLESLIBOBJS)
	
$(SQLITE_LIBFILE): $(SQLITELIBOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $(SQLITELIBOBJS) -o $(SQLITE_LIBFILE) -lsqlite3
	$(STRIP) $(SQLITE_LIBFILE)
	ln -fs $(SQLITE_LIBFILE) $(SQLITE_LIBSONAME)
	$(AR) -ru $(SQLITE_STATLIBFILE) $(SQLITELIBOBJS)
	
	

