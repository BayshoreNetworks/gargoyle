CPPFLAGS=-I. -Ilib

include_HEADERS = lib/config_variables.h lib/gargoyle_config_vals.h lib/iptables_wrapper_api.h lib/singleton.h lib/sqlite_wrapper_api.h nf_queue.h packet_handler.h

lib_GARGOYLE_PSCAND = lib

bin_PROGRAMS = gargoyle_pscand gargoyle_pscand_analysis gargoyle_pscand_monitor gargoyle_config gargoyle_pscand_unblockip

gargoyle_pscand_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c packet_handler.cpp main_daemon.cpp

gargoyle_pscand_analysis_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c main_iptables_analysis.cpp

gargoyle_pscand_monitor_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c main_iptables_monitor.cpp

gargoyle_config_SOURCES = gargoyle_config.cpp

gargoyle_pscand_unblockip_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c main_iptables_remove.cpp
