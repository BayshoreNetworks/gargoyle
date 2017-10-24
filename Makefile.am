CPPFLAGS=-I. -Ilib -Wreturn-type

include_HEADERS = lib/config_variables.h lib/gargoyle_config_vals.h lib/iptables_wrapper_api.h lib/singleton.h lib/sqlite_wrapper_api.h packet_handler.h ip_addr_controller.h

lib_GARGOYLE_PSCAND = lib

bin_PROGRAMS = gargoyle_pscand \
				gargoyle_pscand_analysis \
				gargoyle_pscand_monitor \
				gargoyle_config \
				gargoyle_pscand_unblockip \
				gargoyle_lscand_ssh_bruteforce \
				gargoyle_shared_config_test \
				gargoyle_pscand_remove_from_whitelist \
				gargoyle_pscand_remove_from_blacklist \
				gargoyle_lscand_bruteforce \
				gargoyle_lscand_bruteforce_detect \
				gargoyle_view_shared_mem
				
gargoyle_pscand_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp packet_handler.cpp lib/shared_config.cpp lib/shared_mem.cpp main_daemon.cpp

gargoyle_pscand_analysis_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp lib/shared_config.cpp lib/shared_mem.cpp main_iptables_analysis.cpp

gargoyle_pscand_monitor_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp lib/shared_config.cpp lib/shared_mem.cpp main_iptables_monitor.cpp

gargoyle_config_SOURCES = gargoyle_config.cpp

gargoyle_pscand_unblockip_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp lib/shared_config.cpp lib/shared_mem.cpp main_iptables_remove.cpp

gargoyle_lscand_ssh_bruteforce_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp lib/shared_config.cpp lib/shared_mem.cpp main_iptables_ssh_bruteforce.cpp

gargoyle_shared_config_test_SOURCES = lib/shared_config.cpp lib/shared_mem.cpp main_shared_config_test.cpp

gargoyle_pscand_remove_from_whitelist_SOURCES = lib/sqlite_wrapper_api.c lib/shared_config.cpp lib/shared_mem.cpp main_iptables_remove_from_whitelist.cpp

gargoyle_pscand_remove_from_blacklist_SOURCES = lib/iptables_wrapper_api.c ip_addr_controller.cpp lib/sqlite_wrapper_api.c lib/shared_config.cpp lib/shared_mem.cpp main_iptables_remove_from_blacklist.cpp

gargoyle_lscand_bruteforce_SOURCES = lib/iptables_wrapper_api.c lib/sqlite_wrapper_api.c ip_addr_controller.cpp lib/shared_config.cpp lib/shared_mem.cpp main_iptables_bruteforce.cpp

gargoyle_lscand_bruteforce_detect_SOURCES = main_iptables_bruteforce_detect.c

gargoyle_view_shared_mem_SOURCES = lib/shared_config.cpp lib/shared_mem.cpp view_shared_mem.cpp

