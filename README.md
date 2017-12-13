# gargoyle

<p>
<a href="https://scan.coverity.com/projects/bayshorenetworks-gargoyle">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/13905/badge.svg"/>
</a>
<a href="https://www.openhub.net/p/gargoyle-scand?ref=Thin+badge" rel="nofollow"><img alt="OpenHub-Status" src="https://www.openhub.net/p/gargoyle-scand/widgets/project_thin_badge?format=gif" data-canonical-src="https://www.openhub.net/p/gargoyle-scand/widgets/project_thin_badge?format=gif" style="max-width:100%;"></a></p>
</p>

Gargoyle Protection for Linux

There are 2 main components to Gargoyle:

	1. Gargoyle_pscand (port scan detection)
	2. Gargoyle_lscand (log scanner)

This software (Gargoyle_*) was written on a Linux platform and is intended to run on Linux and no other platforms. It requires netfilter (kernel level), iptables (user space) and sqlite3.

The Gargoyle_* software was written to operate in high speed environments. Most of the stuff we analyzed before deciding to write Gargoyle_* worked off log file data. Gargoyle_pscand is different in that it operates off live network packet data. Gargoyle_lscand* works off log file data. They have been compiled and tested on Debian, Ubuntu, and Raspbian. If you compile and run successfully on some other platform please let us know the details.

Gargoyle_pscand is based on the notion of different severity levels where some blocks are immediate, others are based on a time cycle, and others are based on some analysis process. Then there is also a cleanup process to not leave block rules in forever and ever.

There are numerous run time entities:

	1. gargoyle_pscand - runs as the main daemon and expects signal 2 (SIGINT) to be brought down as there is a complex cleanup process upon the receipt of SIGINT.

		This is the main daemon that reads packet data right off iptables via NFLOG (set up as: "iptables -I INPUT -j NFLOG --nflog-group 5")

		There are multiple layers to this solution (as part of the running main daemon):

		Layer 1 - Immediate rules to block are added to iptables upon detection of blatantly obvious scans (such as FIN/XMAS/NULL scans)

		Layer 2 - A cycled process takes place with the default value of a cycle every 2 minutes, there are 2 phases here:

			- phase 1 creates blocking rules for ip addr's that have been flagged as black listed, this means some anomalous behaviour has been identified
		
			- phase 2 has 2 layers of behavior itself:

				- layer 1 - creates blocking rules when the following conditions are encountered:

					- one src ip has scanned an anomalous number of ports

					- one src ip has scanned one specific port an anomalous number of times

				- layer 2 - does not create blocking rules but inserts rows with details into a DB table, this means there wasnt enough data to make a blocking decision but the data must be tracked as it be relevant in subsequent analysis


	2. gargoyle_pscand_monitor - runs as a daemon with an internal timed cycle. The default cycle is a run every 12 hours based off whenever the daemon was started. This prog will analyze the active rules in our iptables chain and clean out the ones who have been jailed past the point set at variable LOCKOUT_TIME. The clean up process also updates records in the DB.

	3. gargoyle_pscand_analysis - runs as a daemon with an internal timed cycle. The default cycle is a run every 15 minutes based off whenever the daemon was started. This prog will analyze the data in the DB and the data in our iptables chain and add block rules (and DB entries) for targets who are using straggered techniques (slow and low scans, etc) or somehow got past the main daemon.

	4. gargoyle_pscand_unblockip - this is a standalone program that accepts one argument (an ip address string) and will cleanup/remove all traces of that ip address except for the fact that we once encountered it. The thought process here is that you deliberately removing an ip address means you are treating this address as a trusted entity and want no future blocks of it.

		- To run:
			cd install_path
			./gargoyle_pscand_unblockip ip_addr
			
	5. gargoyle_pscand_remove_from_whitelist - this is a standalone program that accepts one argument (an ip address string) and will remove that ip address from the white list (ignored ip addresses) (DB table & shared mem).

	6. gargoyle_lscand_ssh_bruteforce - runs as a daemon and monitors log file data looking for inidcators and patterns of SSH brute force attacks.

	7. gargoyle_pscand_remove_from_blacklist - this is a standalone program that accepts one argument (an ip address string) and will remove that ip address from the black list (blocked ip addresses) and all related entities (DB table, shared mem, etc).

	8. gargoyle_lscand_bruteforce - runs as a daemon and monitors log file data looking for indicators and patterns based on the user provided data in the .conf files located in directory conf.d. 

	9. gargoyle_regex_tester - a standalone program to help users test their regex strings against either a string or data in a file. For details and examples see the section entitled 'notes on gargoyle_regex_tester'


Default install path: /opt/gargoyle_pscand


Required libs

	Debian variant:

		sudo apt-get install sqlite3 libsqlite3-dev autoconf lsb-base libnetfilter-log-dev

	Fedora:

		sudo dnf install sqlite3 libsqlite3x-devel autoconf redhat-lsb-core libnetfilter_log-devel


Database:

	The database file name is "gargoyle_attack_detect.db"

	By default Gargoyle_pscand will look for the path to a database file in ENV variable "GARGOYLE_DB". If that is not present it will default to the root dir for the program plus "/db/gargoyle_attack_detect.db"


Config data:

	Gargoyle_pscand needs to read data from a config file that holds a series of modifiable key/value pairs.

	By default it will look for a path to a file called "gargoyle_config" in ENV variable "GARGOYLE_CONFIG". If that is not present it expects a file named ".gargoyle_config" (in the programs root dir). The code in all 3 Gargoyle_pscand daemons will act based on the values they read from this config file. This means you can modify the values if you wish and the programs will respect the values you put in.

	The following are the supported config keys:

		- "enforce" - boolean type - acceptable values are 1 and 0 where 1 means block (make iptables and syslog entries when appropriate) and 0 means only report (write syslog entries only and take no blocking action)

		- "port_scan_threshold" - integer representing count - when performing analysis of the activity of each host this value is the threshold count of hits per unique port. If this threshold is surpassed for any one port by any given host Gargoyle_pscand will treat that as malicious activity

		- "single_ip_scan_threshold" - integer representing count - when performing analysis of the activity of each host this value is the threshold count of ports that were scanned. If this threshold is surpassed by any given host Gargoyle_pscand will treat that as malicious activity

		- "overall_port_scan_threshold" - integer representing count - when performing analysis of the activity of each host this value is the threshold count of collective activity. Collective activity is based on combinations of actions, for example if one host hits port 23 four times and ports 80,443,8080,9000,9090 each once. If this threshold is surpassed by any given host Gargoyle_pscand will treat that as malicious activity

		- "last_seen_delta" - integer representing seconds - Gargoyle_pscand’s processes will only block hosts that have been seen within (less than) this value 

		- "lockout_time" - integer representing seconds - if a host has been blocked by Gargoyle_pscand for a period longer than this value it will be unblocked

		- "ports_to_ignore" - comma delimited string of ports for Gargoyle_pscand to ignore while processing live network traffic. A range of ports is supported if the format is properly used (x-y). Example (note no white spaces when specifying a range): ports_to_ignore:22,443,80-90,8080,8443-8448,502

		- "hot_ports" - comma delimited string of ports for Gargoyle_pscand to immediately create a block action (of the relevant src ip) upon encountering
		
	Gargoyle lscand (log file scanner) reads config files inside directory "conf.d". An example is provided, here is the content:
	
		- enabled:0
		- enforce:1
		- log_entity:/var/log/syslog
		- regex:401 POST *.+ \((.*)\)
		- number_of_hits:6
		- time_frame:120
	
		Details:
	
			"enabled" is either 0 or 1, a value of 1 means that config file will be used by a running daemon
	
			"enforce" is either 0 or 1, a value of 1 means that iptables rules will be added upon the regex trigger thresholds being hit
	
			"log_entity" is the full path of the log file the lscand daemon will monitor
		
			"regex" is the regex string that will be used against the data seen in the log file (log_entity). Take note that the match entity (inside the parenthesis) needs to be an ip address so that a block can be created if appropriate.
		
			"number_of_hits" is the number of regex triggers we will look for within the time frame set in key "time_frame" 


gargoyle_admin_wrapper.py - wrapper to multiple Gargoyle administrative functions.

    Functions included:

        1. get_current_config - Input: None. Output: Current configuration in .gargoyle_config as a json object

        2. set_config - Input: Json object containing new desired configuration of .gargoyle_config. Functionality: Updates .gargoyle_config with the key-value pairs. Output: Integer

        3. unblock_ip - Input: String of an ip address to be unblocked. Functionality: Unblocks the desired ip. Output: Integer

        4. get_current_white_list - Input: None. Output: List of ip addresses currently in the white list(db table 'ignore_ip_list')

        5. add_to_white_list - Input: String of an ip address to add to the white list. Functionality: Adds the desired ip to the white list. Output: Integer

        6. remove_from_white_list - Input: String of an ip address to remove from the white list. Functionality: Removes the desired ip from the white list. Output: Integer

        7. get_current_from_iptables - Input: None. Output: Returns list of ip addresses currently being blocked

    Note: For any admin functions above that return an integer, a return value of 0 indicates success of the functionality while 1 indicates some sort of failure. 

To compile and install:

	sudo ./build.sh
	sudo make install


Notes:

	- DO NOT manually manipulate any of the data in the iptables chain "GARGOYLE_Input_Chain". This data is synchronized with the data in the DB, and it is important that the synchronization is respected.

	- To start/stop the Gargoyle_pscand daemons use the init script. If Gargoyle fails to start, try running:
          systemctl daemon-reload ; service gargoyle_pscand stop ; service gargoyle_pscand start

	- When one stops the daemons properly (init script [under the hood sends SIGINT]) there is a full cleanup process where all relevant iptables/DB data gets cleaned up.

	- Currently addresses TCP ports, UDP support will come soon
	
	- This  port scanning detection software ignores certain elements by default so as to not be too aggressive or disrupt legitimate functionality:

		- any port that the system is aware of (data comes from "/proc/net/tcp")
		- any port in the ephemeral range for the target system (data comes from "/proc/sys/net/ipv4/ip_local_port_range")
		- any port established in the config file ".gargoyle_config", with key "ports_to_ignore"
		- any ip address bound to the local system (data comes from system call to "ip addr")
		- any ip address whitelisted in the DB 
		- system default gateway (data comes from "/proc/net/route")

	- Port scan detection BLOCK TYPES - 1 - 5 are low hanging fruit, 6 - 8 are more statistical in nature

		1:'NULL Scan' (Stealth technique) - sends packets with no TCP flags set
		2:'FIN Scan' (Stealth technique) - sends packets with the FIN flag set but without first establishing a legitimate connection to the target
		3:'XMAS Scan' (Stealth technique) - sends packets with the URG, PUSH, FIN flags set
		4:'HALF Connect Scan' - This technique is based on the attacker not opening a full TCP connection. They send a SYN packet, as if to open a full connection, and wait for a response [deprecated]
		5:'FULL Connect Scan' - This technique is based on the attacker opening a full TCP connection [deprecated]
		6:'Single host scanned multiple ports' - example: host A scans 80 ports for openings, 1 hit for each 
		7:'Single host scanned one port multiple times' - example: host A hits port 23 80 times 
		8:'Single host generated too much port scanning activity' - this is cumulative and covers combinations of 6 & 7 where either one of those alone would not trigger detection
		9:'Hot Port' triggered - This means the user wants an immediate block of any entity that touches this port

	- Log scan detection BLOCK TYPES:

		50:'SSH brute force attack detected' - An SSH brute force attack was detected and blocked. Take note of the fact that for this use case the actual SSH port is not relevant so these actions are identified via a fake port defined in "main_iptables_ssh_bruteforce.cpp", the default being 65537. Relevant slow and low activity is registered in the DB and processed by the analysis daemon.
		51:'brute force attack detected' - A brute force attack was detected and blocked. The definition of brute force attack as it applies here is based on number of regex hits (user provided regex) within time frame (user provided value) in the some log file (user provided log file).
		
	- Blacklist BLOCK TYPE:

		100: The ip addr in question has been blacklisted by the user, this data is stored in the DB table 'black_ip_list'
	
	- Overtly malicious activity will trigger immediate blocks of the source that Gargoyle_pscand sees. This activity does not store enough data in the analysis related DB tables to trigger subsequent blocks in the case of a software restart.

	- If you are interested in performing analysis on data that Gargoyle_pscand generates then make sure you pipe syslog to an endpoint you control and where this data will be properly stored for analysis. The internal DB that Gargoyle_pscand uses will clean itself up over time in order to keep performance acceptable.
	
	- To remove ip addresses from the white (or ignore) list, or the blacklist, use the respective standalone programs "gargoyle_pscand_remove_from_whitelist" or "gargoyle_pscand_remove_from_blacklist", do not manually remove that ip address from the DB table.


Notes on gargoyle_regex_tester:

	The most important point here is that this is NOT a generic regex tester. It is designed to be useful in verifying a regex to be used with gargoyle to detect ip addresses within log file data. Your regex should be written to target ip addresses that are doing something nefarious to the system gargoyle is protecting. 

	Usage:
	
		./gargoyle_regex_tester -r regex_string -l target_string_or_file


	Example:
	
		For this example we have a web application that logs unsuccessful login attempts to a file called "/var/log/myapp_bad_logins.log"

		Our log file used for this example has the following data in it:

			$ cat /var/log/myapp_bad_logins.log 
			Dec 12 23:53:27 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msffabcdef
			Dec 12 23:53:27 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msffabcdef
			Dec 12 23:53:27 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msffabcdef
			Dec 12 23:53:27 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msff
			Dec 12 23:53:28 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msffabcdef
			Dec 12 23:53:28 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.228.120.126) 25.79msffabcdef
			Dec 12 23:53:28 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.258.120.126) 25.79msffabcdef
			Dec 12 23:53:28 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.258.120.126) 25.79ms
			Dec 12 23:53:29 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.258.120.126) 25.79msffabcdef
			Dec 12 23:53:29 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.251.120.126) 25.79msffabc
			Dec 12 23:53:29 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.251.120.126) 25.79msffabcdef
			Dec 12 23:53:30 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (192.251.120.126) 25.79msffabcdef
			Dec 12 23:53:30 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (12.168.170.26) 25.79msffabcdef

		Our regex test run:
		
			$ ./gargoyle_regex_tester -r "401 POST *.+ \((.*)\)" -l /var/log/myapp_bad_logins.log

			Results
			=======
			
			Entity scanned is a file named "/var/log/myapp_bad_logins.log"
			13 lines were consumed and scanned
			Regex used: 401 POST *.+ \((.*)\)
			Number of hits for this regex: 13
			Number of valid IP ADDRs from regex hits: 10
			
			Unique list of valid IP ADDRs discovered:
			-----------------
			192.228.120.126
			192.251.120.126
			12.168.170.26
			
		*** Take note that ip addresses are validated here and this is why there were 13 regex hits but only 10 valid ones as "192.258.120.126" is not a valid ip address ***


		You could also use gargoyle_regex_tester with a target string instead of a file as such:
		
			$ ./gargoyle_regex_tester -r "401 POST *.+ \((.*)\)" -l "Dec 12 23:53:30 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (12.168.170.26) 25.79msffabcdef"

			Results
			=======
			
			Entity scanned is a string: "Dec 12 23:53:30 GARGOYLE-EXT-TEST spal: WARNING bayshore - 401 POST /login (12.168.170.26) 25.79msffabcdef"
			Regex used: 401 POST *.+ \((.*)\)
			Number of hits for this regex: 1
			Number of valid IP ADDRs from regex hits: 1
			
			Unique list of valid IP ADDRs discovered:
			-----------------
			12.168.170.26


			



