# gargoyle
Gargoyle Port Scan Detector

This software (Gargoyle_pscand) was written on a Linux platform and is intended to run on Linux and no other platforms. It requires netfilter (kernel level), iptables (user space) and sqlite3.

Gargoyle_pscand was written to operate in high speed environments. Most of the stuff we analyzed before deciding to write Gargoyle_pscand worked off log file data. Gargoyle_pscand is different in that it operates off live network packet data. It has been compiled and tested on Debian, Ubuntu, and Raspbian. If you compile and run it successfully on some other platform please let us know the details.

Gargoyle_pscand is based on the notion of different severity levels where some blocks are immediate, others are based on a time cycle, and others are based on some analysis process. Then there is also a cleanup process to not leave block rules in forever and ever.

There are numerous run time entities:

	1. gargoyle_pscand - runs as the main daemon and expects signal 2 (SIGINT) to be brought down as there is a complex cleanup process upon the reciept of SIGINT.

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


	3. gargoyle_pscand_analysis - runs as a daemon with an internal timed cycle. The default cycle is a run every 30 minutes based off whenever the daemon was started. This prog will analyze the data in the DB and the data in our iptables chain and add block rules (and DB entries) for targets who are using straggered techniques (slow and low scans, etc) or somehow got past the main daemon.

	4. gargoyle_pscand_unblockip - this is a standalone program that accepts one argument (an ip address string) and will cleanup/remove all traces of that ip address except for the fact that we once encountered it. The thought process here is that you deliberately removing an ip address means you are treating this address as a trusted entity and want no future blocks of it.

		- To run:
			cd install_path
			./gargoyle_pscand_unblockip ip_addr



Default install path: /opt/gargoyle_pscand


Required libs

	Debian variant:

		sudo apt-get install sqlite3 libsqlite3-dev autoconf lsb-base libnetfilter-log-dev

	Fedora:

		sudo dnf install sqlite3 libsqlite3x-devel autoconf redhat-lsb-core libnetfilter_log-devel


Database:

	The database file name is "port_scan_detect.db"

	By default Gargoyle_pscand will look for the path to a database file in ENV variable "GARGOYLE_DB". If that is not present it will default to the root dir for the program plus "/db/port_scan_detect.db"


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



To compile and install:

	sudo ./build.sh
	sudo make install


Notes:

	- DO NOT manually manipulate any of the data in the iptables chain "GARGOYLE_Input_Chain". This data is syncronized with data in the DB and it is important for that synchronization is be respected.

	- To start/stop the Gargoyle_pscand daemons use the init script.

	- When one stops the dameons properly (init script [under the hood sends SIGINT]) there is a full cleanup process where all relevant iptables/DB data gets cleaned up.

	- Currently addresses TCP ports, UDP support will come soon
	
	- This software ignores certain elements by default so as to not be too aggressive or disrupt legitimate functionality:

		- any port that the system is aware of (data comes from "/proc/net/tcp")
		- any port in the ephemeral range for the target system (data comes from "/proc/sys/net/ipv4/ip_local_port_range")
		- any port established in the config file ".gargoyle_config", with key "ports_to_ignore"
		- any ip address bound to the local system (data comes from system call to "ip addr")
		- any ip address whitelisted in the DB 
		- system default gateway (data comes from "/proc/net/route")

	- BLOCK TYPES - 1 - 5 are low hanging fruit, 6 - 8 are more statistical in nature

		1:'NULL Scan' (Stealth technique) - sends packets with no TCP flags set
		2:'FIN Scan' (Stealth technique) - sends packets with the FIN flag set but without first establishing a legitimate connection to the target
		3:'XMAS Scan' (Stealth technique) - sends packets with the URG, PUSH, FIN flags set
		4:'HALF Connect Scan' - This technique is based on the attacker not opening a full TCP connection. They send a SYN packet, as if to open a full connection, and wait for a response.
		5:'FULL Connect Scan' - This technique is based on the attacker opening a full TCP connection.
		6:'Single host scanned multiple ports' - example: host A scans 80 ports for openings, 1 hit for each 
		7:'Single host scanned one port multiple times' - example: host A hits port 23 80 times 
		8:'Single host generated too much port scanning activity' - this is cumulative and covers combinations of 6 & 7 where either one of those alone would not trigger detection
		9:'Hot Port' triggered - This means the user wants an immediate block of any entity that touches this port

	
	- Overtly malicious activity will trigger immediate blocks of the source that Gargoyle_pscand sees. This activity does not store enough data in the analysis related DB tables to trigger subsequent blocks in the case of a software restart.

	- If you are interested in performing analysis on data that Gargoyle_pscand generates then make sure you pipe syslog to an endpoint you control and where this data will be properly stored for analysis. The internal DB that Gargoyle_pscand uses will clean itself up over time in order to keep analysis performance acceptable.




