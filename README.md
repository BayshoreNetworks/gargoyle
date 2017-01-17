# gargoyle
Gargoyle Port Scan Detector

This software (Gargoyle) was written on a Linux platform and is intended to run on Linux and no other platforms. It requires netfilter (kernel level), iptables (user space) and sqlite3.

Gargoyle was written to operate in high speed environments. Most of the stuff we analyzed before deciding to write Gargoyle worked off log file data. Gargoyle is different in that it operates off live network packet data. It has been compiled and tested on Debian, Ubuntu, Fedora and Raspbian.

Gargoyle is based on the notion of different severity levels where some blocks are immediate, others are based on a time cycle, and others are based on some analysis process. Then there is also a cleanup process to not leave block rules in forever and ever.

There are numerous run time entities:

	1. gargoyle_pscand - runs as the main daemon and expects signal 2 (SIGINT) to be brought down as there is a complex cleanup process upon the reciept of SIGINT.

		This is the main daemon that reads packet data right off the netfilter queue (set up as: "iptables -I INPUT -j NFQUEUE --queue-num 5")

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


- Default install path: /opt/gargoyle_pscand


- Required libs:

	Debian variant:

		sudo apt-get install libnetfilter-queue-dev sqlite3 libsqlite3-dev

	Fedora:

		sudo dnf install libnetfilter_queue-devel sqlite3 libsqlite3x-devel




- To compile and install:
```
make
sudo make deploy
```
- Optional environment variables to specify:
``` 
DESTDIR - for cross compilation. similar to autoconf DESTDIR
DEPLOY_TO - similar to autoconf '--prefix'
SYSROOT - path to system root provided by GCC
CROSS_COMPILE - cross compile prefix
```

- To compile on systems where netfilter is in a non-standard path:
```
NETFILTER_LIBRARY_PATH=
NETFILTER_INCLUDE_PATH=
NETFILTER_LIBS_EXTRA=
```
- To run the main daemon:

*** first time setup only [do this once the first time you set this up] ***: sudo cp db/port_scan_detect.db /opt/gargoyle_pscand/db/


- To run the main daemon:
```
(cd /opt/gargoyle_pscand && sudo LD_LIBRARY_PATH=lib ./gargoyle_pscand)
```
- To test the daemon (from another machine):
```
sudo nmap -sX <daemon_machine_ip>
```
- To view the blocked IPs:
```
sudo iptables -L -n
```
- To clear the blocked IPs:
```
sudo iptables -D GARGOYLE_Input_Chain <rulenum>
```
- To enable gargle as a systemd service:
```
cp etc-init.d-gargoyle /etc/init.d/gargoyle
chmod +x /etc/init.d/gargoyle
systemctl enable gargoyle
service gargoyle start, service gargoyle status, etc
```


TODO:

- calculate ports for the UDP singleton (GARG-4)

- add timestamp to block syslog line (GARG-5)

- add full iptables cleanup upon prog termination (GARG-7)

- add bool to turn on and off iptables rule addition (allow total passive mode with no block rules added) (GARG-8)

- build in support for a config file and we read global values from there (SINGLE_IP_SCAN_THRESHOLD, SINGLE_PORT_SCAN_THRESHOLD, LOCKOUT_TIME, etc) (GARG-10)

- add sync step that synchronizes iptables rules with the DB - part of cleanup process

- add support for -v in iptables query, use the number of hits/bytes in the cleanup decision

- cleanup/archive process for the DB (separate code to be cron'd)

- add support for HOT_PORTS - if these are encountered a block is immediate

- automate init.d script install






This software ignores certain elements by default so as to not be too agressive or disrupt legitimate functionality:

	- any open ports that the system is aware of (data comes from "/proc/net/tcp")
	- any port in the ephemeral range for the target system (data comes from "/proc/sys/net/ipv4/ip_local_port_range")
	- any port dictated by user created process (function "get_my_ports_to_ignore")
	- any ip address bound to the local system (data comes from system call to "ip addr")
	- system default gateway (data comes from "/proc/net/route")




BLOCK_TYPES - 1 - 5 are low hanging fruit, 6 - 8 are more statistical in nature

	1:'NULL Scan' (Stealth technique) - sends packets with no TCP flags set
	2:'FIN Scan' (Stealth technique) - sends packets with the FIN flag set but without first establishing a legitimate connection to the target
	3:'XMAS Scan' (Stealth technique) - sends packets with the URG, PUSH, FIN flags set
	4:'HALF Connect Scan' - This technique is based on the attacker not opening a full TCP connection. They send a SYN packet, as if to open a full connection, and wait for a response.
	5:'FULL Connect Scan' - This technique is based on the attacker opening a full TCP connection.
	6:'Single host scanned multiple ports' - example: host A scans 80 ports for openings, 1 hit for each 
	7:'Single host scanned one port multiple times' - example: host A hits port 23 80 times 
	8:'Single host generated too much port scanning activity' - this is cumulative and covers combinations of 6 & 7 where either one of those alone would not trigger detection


