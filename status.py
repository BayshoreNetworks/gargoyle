#!/usr/bin/env python
from utils.gargoyle_admin_wrapper import *
import argparse

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
P  = '\033[35m' # purple
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

def blocked(blockedIps):
    print(R+"Blocked IPs".ljust(24)+ R+"Time Blocked".ljust(28)+ R+"Time Unblocked"+W)
    print(P+"\n*Note: this does not take into account manual unblocking or adding to white list\n"+W)
    for ip in blockedIps.keys():
        if blockedIps[ip][1] == 0:
            print ip.ljust(23), blockedIps[ip][0].ljust(27), "When removed from black list"
        else:
            print ip.ljust(23), blockedIps[ip][0].ljust(27), blockedIps[ip][1]
    print '\n'

def whiteListed(whiteList):
    print(R+"White Listed IPs".ljust(24) + R+"Time White Listed"+W)
    for ip in whiteList.keys():
        print ip.ljust(23) , whiteList[ip]
    print '\n'

def blackListed(blackList):
    print(R+"Black Listed IPs".ljust(24) + R+"Time Black Listed"+W)
    for ip in blackList:
        print ip.ljust(23), blackList[ip]
    print '\n'

def daemons(daemonStats):
    
    daemons = ["gargoyle_pscand","gargoyle_pscand_analysis","gargoyle_pscand_monitor","gargoyle_lscand_ssh_bruteforce"]
    print(R+"Daemon Information:"+W)
    running = ''.join(daemonStats["runningDaemons"])
    for daemon in daemons:
        if daemon in running:
            print(daemon+G+' - Running'+W)
        else:
            print(daemon+R+' - Not Running'+W)
    print '\n'
    print("Last Analysis Process - " + daemonStats["last_analysis"])
    print("Last Monitor Process - " + daemonStats["last_monitor"])
    print("Next Analysis Process - " + daemonStats["next_analysis"])
    print("Next Monitor Process - " + daemonStats["next_monitor"])
    
    print '\n'

def main():

    parser = argparse.ArgumentParser(description='Display Gargoyle Statistics.', prog="status.py")
    parser.add_argument('--blocked',  dest='blocked', action='store_const', const='blocked',
                   help='Display list of blocked ips, time they were blocked, and when they will be unblocked')
    parser.add_argument('--whitelist',  dest='whitelist', action='store_const', const='whitelist',
                   help='Display list of white listed ips')
    parser.add_argument('--blacklist',  dest='blacklist', action='store_const', const='blacklist',
                   help='Display list of black listed ips')
    parser.add_argument('--daemonstats', dest='daemons', action='store_const', const='daemons',
                   help='Activity of daemons(gargoyle_pscand, gargoyle_pscand_monitor, gargoyle_pscand_analysis, gargoyle_lscand_ssh_bruteforce')
    parser.add_argument('--all',  dest='all', action='store_const', const='all',
                   help='Display all statistics listed above')
    
    args = parser.parse_args()
    
    if args.all != None:
        showAll = True
    else:
        showAll = False
    daemonStats = daemon_stats()
    

    print (G+"\n******************** Gargoyle Statistics ********************\n"+W)
    print (G+daemonStats["Active"]+W + '\n')

    if os.getuid() != 0:
        print (R+"Program must be run as root user...exiting\n"+W)
        exit(1)

    if 'running' in daemonStats['Active']:
            
        
        try:
            db_loc = os.environ["GARGOYLE_DB"]
        except:
            print(R+'Error: '+W + er.message+ "\nPlease set an environment variable 'GARGOYLE_DB' to the correct database path.")
            exit(1)

        try:
            blockedIps = blocked_time()
            whiteList = get_current_white_list()
            blackList = get_current_black_list()
        except:
            print(R+"Are you sure you set your envinronment variable, GARGOYLE_DB, to the correct path?"+W)
   
        if args.blocked == None and args.whitelist == None and args.blacklist == None and args.daemons == None and args.all == None:
            showAll = True

        if showAll:
            blocked(blockedIps)
            whiteListed(whiteList)
            blackListed(blackList)
            daemons(daemonStats)
        else:
            if args.blocked != None:
                blocked(blockedIps)
            if args.whitelist != None:
                whiteListed(whiteList)
            if args.blacklist != None:
                blackListed(blackList)
            if args.daemons != None:
                daemons(daemonStats)

main()


