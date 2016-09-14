
####################################################################
# Modified by J.A.E Habraken <j.a.e.habraken@student.tue.nl>
# to make use of ipcalc found at
# https://labs.tehmaze.com/code/assorted/file/9b89d9343d5c/projects/
# instead of ipv4.py
#####################################################################

#!/usr/bin/python

import re
import sys
import socket
from optparse import OptionParser
from ipcalc import *
from PBunnyServices import *
import threading

"""
PortBunny Option-Parser
=======================

Parses the command-line.

The dictionary of options and the list
of hosts to scan can then be retrieved
using get_options_dict and
get_hosts_to_scan respectively.

"""

IP_EXPRESSION_REGEX = '^([\d]{1,3}\.){3}[\d]{1,3}(/[\d]{1,2})*$'
HOSTNAME_REGEX      = '^(([a-zA-Z0-9\-\.]+)+[a-z]+[\.]*$)'

ip_re = re.compile(IP_EXPRESSION_REGEX)
hostname_re = re.compile(HOSTNAME_REGEX)


# Default list of triggers:
# First check for TCP-SYN-triggers.
# After that, check TCP-ACK-triggers and then
# ICMP, followed by UDP and IP_PROT-triggers


DEFAULT_TRIGGERS_TO_TEST = [['TCP_SYN', '80'], ['TCP_SYN', '25'],
                            ['TCP_SYN', '22'], ['TCP_SYN', '443'],
                            ['TCP_SYN', '21'], ['TCP_SYN', '113'],
                            ['TCP_SYN', '23'], ['TCP_SYN', '53'],
                            ['TCP_SYN', '554'], ['TCP_SYN', '3389'],
                            ['TCP_SYN', '445'],                              
                            ['TCP_ACK', '80'], ['TCP_ACK', '65535'],
                            ['ICMP_ER', '0'],
                            ['ICMP_TS', '0'], ['UDP', '161'],
                            ['IP_PROT', '51']
                            ]

DEFAULT_NTRIGGER_JOBS_AT_ONCE = 40
DEFAULT_NFLOOD_JOBS_AT_ONCE = 20


class PBunnyOptionParser:

    ################### PUBLIC METHODS #########################


    """
    Create a PBunnyOptionParser by parsing
    the current command-line.
    
    """

    def __init__(self, services):        

        parser = OptionParser("")

        self.services = services
        
        parser.add_option("-p", "--ports", nargs = 1,
                          action = "callback", dest = "port_ranges",
                          default = self.get_default_ports_to_scan(),
                          callback = self.ports_option_parser,
                          help = "comma-seperated list of ports to scan.")    

        parser.add_option('-d', '--discover', action="store_true",
                          dest = 'only_discover', default = False,
                          help = "Don't perform the actual scan. Only 'discover' hosts by sending triggers.")
       
         
        
        parser.add_option("-t", '--triggers-to-test',
                          action = "callback", dest = "triggers_to_test",
                          default = DEFAULT_TRIGGERS_TO_TEST,
                          callback = self.triggers_to_test_parser,
                          help = "only the specified triggers will be tested. " +
                          "For example, '-t ICMP_ER-0,TCP_SYN-80' will only try an ICMP-ECHO-REQUEST " +
                          "and a TCP-SYN-packet on port 80. The README contains a complete list of all " +
                          "available triggers."
                          )

        parser.add_option('-l', '--log', action="store_true",
                          dest = 'log', default = False,
                          help = "Creates a scan-log which can help debug problems.")

        
        parser.add_option('-w', '--wait-longer', action="store_true",
                          dest = 'wait_longer', default = False,
                          help = "Wait longer for triggers to return in the trigger-phase.")
        
        parser.add_option('-a', '--set-timing-algo', action="store",
                          type = "string", dest="timing_algo")
        

        (self.options, self.hosts) = parser.parse_args()            
        
        # self.hosts now contains the hosts to scan
        # validate these 'host-expressions' and
        # construct the final list of hosts.
        
        self.parse_host_expressions()
        
        # Initialize defaults for number of jobs at once
        self.options.ntrigger_jobs_at_once = DEFAULT_NTRIGGER_JOBS_AT_ONCE
        self.options.nflood_jobs_at_once = DEFAULT_NFLOOD_JOBS_AT_ONCE
       
        self.lock = threading.Semaphore(1)
        

    """
    returns the default-list of ports:
    well-known ports + all ports in the
    'services'-file
    """

    def get_default_ports_to_scan(self):
        retval = ['1-1024']

        ser = self.services.keys()
        ser.sort()

        for s in ser:
            if s > 1024:
                retval.append(str(s))
        
        return retval
    

    """
    Return list of hosts to scan:
        
    """

    def get_hosts_to_scan(self):
        return self.hosts
                            

    """
    Return dictionary of options.
    """
    
    def get_options_dict(self):
        return self.options


    """
    Generate a list of single ports
    from the given port-expressions
    and save it in self.options.ports_to_scan
    and its length in
    self.options.nports_to_scan_per_job
    
    """

    def gen_list_of_single_ports(self):
        retval = []

        for port_exp in self.options.port_ranges:

            # Since ports have been validated at construction,
            # this check is fine.
            
            match = re.compile('^([0-9]+)-([0-9]+)$').match(port_exp)
            
            if not match:
                retval.append(port_exp)
                continue

            start_num = match.group(1)
            end_num = match.group(2)

            for i in range(int(start_num), int(end_num) + 1):
                retval.append(i)
            
        self.options.nports_to_scan_per_job = len(retval)
        self.options.ports_to_scan = retval
    
    
    def get_triggers_to_test(self):
        return self.options.triggers_to_test
    

    def lock_object(self):
        self.lock.acquire()

    def unlock_object(self):
        self.lock.release()
    
  
    ############### PRIVATE METHODS ###################

    
    def usage(self):        
        print "portbunny <host1> [host2] ... [hostn] [options]"    
        print "by default all well known ports are scanned."    


    """
    (1) Validates all host-expressions contained in
    self.hosts

    (2) Resolves hostnames

    (3) Breaks down subnets given in CIDR-notation
    into single hosts.

    (4) Saves the result in self.hosts

    """

    def parse_host_expressions(self):

        if self.hosts == []:
            print "Please tell the bunny what to scan."            
            sys.exit(1)
        
        final_host_list = []
                
        for host in self.hosts:

            ip_match   = ip_re.match(host)
            host_match = hostname_re.match(host)
            
            
            if not ( ip_match or host_match ):
                print "Invalid host-expression: " + host
                sys.exit(1)                
                

            # If this expression is a hostname, resolve it.

            if host_match:   
                try:
                    host = socket.gethostbyname(host)                    
                except socket.gaierror:
                    print "Error: Cannot resolve " + host
                    sys.exit(1)   
                    
                final_host_list.append(host)
            # Handle IP-ranges
            elif host.find('/') != -1 :

                try:
                    # Create list of hosts from CIDR-expression
                    # and interate through each element of the
                    # list.

		    host_list = [str(h) for h in Network(host)]
		    if host.split('/')[-1] not in ['31', '32'] :
                        host_list = host_list[1:-1]
                   
		    final_host_list += host_list
                except ValueError:

                    print "Error while parsing: " + host
                    sys.exit(1)
            else:
                final_host_list.append(host)
	        
       
        self.hosts = final_host_list
        

    """
    Handle arguments to -p which is a comma-seperated list of
    single-ports and port-ranges and make them available as
    self.options.port_ranges.
    
    """
    def ports_option_parser(self, option, opt_str, value, parser):
        assert value is None
        done = 0
        value = []
        
        if len(parser.rargs) == 0:
            print "-p requires an argument"
            sys.exit(1)
        
        rargs = parser.rargs[0].split(',')
        port_ex_regex = re.compile('^(\d+)(-(\d+))*$')

        while rargs:
            arg = rargs[0]

            # Validate that arg is indeed a port-expression
            if not port_ex_regex.match(arg):
                print "invalid port-expression: " + arg
                sys.exit(1)

            value.append(arg)
            del rargs[0]

        setattr(parser.values, option.dest, value)      
        del parser.rargs[0]


    """
    Parse 'triggers_to_test' which will be accepted
    in the form 'TRIGGER_NAME1-ROUND1,TRIGGER_NAME2-ROUND2 ...'    
    
    TODO: We're using a regexp here which is SLOW. Optimize this.
    
    """

    def triggers_to_test_parser(self, option, opt_str, value, parser):
        assert value is None
        done = 0
        value = []
        rargs = parser.rargs[0].split(',')
        trigger_ex_regex = re.compile('^(.*?)-(\d+)$')
        

        while rargs:
            arg = rargs[0]

            # Validate that arg is indeed a trigger
            match = trigger_ex_regex.match(arg) 
            if not match:
                print "invalid trigger-expression: " + arg
                sys.exit(1)
            
            value.append([match.group(1), match.group(2)])
            del rargs[0]

        setattr(parser.values, option.dest, value)
        del parser.rargs[0]

