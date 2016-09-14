#!/usr/bin/python

# Adds a scan-job to portbunny

import re
import sys

deviceName = '/dev/portbunny'

SCRIPT_ARG = 0
HOST_ARG = 1
PORT_ARG = 2
TRIGGERS_ARG = 3
NARGS = 4

# Regular expression to parse IP

IP_EXPRESSION_REGEX = '^([\d]{1,3}\.){3}[\d]{1,3}(/[\d]{1,2})*$'
ip_regex = re.compile(IP_EXPRESSION_REGEX)


def usage():
    print "portbunny_add_job <host_ip> <ports> <TRIGGER>"
    print "<host_ip>: IP-address. NO HOSTNAMES or CIDR"
    print "<ports>  : Port-expressions: a-b or a,b,c or just a"
    sys.exit(1)


# Make sure all expressions handed to
# the -p flag are actually port-expressions.
# The module also validates this but let's
# be nice and filter totally bogus input
# at this point already.
#
# Returns list of port-expressions.

def validate_port_expr(port_expr):
    
    retval = []
    rargs = port_expr.split(',')
    
    port_ex_regex = re.compile('^(\d+)(-(\d+))*$')
    
    while rargs:
        arg = rargs[0]
        
        # Validate that arg is indeed a port-expression
        if not port_ex_regex.match(arg):
            print "invalid port-expression: " + arg
            sys.exit(1)
        
        retval.append(arg)
        
        del rargs[0]

    return retval

"""
Validates trigger-expression and returns
a list of tuples of the form [$TRIGGER_NAME, $TRIGGER_ROUND].
"""

def validate_trigger_expr(trigger_expr):
    retval = []
    rargs = trigger_expr.split(',')
    
    trigger_ex_regex = re.compile('^(.*?)-(\d+)$')
    
    while rargs:
        arg = rargs[0]
        
        # Validate that arg is indeed a port-expression
        match = trigger_ex_regex.match(arg) 
        if not match:
            print "invalid trigger-expression: " + arg
            sys.exit(1)
        
        retval.append([match.group(1), match.group(2)])
        
        del rargs[0]

    return retval


def writeOut(outFile, command):
    outFile.write(command + "\n")
    outFile.flush()


############### MAIN #####################

if len(sys.argv) != NARGS:
    usage()

if not ip_regex.match(sys.argv[HOST_ARG]):
    print "Error: Argument 1 is not an IP!"
    sys.exit(1)

port_list = validate_port_expr(sys.argv[PORT_ARG])
trigger_list = validate_trigger_expr(sys.argv[TRIGGERS_ARG])

outFile = open(deviceName, "w", 0)

# Interact with scanner

writeOut(outFile, "create_scanjob %s FLOOD" % sys.argv[HOST_ARG])
for p in port_list:
    writeOut(outFile, "set_ports_to_scan %s %s" % (sys.argv[HOST_ARG], p))
writeOut(outFile, "clear_trigger_list %s" % sys.argv[HOST_ARG])
for t in trigger_list:
    writeOut(outFile, "append_to_trigger_list %s %s %s" % (sys.argv[HOST_ARG], t[0], t[1]))

# writeOut(outFile, "set_report_events %s 1" % sys.argv[HOST_ARG])

writeOut(outFile, "execute_scanjob %s" % sys.argv[HOST_ARG])

outFile.close()
