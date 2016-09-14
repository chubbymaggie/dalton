#!/usr/bin/python

import sys
import re

deviceName = '/dev/portbunny'

SCRIPT_ARG = 0
HOST_ARG = 1
NARGS = 2

# Regular expression to parse IP

IP_EXPRESSION_REGEX = '^([\d]{1,3}\.){3}[\d]{1,3}(/[\d]{1,2})*$'
ip_regex = re.compile(IP_EXPRESSION_REGEX)

def usage():
    print "portbunny_pause_job <host_ip>"
    sys.exit(1)
    

############### MAIN #####################

if len(sys.argv) != NARGS:
    usage()

if not ip_regex.match(sys.argv[HOST_ARG]):
    print "Error: Argument 1 is not an IP!"
    sys.exit(1)

outFile = open(deviceName, "w", 0)

def writeOut(outFile, command):
    outFile.write(command + "\n")
    outFile.flush()

writeOut(outFile, "execute_scanjob %s" % sys.argv[HOST_ARG])
