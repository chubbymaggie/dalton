#!/usr/bin/python

import os
import re

#############################################
# Reads all csv-files generates by portbunny
# and performs an nmap service discovery on
# all open ports.
#############################################

a_re = re.compile('(.*?)\.csv')
hosts = os.listdir('./')
OPEN_PORT = '2'

for host in hosts:
    
    # Filter out any files not ending in '.csv'

    match = a_re.match(host)
    if not match:
        continue
    
    ports = []

    # open the csv-file and
    # append open ports to 'ports'
    
    f = open(host)
    
    for line in f:
        p = line.split()
        if p[1] == OPEN_PORT:
            ports.append(p[0])
    
    # Build string of ports seperated
    # by ',' to hand to nmap.
    port_str = ""
    for p in ports:
        port_str = port_str + p + ","
    
    
    if port_str == "":
        continue

    
    port_str = port_str[:-1]
    
    # Launch nmap
    
    cmd = "nmap -sV -P0" + match.group(1) + " -p " + port_str + " -oG services/" + host + "_services";
    os.system(cmd)
    cmd = "mv " + host + " services/"
    os.system(cmd)


