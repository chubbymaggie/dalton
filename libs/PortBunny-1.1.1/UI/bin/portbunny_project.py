#!/usr/bin/python

import os
import atexit
import time
import sys
import re

####################################
# PortBunny_Project <NAME> <NETWORK>
#
# PortBunny_Project will perform
# the following actions:
#
# If the directory <NAME> does not exist in the
# current working directory, a portbunny discovery
# (portbunny -d) is performed on the given <NETWORK>.
# PortBunny_Project will then create a $CWD/<NAME>
# and the subdirectories 'scheduled', 'finished'
# and 'complete'. The list of discovered hosts and
# triggers will be saved in <NAME>/hosts.
#
# All hosts in <NAME>/hosts will then be scheduled,
# which is done by creating a file for each host
# in <NAME>/scheduled.

portRange = '1-65535'
NHOSTS_AT_ONCE = 20;

deviceName = "/dev/portbunny"
moduleName = "portbunny"

SCHEDULED_DIR = 'scheduled'
INCOMPLETE_DIR = 'incomplete'
FINISHED_DIR = 'finished'

ip_re = re.compile("\d+\.\d+\.\d+\.\d+")

def fini(aborted):
    os.system("killall portbunny")
    print "closing /dev/portbunny"
    dev_portbunny.close()

    if aborted:
        print 'aborted, unloading module to reset state.'
        # remove module
        os.system('rmmod ' + moduleName)


# Fill scheduled-dir with all hosts
# listed in input-file, which are
# not in the finished-directory.

def parse_host_file():
    
    if not os.path.exists('hosts'):
        print 'Error: no hosts-file'
        return
    
    fh = open('hosts', 'r')
    
    for line in fh:
        if not ip_re.search(line):
            continue
        
        elems = line.split(' ')
        
        if len(elems) != 3:
            print 'Skipping line: ' + line
            continue

        HOST = elems[0]
        TRIGGER_NAME = elems[1]
        TRIGGER_ROUND = elems[2]
         
        # Don't add hosts we already have result-files for
        if os.path.exists(FINISHED_DIR + '/' + HOST + '.csv'):
            print "Not adding job " + HOST + " because it's in finished dir"
            continue
        
        # Create host-file in SCHEDULED_DIR
        
        print "Scheduling " + HOST
        
        new_host_file = open(SCHEDULED_DIR + '/' + HOST, 'w')
        new_host_file.write(TRIGGER_NAME + " " + TRIGGER_ROUND + "\n")
        new_host_file.close()
        

def schedule_new_job():
    hosts = os.listdir(SCHEDULED_DIR)

    if len(hosts) == 0:
        # print "No more jobs to add"
        return False

    hostname = hosts[0]

    fh = open(SCHEDULED_DIR + '/' + hostname, 'r')
    line = fh.readline()
    elems = line.split(' ')
    
    if len(elems) != 2:
        print "Warning: Invalid input line in schedule_new_job"
        sys.exit

    TRIGGER_NAME = elems[0]
    TRIGGER_ROUND = elems[1]

    fh.close()

    os.system('portbunny_add_job.py ' + hostname + ' ' + portRange + ' ' + TRIGGER_NAME + '-' + TRIGGER_ROUND)
    os.system('rm ' + SCHEDULED_DIR + '/' + hostname)
    return True
    

############# MAIN ##############################

# Make sure that user is root, we have been given the
# correct number of argyments and the portbunny
# kernel-module has been loaded.

if os.getuid() != 0:
    print "You are not root. PortBunny_Project wont do anything."
    sys.exit(1)
    
if len(sys.argv) != 3:
    print "usage: " + sys.argv[0] + " <project_name> <network>"
    print "<project_name>: name of the directory to store project in."
    print "<network>: network to scan in CIDR-notation"
    sys.exit(1)

projectName = sys.argv[1]
network = sys.argv[2]

# (1) Check if project already exists:

if not os.path.exists(projectName):
    print 'Creating project ' + projectName

    # Create project-directory and its
    # subdirectories and change into it.

    os.system('mkdir ' + projectName)
    os.chdir(projectName)
    os.system('mkdir ' + SCHEDULED_DIR)
    os.system('mkdir ' + INCOMPLETE_DIR)
    os.system('mkdir ' + FINISHED_DIR)

    # os.system('echo flush_device_file > ' + deviceName)
    
    print 'Performing portbunny discovery for ' + network
    print "(Please don't interrupt discovery)"

    os.system('portbunny -d ' + network + ' | tee hosts')
    
else:
    print 'Project Already exists, resuming ' + projectName
    os.chdir(projectName)

# Cleanup 'incomplete-dir'
os.system('rm -f incomplete/*')

# sys.exit(1)

# Check if module is loaded
if not os.path.exists(deviceName):
    
    print 'reloading module'
    ret = os.system('modprobe ' + moduleName)
    if ret:
        print 'Error probing module'
        sys.exit(1)
    
    time.sleep(0.5)


parse_host_file()

# Add initial scan-jobs

nhosts_running = 0;
hosts_left = True

while hosts_left and nhosts_running < NHOSTS_AT_ONCE:
    hosts_left = schedule_new_job()
    if hosts_left:
        nhosts_running = nhosts_running + 1
        

#############################
# Read from device-file
#############################

time.sleep(1)

dev_portbunny = open(deviceName, "r")

atexit.register(fini, True)

result_fh_dict = dict()
info_fh_dict = dict()
dont_read = False

print 'Now reading from device-file'

while 1:
         
    if not hosts_left and nhosts_running == 0:
        sys.exit() 

    line = dev_portbunny.readline() 
    line = line[:-1]
    
    elems = line.split(' ')
    if len(elems) < 3:
        # print "Warning: " + line
        continue

    HOST = elems[0]
    CLASS = elems[1]
    TYPE = elems[2]

    # Handle 'results'

    if CLASS == 'R':

        if not result_fh_dict.has_key(HOST):
            # create a new file-handle for this host
            print "Creating result-file for " + HOST
            result_fh_dict[HOST] = open(INCOMPLETE_DIR + '/' + HOST + ".csv", 'w+')                
        
        # Encode results in numbers so that they can be read
        # by bitchy spreadsheet and eng. tools.

        if TYPE == 'P':
            if elems[4] == 'C':
                elems[4] = '0'
            elif elems[4] == 'F':
                elems[4] = '1'
            else:
                elems[4] = '2'
            result_fh_dict[HOST].write(elems[3] + ' '+ elems[4] +"\n")       

        if TYPE == 'SCAN_JOB_REMOVED':
                
            if result_fh_dict.has_key(HOST):                    
                result_fh_dict[HOST].close()
            if info_fh_dict.has_key(HOST):                    
                info_fh_dict[HOST].close()


            # Move file to FINISHED_DIR
            print HOST + " finished, compressing and moving"
            
            os.system('portbunny_compress.py ' + INCOMPLETE_DIR + '/' + HOST + ".csv >" + FINISHED_DIR + "/" + HOST + ".csv")                
            os.system('rm ' + INCOMPLETE_DIR + '/' + HOST + '.csv')

            nhosts_running = nhosts_running - 1  
                
            hosts_left = schedule_new_job()

            if hosts_left:
                nhosts_running = nhosts_running + 1
            # print nhosts_running            
