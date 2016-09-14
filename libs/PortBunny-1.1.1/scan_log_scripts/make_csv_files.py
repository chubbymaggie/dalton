#!/usr/bin/python

import sys

# Utility script, which generates CSV-files
# containing the most commonly used scan-information.

HOST_FIELD = 0
EVENT_CLASS_FIELD = 1
EVENT_TYPE_FIELD  = 2
TIMESTAMP_FIELD   = 3

CUR_CWND_FIELD    =   4
CUR_CCTHRESH_FIELD =  5
RTT_AVERAGE_FIELD  =  6
RTT_DEVIATION_FIELD = 7
LATEST_RTT_FIELD    = 8

NFIELDS_MINIMUM = 9

# Open CSV-files to be generated

f_cwnd = open('./cwnd_ccthresh_timestamp.csv', 'w')
f_rtt = open('./rtt_timestamp.csv', 'w')

"""
Generates a CSV-file containing the
fields specified by 'field_indices'
selected from the array 'fields' and
writes it to the file 'file_obj'

"""

def csv_file_write_line(fields, field_indices, file_obj):  
    
    flength = len(fields)
    first_round = True

    for f in field_indices:
        if f >= flength:
            continue
        
        if first_round:
            first_round = False
        else:
            file_obj.write(',')

        file_obj.write(fields[f])

    # Terminate line    
    file_obj.write("\n")


############## MAIN ##########################

while 1:
    # Read one line at a time until EOF is reached
    line = sys.stdin.readline()
    if line == '':
        break;
    
    if line[-1] == "\n":
        line = line[0:-1]    

    # Cut out the specified fields
    fields = line.split(' ')
    
    # Skip lines, which don't contain enough fields
    if len(fields) < NFIELDS_MINIMUM:
        print fields
        continue
    
    # Skip RESULT-messages
    if fields[EVENT_CLASS_FIELD] == 'R':
        continue 
    
    # Now generate the CSV-files for, which can then be used
    # by other tools.
    
    csv_file_write_line(fields,
                        [TIMESTAMP_FIELD, LATEST_RTT_FIELD, RTT_AVERAGE_FIELD, RTT_DEVIATION_FIELD],
                        f_rtt)
    
    csv_file_write_line(fields, [TIMESTAMP_FIELD, CUR_CWND_FIELD, CUR_CCTHRESH_FIELD], f_cwnd)
    
f_cwnd.close()
f_rtt.close()
