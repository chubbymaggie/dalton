
#!/usr/bin/python

import re
import sys
import os

ETC_SERVICES = '../share/portbunny/services'
if not os.path.exists(ETC_SERVICES):
    ETC_SERVICES = '/usr/local/share/portbunny/services'


"""
PortBunny 'service-file' keeper

"""
class PBunnyServices:

    """
    Initialize PBunnyServices-Object using ETC_SERVICES
    
    """
    def __init__(self):

        self.service_names = dict()

        # Read in services-file
        
        fd = open(ETC_SERVICES)

        if not fd:
            print "ERROR: Could not open services-file";
            sys.exit(1)

        try:
            for line in fd:

                # Parse services-line
                match = re.compile("^(.+?)(\s+)?([0-9]+?)/tcp(.*)$").match(line)
                if not match:
                    continue
                
                # Add entry to the service-array.                
                name = match.group(1)
                port = int(match.group(3))                    
                self.service_names[port] = name   
                
                
        finally:
            fd.close()            



    """
    Return dictionary of services which
    maps ports to service-names.
    
    """

    def get_services_dict(self):
        return self.service_names
    

    """
    Return a list of all ports known by this
    PBunnyServices-Object
    
    """

    def get_port_list(self):

        retval = []

        for port in self.service_names.keys():
            retval.append(port)

        retval.sort()

        return retval;

    
    """
    add a service if a service at this port
    is unknown as of now.
    
    """

    def add_service(self, port, name):
        if self.service_names[port]:
            return 
        
        self.service_names[port] = name

