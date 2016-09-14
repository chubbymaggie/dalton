#!/usr/bin/python

###################################################
#
# Recurity Labs PortBunny -
# command-line-interface
#
#  Fabian Yamaguchi <fabs@recurity-labs.com>
###################################################

PBUNNY_VERSION = "1.1.1"


PBUNNY_SHARE = '../share/portbunny/'
PBUNNY_SHARE2 = '/usr/local/share/portbunny/'

import sys
import time
import os
import tty
from select import select

if not PBUNNY_SHARE in sys.path:
    sys.path.append(PBUNNY_SHARE)

if not PBUNNY_SHARE2 in sys.path:
    sys.path.append(PBUNNY_SHARE2)

from interface import *
from PBunnyServices import *
from PBunnyOptionParser import *
from UserEventHandler import UserEventHandler
from UILogic import UILogic

def main():        
   
    print "Starting PortBunny " + PBUNNY_VERSION

    # This is not a security-check.
    # The modprobing, device-creation etc.
    # will simply not work if you are not
    # root.
    
    if os.getuid() != 0:
        print "Error: PortBunny refuses to obey: You are not root."
        sys.exit(1)

    # Create PBunnyOptionParser which will
    # parse the command line when constructed.

    services = PBunnyServices().get_services_dict()    
    options_parser = PBunnyOptionParser(services)
    
    try:
        scanner = Scanner(options_parser.options.log)
    
    except IOError:
       print "I/O Error."
       sys.exit(1)
         
    # Create UserEventHandler
    user_event_handler = UserEventHandler(scanner, options_parser)

    # Start the UI-Logic
    ui_logic = UILogic(scanner, options_parser, services, user_event_handler)
    ui_logic.start()

    # Wait until the UI-logic has been initialized before allowing
    # any user-interaction.
    ui_logic.initialized_sem.acquire()

    # Start UserEventHandler
    user_event_handler.run()     


if __name__ == "__main__":
    main()

