###########################################
# PortBunny user-event-handler
# Component of the UI which interacts with
# the user during the scan
###########################################

import threading
import sys, os
import tty, termios
import fcntl
from select import select
from interface import stopParserThread


def stopUserEventHandler(event_handler): 
    event_handler.running = False    
    os.write(event_handler.transmit, 'x')
    
    event_handler.fini_mutex.acquire()

class UserEventHandler:

    def __init__(self, scanner, options_parser):
        
        self.running = True
        self.scanner = scanner
        self.options_parser = options_parser
        self.fini_mutex = threading.Semaphore(0)
      
        # Create exit-pipe
        (self.receive, self.transmit) = os.pipe()
        
        # Set terminal to cbreak-mode
        fd = sys.stdin.fileno()
        self.old_settings = termios.tcgetattr(fd)
        tty.setcbreak(fd)
    

    def run(self):
        

        print "press h for help."
        try:
            while self.running: 
                (read_fds, write_fds, err_fds) = select([sys.stdin, self.receive], [], [])
            
                for rfd in read_fds:
                    if rfd == sys.stdin:
                        command = sys.stdin.read(1)                        
    
                        if command == 'h':
                            self.print_help()
                        elif command == 'l':
                            self.print_active_scan_jobs()
                        elif command == 'a':
                           self.abort_group()
                        elif command == '+':
                            self.increase_number_of_jobs()
                        elif command == '-':
                            self.decrease_number_of_jobs()
                        else:
                            self.print_progress_report()
                    else:
                        self.running = False
                        break          
        
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, self.old_settings)
            self.fini_mutex.release()

        except KeyboardInterrupt:
            print "keyboard-interrupt received, quitting"
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, self.old_settings)
            stopParserThread(self.scanner.parser)
            sys.exit(1)


    def print_progress_report(self):
        nports_to_scan_per_job = self.options_parser.options.nports_to_scan_per_job
        
    
        for job in self.scanner.floodJobs.keys():
            
            nports_scanned = len(self.scanner.floodJobs[job].results.keys())
            percent = (nports_scanned * 100) / nports_to_scan_per_job
            print str(job) + ": " + str(nports_scanned) + "/" + str(nports_to_scan_per_job) + " ports scanned (" + str(percent) + "%)"
            

    def print_help(self):
        print "h:\tview this help"
        print "l:\tlist active scan-jobs"
        print "a:\tabort group"
        print "+:\tincrease number of jobs at once for next group"
        print "-:\tdecrease number of jobs at once for next group"
        print "other:\tprogress-report"
        pass

    def print_active_scan_jobs(self):
        i = 0
        self.scanner.lock_object()
        keys = self.scanner.floodJobs.keys()
        keys.sort()
        for job in keys:
            print "(" + str(i) + ") " + str(job)
            i = i + 1
    
        self.scanner.unlock_object()

    def increase_number_of_jobs(self):
        
        old_jobs_at_once = self.options_parser.options.nflood_jobs_at_once
        self.options_parser.options.nflood_jobs_at_once = old_jobs_at_once + 1 

        print "number of jobs at once: " + str(self.options_parser.options.nflood_jobs_at_once)

    def decrease_number_of_jobs(self):
        
        old_jobs_at_once = self.options_parser.options.nflood_jobs_at_once
        
        if old_jobs_at_once == 1:
            
            print "number of jobs at once: " + str(self.options_parser.options.nflood_jobs_at_once)
            return

        self.options_parser.options.nflood_jobs_at_once = old_jobs_at_once - 1 
        
        print "number of jobs at once: " + str(self.options_parser.options.nflood_jobs_at_once)



    def abort_group(self):
        
        print "aborting group"

        self.scanner.lock_object()
        
        keys = self.scanner.floodJobs.keys()
        keys.sort()
        # Pause and remove all jobs
        for job in keys:
            self.scanner.floodJobs[job].pause()
            self.scanner.floodJobs[job].remove()

        self.scanner.unlock_object()

