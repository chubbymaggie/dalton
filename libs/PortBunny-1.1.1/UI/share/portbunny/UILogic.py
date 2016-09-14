
import threading, atexit
from interface import PortList, stopParserThread
from UserEventHandler import stopUserEventHandler

def kill_ui_logic(ui_logic):
    # Up the finished-job-mutex so that the
    # UI-Logic wakes up.
    ui_logic.scanner.finished_job_mutex.release()


def lxor(a, b):
        return ((a and not(b)) or (not(a) and b))

class UILogic(threading.Thread):

    def __init__(self, scanner, options_parser, services, event_handler):
       
        threading.Thread.__init__(self)
 
        self.scanner = scanner
        self.options_parser = options_parser
        self.services = services
        self.event_handler = event_handler

        self.nactive_trigger_jobs = 0
        self.nactive_flood_jobs = 0
        self.pending_trigger_jobs = []
        self.pending_flood_jobs = []
        self.running = True
                        
        self.initialized_sem = threading.Semaphore(0)
        

        atexit.register(kill_ui_logic, self)
        

    """
    Adds intial trigger-jobs and then waits for
    jobs to complete and feeds the scanner new jobs.
    """

    def run(self):
         
        # (1) Create initial trigger-jobs.

        hosts_to_scan = self.options_parser.get_hosts_to_scan()
        self.options_parser.gen_list_of_single_ports()
        
        # we have now initialized
        self.initialized_sem.release()     
        
        if not self.options_parser.options.only_discover:
            print "+++ Will scan " + str(self.options_parser.options.nports_to_scan_per_job),
            print "ports on " + str(len(hosts_to_scan)) + " hosts. +++"

        # Each host we want to scan has to be triggered first
        self.pending_trigger_jobs = hosts_to_scan
        self.create_trigger_jobs()
        


        # (2) Wait for finished jobs
        
        while self.running:            
            

            target_mode_tuple = self.scanner.poll_for_finished_jobs()

            if not target_mode_tuple:
                # Empty tuples are returned when the logic
                # should terminate.                                
                return
                
                
            (target, mode) = target_mode_tuple

            # Handle errors
            if target == 'ERROR':
                print "scanner-module returned an error. Quitting."
                
                # Shut down the scanner
                stopParserThread(self.scanner.parser)
                stopUserEventHandler(self.event_handler)
                return
            
            
            """ Handle finished Jobs  """

            if mode == 'FLOOD':
                
                # A flood-job has finished: Output results,
                # delete the flood-jobs and execute the next
                # pending job

                self.output_flood_job_summary(target)
                self.scanner.free_scanjob(target, mode)
                
                self.nactive_flood_jobs = self.nactive_flood_jobs - 1                                
                
                # Submit a pending job
                if self.pending_flood_jobs != []:
                    self.scanner.parser.dont_read = False
                    self.create_flood_jobs()
                

            elif mode == 'TRIGGER':
                
                # A trigger-job has finished. Output results,
                # execute the next pending trigger-job.
                # If no more pending trigger-jobs exist,
                # start creating flood-jobs

                # self.output_trigger_job_summary(target)
                host_is_up = self.scanner.is_trigger_job_up(target) and self.scanner.triggerJobs[target].triggers != []
                
                self.nactive_trigger_jobs = self.nactive_trigger_jobs - 1
                
                if host_is_up and not self.options_parser.options.only_discover:
                    self.pending_flood_jobs.append(target)
    
                # Execute a pending trigger-job if there is one.
                if self.pending_trigger_jobs != []:
                    self.scanner.parser.dont_read = False
                    self.create_trigger_jobs()
                elif self.nactive_trigger_jobs == 0:  
                    
                    # No pending-trigger-jobs left, no active
                    # trigger-jobs left, execute flood-jobs
                    
                    banner_printed = False
                    nhosts = 0
                    
                    for trig_job in self.scanner.triggerJobs:
                        
                        if not banner_printed:
                            print "+++ Trigger-Phase done. The following hosts are up: +++"
                            banner_printed = True
                              

                        if self.scanner.triggerJobs[trig_job].triggers == []:
                            if self.scanner.triggerJobs[trig_job].got_arp_rsp:
                                print trig_job + " NO-TRIGGERS"
                                nhosts = nhosts + 1
                            continue
                        else:
                            trigger_job = self.scanner.triggerJobs[trig_job]
                            print trigger_job.target + " " + trigger_job.triggers[0].method + " " + trigger_job.triggers[0].rnd
                            nhosts = nhosts + 1
                    
                    if not banner_printed:
                        print "All hosts seem down."
                    else:
                        print str(nhosts) + " hosts total."

                    self.scanner.parser.dont_read = False
                    self.create_flood_jobs()
                    
            

            # No jobs left, exit.
            if self.nactive_trigger_jobs + self.nactive_flood_jobs == 0:
                print "All done"
                # Shut down the scanner
                stopUserEventHandler(self.event_handler)
                stopParserThread(self.scanner.parser)                
                return
            else:
                self.scanner.parser.dont_read = False


    
    """
    creates and executes trigger-jobs until
    ntrigger_jobs_at_once has been reached.
    """
    
    def create_trigger_jobs(self):
        
   
        scanner = self.scanner 
        options_parser = self.options_parser 
        ntrigger_jobs_at_once = options_parser.options.ntrigger_jobs_at_once
        

        while ntrigger_jobs_at_once > self.nactive_trigger_jobs:
            
            if self.pending_trigger_jobs == []:
                # No more pending jobs, exit.
                return

            # Create next pending trigger-job

            host = self.pending_trigger_jobs.pop(0)
        
            scanner.createTriggerJob(host)
        

            # And tell scanner which triggers to use
                 
            scanner.triggerJobs[host].clearMethodsList()
            
            if self.options_parser.options.wait_longer:
                scanner.triggerJobs[host].methodTimeout(1, 0)
            
            for (name, round) in options_parser.get_triggers_to_test():
                # print "trying trigger " + name + " "+ str(round) + " on " + host 
                
                # Handle one-round-triggers
                scanner.triggerJobs[host].appendToMethodList(name, round)   

            self.nactive_trigger_jobs = self.nactive_trigger_jobs + 1
            scanner.triggerJobs[host].execute()

    """
    create and execute flood-jobs until
    nflood_jobs_at_once has been reached.
    """

    def create_flood_jobs(self):
        
        nactive_flood_jobs = self.nactive_flood_jobs
        pending_flood_jobs = self.pending_flood_jobs
        scanner = self.scanner
        
        options_parser = self.options_parser
        nflood_jobs_at_once = options_parser.options.nflood_jobs_at_once

        while nflood_jobs_at_once > self.nactive_flood_jobs:
            
            if pending_flood_jobs == []:
                break

            target = pending_flood_jobs.pop(0)
            
            # create the flood-scan-job
            self.nactive_flood_jobs = self.nactive_flood_jobs + 1
            port_list = PortList(options_parser.options.port_ranges)
            
            trigs_arg = scanner.triggerJobs[target].triggers
           
            known_port_states = scanner.triggerJobs[target].port_results
            
            del scanner.triggerJobs[target]
            scanner.createFloodJob(target, port_list, trigs_arg)    

            if options_parser.options.log:
                # Report all events
                scanner.floodJobs[target].setReportEvents('1')
                
            if self.options_parser.options.timing_algo:
                scanner.floodJobs[target].setTimingAlgo(self.options_parser.options.timing_algo)
            
            # Set known results from trigger-state
            for res in known_port_states:
                scanner.floodJobs[target].results[res[0]] = res[1]
            
            scanner.floodJobs[target].execute()
    
    

    def output_trigger_job_summary(self, hostname):
        
        if self.scanner.triggerJobs[hostname].triggers != []:
            
        
            i = 0
            print "Best triggers for " + hostname + ": "
            print "===================================================="
            for trigger in self.scanner.triggerJobs[hostname].triggers:
                print trigger.method + " " + trigger.rnd + " ",
                i = i + 1
                if i == 3:
                    print ""
                    i = 0
            print "\n===================================================="
        elif self.scanner.triggerJobs[hostname].got_arp_rsp:
            print hostname + " is up but no triggers available."
        

    

    """
    nicely print results:

    Output all OPEN ports and either all
    CLOSED or all FILTERED ports depending
    on which of the two sets contains less
    elements.
    
    """

    def output_flood_job_summary(self, hostname):
        
        scanner = self.scanner
        services = self.services
        options_parser = self.options_parser
        results = scanner.floodJobs[hostname].results
        
        nports_to_scan_per_job = options_parser.options.nports_to_scan_per_job
                
        
        print "Results for " + hostname
        print "===================================================="        
        
        # Traverse the list once to count the number of filtered
        # ports and the number of closed ports so that these two
        # values can be compared to decide which of these are to
        # be listed in the output.
        
        nentries = {}        
        nentries['OPEN'] = 0
        nentries['CLOSED'] = 0
        nentries['FILTERED'] = 0

        ports_to_output = []

        for port in results.keys():                                                                    
            if results[port] != 'OPEN':                
                nentries[results[port]] = nentries[results[port]] + 1            
    
        output_filtered = nentries['FILTERED'] < nentries['CLOSED']
        
        dont_output_others = False
        if min(nentries['FILTERED'], nentries['CLOSED']) > 30:
            dont_output_others = True

        # Output all open ports and either all filtered or all closed
                                
        for port in results.keys():                                            
            if results[port] == 'OPEN' or ( not(lxor((results[port] == 'FILTERED'), output_filtered)) ):
                ports_to_output.append(port)
                

        # Sort only ports to output.

        ports_to_output.sort(lambda x, y: int(x) - int(y))
                        
        for port in ports_to_output:
            service_name = "UNKNOWN"
            if(int(port)) in services:
                service_name = services[int(port)]
            
            if(results[port] == 'OPEN'):
                print hostname + "\t" + port + "\t" + "OPEN\t" + "\t" + service_name
            else:
                if not dont_output_others:
                    if results[port] == 'CLOSED':
                        print hostname + "\t" + port + "\t" + results[port] + "\t\t" + service_name
                    else:
                        print hostname + "\t" + port + "\t" + results[port] + "\t\t" + service_name

        if dont_output_others:
            print "all other ports are CLOSED/FILTERED"

        elif output_filtered:
            print "all other ports are CLOSED."            
        else:
            print "all other ports are FILTERED"

        print str(nports_to_scan_per_job) + " ports scanned."
        print "===================================================="
