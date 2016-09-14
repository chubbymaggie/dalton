
#############################################
# Dario Ernst <nebuk@kanojo.de>
# Fabian Yamaguchi <fabs@recurity-labs.com>
#
# PortBunny's PythonInterface.
#############################################


import threading
import time
import os
import mutex
import sys, atexit

fini_mutex = threading.Semaphore(0)
deviceName = "/dev/portbunny"
moduleName = "portbunny"

# Constants to index portbunny-messages

MSG_MIN_FIELDS = 3

MSG_HOST_IP = 0
MSG_EVENT_CLASS = 1
MSG_TYPE = 2
MSG_TIMESTAMP = 3

# Result-messages

# PORT_RESULT-message

MSG_RES_P_PORT_NUM = 3
MSG_RES_P_PORT_STATE = 4
MSG_RES_P_NFIELDS = 5

# SCAN_JOB_CREATED-message

MSG_RES_CREATED_MODE = 3
MSG_RES_CREATED_NFIELDS = 4

# TRIGGER-message

MSG_RES_TRIGGER_METHOD = 3
MSG_RES_TRIGGER_ROUND = 4
MSG_RES_TRIGGER_NFIELDS = 5


def stopParserThread(parser):
        
    # Stopping parser
    
    parser.running = False  
    # Wait until the thread has cleaned up.    
    fini_mutex.acquire()    
        

class Trigger(object):
    def __init__(self, method, rnd):
        self.method = method
        self.rnd = rnd        


class TriggerJob(object):
    def __init__(self, target, scanner):
        self.scanner = scanner
        self.target = target
        self.triggers = []
        self.down = False
        self.got_arp_rsp = False

        self.created_mutex = threading.Semaphore(0)
        self.ended = False
        self.executed = False
        self.paused = False

        self.port_results = []


    def getTrigger(self, trigger):        
        self.triggers.append(trigger)

    def execute(self):
        if not self.ended:
            self.scanner.writeOut("execute_scanjob %s"%self.target)

    def pause(self):
        self.scanner.writeOut("pause_scanjob %s"%self.target)

    def appendToMethodList(self, method, round):
        self.scanner.writeOut("append_to_methods_list %s %s %s"%(
            self.target, method, round
            ))

    def clearMethodsList(self):
        self.scanner.writeOut("clear_methods_list %s"%self.target)

    def numTriggersWanted(self, num):
        self.scanner.writeOut("number_of_triggers_wanted %s %s"%(
            self.target, num
            ))

    def methodTimeout(self, seconds, nseconds):
        self.scanner.writeOut("set_method_timeout %s %s %s"%(
            self.target, seconds, nseconds
            ))
        

class PortList(object):
    def __init__(self, ports):
        self.ports = ports        
                    
    def getPorts(self, *args):
        for item in args:
            self.processPorts(item)

    def processPorts(self, port):       
        if type(port) == int:            
            self.ports.append(str(port))
        elif type(port)==str:            
            if '-' in port:
                frm = int(port.split('-')[0])
                to = int(port.split('-')[1])                
                
                for j in range(frm,to):
                    self.ports.append(str(j))
            else:               
                self.ports.append(port)

    def makeCommand(self, target):
        cmd = "set_ports_to_scan %s"%(target)
        for port in self.ports:            
            cmd = cmd + " " + str(port)
                
        return cmd


class FloodJob(object):
    def __init__(self, target, scanner, portlist):
        self.scanner = scanner
        self.target = target
        self.results = {}
        self.portlist = portlist

        self.created_mutex = threading.Semaphore(0)
        self.ended = False
        self.executed = False
        self.paused = False
        
        self.rate_limiter_reported = False

    def init2(self, triggers=None):
        
        # Sleep until the job has been created.
        self.created_mutex.acquire()
        
        self.updatePorts()
        
        if triggers:            
            self.clearTrigggerList()
            for trigger in triggers:
                self.appendTrigger(trigger)


    def getResult(self, port, result):                        
        self.results[port] = result

    def execute(self):
        if not self.ended:
            self.scanner.writeOut("execute_scanjob %s"%self.target)

    def pause(self):
        self.scanner.writeOut("pause_scanjob %s"%self.target)

    def remove(self):
        self.scanner.writeOut( "remove_scanjob %s"%self.target )

    def appendTrigger(self, trigger):        
        # print "using trigger " + trigger.method + " " + trigger.rnd + " on " + self.target
        self.scanner.writeOut("append_to_trigger_list %s %s %s"%(
                              self.target, trigger.method, trigger.rnd
                              ))
        
    def clearTrigggerList(self):
        self.scanner.writeOut("clear_trigger_list %s"%self.target)

    def setReportEvents(self, boolean_val):
        self.scanner.writeOut("set_report_events %s %s"%(self.target, boolean_val))

    def setTimingAlgo(self, timing_algo):
        self.scanner.writeOut("set_timing_algorithm %s %s"%(self.target, timing_algo))

    def updatePorts(self):        
        self.scanner.writeOut(self.portlist.makeCommand(self.target))

class Scanner(object):

    def __init__(self, create_log):

        # Load kernel-module.
        
        module_loaded = os.path.exists(deviceName)
        if not module_loaded:
            ret = os.system('modprobe ' + moduleName)
        
            if ret:
                print "Error probing module."
                sys.exit(1)    

        # Wait for /dev/portbunny to exist.
        
        while not os.path.exists(deviceName):
            pass

        self.parser = Parser(self, create_log)
        self.triggerJobs = {}
        self.floodJobs = {}
        self.finished_job_queue = []                
        self.finished_job_mutex = threading.Semaphore(0)
        self.outFile = open(deviceName, "w",0)
        self.lock = threading.Semaphore(1)

        if not self.outFile:    
            print "Can't open /dev/portbunny."
            sys.exit(1)
                
        if module_loaded:
            # flush device to start off with a clean
            # state if module was already loaded.
            self.writeOut("flush_device_file")
            

        self.parser.start()        


    def __del__(self):
        if 'parser' in self.__dict__:
            self.parser.running = False


    def lock_object(self):
        self.lock.acquire()
    
    def unlock_object(self):
        self.lock.release()

    """
    Allow the user of the Scanner-Object
    to ask for finished jobs.

    Returns NULL if no job has finished
    and (TARGET_IP, MODE) if a job has finished.
    
    """
    
    def poll_for_finished_jobs(self):
        
        # Sleep until a new finished job or
        # error is available.
        
        self.finished_job_mutex.acquire()
        
        if self.parser.error:
            return ('ERROR', 'ERROR')
        
        if self.finished_job_queue == []:
             return None
        
        return self.finished_job_queue.pop()
               

    def createTriggerJob(self, target):
        
        tmp = TriggerJob(target, self)
        self.lock_object()
        self.triggerJobs[target] = tmp
        self.unlock_object()
        self.writeOut( "create_scanjob %s TRIGGER"%target )
        

        return tmp

    def removeTriggerJob(self, job):
        self.writeOut( "remove_scanjob %s"%(job.target) )
        self.triggerJobs.pop(job.target)

    def createFloodJob(self, target, portlist, trigger=None):

        ##############################################
        # Tell the scanner-module to create a flood-job
        # and call init2 on our local representation
        # of the scan-job.
        # init2 will wait until the scanner-module has
        # reported that the flood-job was created.       
        ##############################################

        new_job = FloodJob(target, self, portlist)
        self.lock_object()
        self.floodJobs[target] = new_job        
        self.writeOut( "create_scanjob %s FLOOD"%target )
        
        new_job.init2(trigger)        
        self.unlock_object()
        return new_job


    def writeOut(self, command):                
        self.outFile.write(command+"\n")
        self.outFile.flush()
        

    def free_scanjob(self, target, mode):
        
        self.lock_object()
        if mode == 'FLOOD':
            del self.floodJobs[target]
        elif mode == 'TRIGGER':
            del self.triggerJobs[target]
        self.unlock_object()


    def is_trigger_job_up(self, target):
        return not self.triggerJobs[target].down



class Parser(threading.Thread):
    def __init__(self, scanner, create_log):
        threading.Thread.__init__(self)
        self.scanner = scanner
        self.inFile = open(deviceName, "r")
        self.running = False
        self.error = False
        self.dont_read = False        

        # The parser may optionally keep a log-file
        # of all events which is created for debugging-purposes
                
        if create_log:
            try:
                self.log_file = open('./scan_log.txt', 'w')
            except:
                self.log_file = None
                print "Error creating log-file, scanning anyway."

        else:
            self.log_file = None


    def run(self):
        self.running = True
        while self.running:    

            if self.dont_read:
                time.sleep(0.001)                
                continue
            
            line = self.inFile.readline()
            line = line[:-1]
            
            self.parseData(line)            
            

        # Done. Close the file-handles to
        # /dev/portbunny, remove the
        # device-file and module and release
        # the fini-mutex so that the main-thread
        # can exit.
        
        self.inFile.close()
        self.scanner.outFile.close()
        if self.log_file:
            self.log_file.close()

        
        # Unload the module.
        
        os.system('rmmod ' + moduleName)

        fini_mutex.release()
    
        
    def parseData(self, line):
        
            # A message reported from the kernel-module
            # always has the format "$HOST $EVENT_CLASS $TYPE"
        
 
            args = line.split(' ')
            nargs = len(args)
            
            target = args[MSG_HOST_IP]
            
            if target == 'ERROR':
                print "ERROR:\n%s"%args
                # On error, shutdown portbunny immediately.
                self.dont_read = True
                self.error = True
                self.scanner.finished_job_mutex.release()
                return



            if nargs < MSG_MIN_FIELDS:                
                print "WARNING: invalid message: " + line                
                return
            
            
            msg_event_class = args[MSG_EVENT_CLASS]
            msg_type = args[MSG_TYPE]
            
            
            # First handle results.
                        
            # R is short for 'RESULT'
            # Saying 'R' instead of 'RESULT'
            # decreases load on /dev/portbunny
            # drastically.


            if msg_event_class[0] == 'R':
                
                # PORT_STATE has been moved to the
                # top because it is the most frequent
                # event.
                # P is short for 'PORT_STATE'. See
                # remark about 'R' above.

                if msg_type[0] == 'P':
                    if nargs < MSG_RES_P_NFIELDS:                        
                        print "WARNING: invalid message" + line
                        return
                    
                    port = args[MSG_RES_P_PORT_NUM]
                    result = args[MSG_RES_P_PORT_STATE]
                    
                    # Convert result into human-readable format

                    if result == 'F':
                        result = 'FILTERED'
                    elif result == 'C':
                        result = 'CLOSED'
                    else:
                        result = 'OPEN'


                    if not self.scanner.floodJobs.has_key(target):
                        # Trigger-state may also report port-states
                        self.scanner.triggerJobs[target].port_results.append([port, result])
                        return
                    
                    # Only overwrite non-filtered fields

                    register = True
                    if self.scanner.floodJobs[target].results.has_key(port):
                        if self.scanner.floodJobs[target].results == 'FILTERED':
                            register = True
                        elif self.scanner.floodJobs[target].results == 'CLOSED' and result != 'OPEN':                            
                            register = False
                        # also, don't register the result if this port is already
                        # known to be open.
                        elif self.scanner.floodJobs[target].results == 'OPEN':
                            register = False

                    if register:
                        self.scanner.floodJobs[ target ].getResult(port, result)
                    

                    if self.log_file:
                        self.log_file.write(line + "\n")
                    
            
                elif msg_type == "SCAN_JOB_CREATED":
                    
                    if nargs < MSG_RES_CREATED_NFIELDS:
                        print "WARNING: Received invalid message from portbunny"
                        return

                    mode = args[MSG_RES_CREATED_MODE]
                    if mode == "TRIGGER":
                        self.scanner.triggerJobs[target].created_mutex.release()
                    elif mode == "FLOOD":
                        self.scanner.floodJobs[target].created_mutex.release()
                    
                elif msg_type == "SCAN_JOB_EXECUTED":                    
                    
                    if self.scanner.triggerJobs.has_key(target):
                                            
                        if self.scanner.triggerJobs[target].paused:
                            self.scanner.triggerJobs[target].paused = False
                        else:
                            self.scanner.triggerJobs[target].executed = True
                    elif self.scanner.floodJobs.has_key(target):
                        if self.scanner.floodJobs[target].paused:
                            self.scanner.floodJobs[target].paused = False
                        else:
                            self.scanner.floodJobs[target].executed = True
                    
                elif msg_type == "SCAN_JOB_PAUSED":
                                        
                    if self.scanner.triggerJobs.has_key(target):
                        self.scanner.triggerJobs[target].paused = True
                    elif self.scanner.floodJobs.has_key(target):
                        self.scanner.floodJobs[target].paused = True
                    
                elif msg_type == "SCAN_JOB_REMOVED":
                    
                    mode = 'TRIGGER'
                    
                    if self.scanner.triggerJobs.has_key(target):                                                
                        self.scanner.triggerJobs[target].ended = True

                        if self.scanner.triggerJobs[target].triggers == []:
                            if not self.scanner.triggerJobs[target].got_arp_rsp:
                                self.scanner.triggerJobs[target].down = True                        
                        else:
                            self.scanner.triggerJobs[target].down = False

                    elif self.scanner.floodJobs.has_key(target):
                        mode = 'FLOOD'
                        self.scanner.floodJobs[target].ended = True                           

                    # Don't read until the UI has decided whether to terminate
                    # or not.
                    self.dont_read = True
                    self.scanner.finished_job_queue.append((target, mode))                    
                    self.scanner.finished_job_mutex.release()
                    
                    


                elif msg_type == "TRIGGER":
                    
                    if nargs < MSG_RES_TRIGGER_NFIELDS:
                        print "WARNING: Received invalid message from portbunny"
                        return

                    method = args[MSG_RES_TRIGGER_METHOD]
                    rnd = args[MSG_RES_TRIGGER_ROUND]
                    trigger = Trigger(method, rnd)
                    self.scanner.triggerJobs[ target ].getTrigger(trigger)
                
                elif msg_type == "UP":
                    
                    if self.scanner.triggerJobs.has_key(target):
                        self.scanner.triggerJobs[target].got_arp_rsp = True
                    
                else:
                    pass

 
            # Write info-messages to file
               
            elif msg_event_class[0] == "I":                       
                if self.log_file:
                    self.log_file.write(line + "\n")

                if msg_type == 'RATE_LIMITER':
                    
                    if self.scanner.floodJobs[target].rate_limiter_reported == False:
                        print "[Experimental detection code has identified a rate-limiter]"
                        self.scanner.floodJobs[target].rate_limiter_reported = True  
                                
                
            else:
                print "WARNING: parsed something unknown:\n%s"%args

