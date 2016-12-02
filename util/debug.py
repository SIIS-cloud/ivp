# The Integrity Verification Proxy (IVP) additions are ...
#
#  Copyright (c) 2012 The Pennsylvania State University
#  Systems and Internet Infrastructure Security Laboratory
#
# they were developed by:
# 
#  Joshua Schiffman <jschiffm@cse.psu.edu>
#  Hayawardh Vijayakumar <huv101@cse.psu.edu>
#  Trent Jaeger <tjaeger@cse.psu.edu>
#
# Unless otherwise noted, all code additions are ...
#
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  * http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.






"""
GDB Interaction Module

Filename:    gdb.py
Author:      Joshua Schiffman <jschiffm@cse.psu.edu>
            
Description: Module to send and receive output from gdb.

"""
import select
from subprocess import *
from util.timing import timecall
from threading import Lock
from time import *
import sys
import os
#from timer import getticks

class Dbg():
    """ GDB Interactive Terminal Wrapper """
    
    proc = None
    marker_fd = None
    
    def __init__(self, args='-q'):
        """ Spawns a new GDB process with @args """
        
        self.proc = Popen("gdb " + args, shell=True, stdin=PIPE, stdout=PIPE)
        self.poll = select.poll()
        self.poll.register(self.proc.stdout, select.POLLIN)
	self.marker_fd = open('/sys/kernel/debug/tracing/trace_marker', 'w')
        
    def readline(self):
        """ 
        Reads a line from gdb.  
        This is blocking.
        """
        self.poll.poll()
	self.marker_fd.write('gdb-marker')
	try:
		self.marker_fd.flush()
	except IOError:
		pass
#        t = float(getticks())
#        print "Poll: %f" % time()
#        print "Poll: " + t/ 3473848105.59
        line = self.proc.stdout.readline().rstrip()
        #print "read value is ---",line
        return line

    def feed(self,n):
        """ Clears @n lines from stdout """
        
        res = []
        for x in range(n):
            res += [self.proc.stdout.readline().rstrip()]
        #print "return value is --",res 
        return res
    
    def cmd(self, c, newline=True, feed=0):
        """ 
        Sends a command to GDB and returns after @feed number of getlines.
        Useful for clearing stdout if you know how many lines you expect.
        """
        if newline:
            c+='\n' 

        self.proc.stdin.write(c)

        res = []        
        for x in range(feed):
            res += [self.proc.stdout.readline()]

        return res

    def interrupt(self):
	"""
	Sends SIGINT so the domain is paused and gdb gets control. 
	We can issue gdb commands then. 
	"""
	os.kill(self.proc.pid, signal.SIGINT)
	
