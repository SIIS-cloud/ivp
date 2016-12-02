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
VM Integrity Monitor

Filename:    monitor.py
Author:      Joshua Schiffman <jschiffm@cse.psu.edu>
            
Description: Integrity Monitor that measures the integrity of a VM.  This module
             defines the Monitor itself and its helper classes.  The Monitor
             uses introspection modules from the util.mods module.  One monitor
             object is spawned per VM.  

"""
import sys
import mods
import debug
import libvirt
import threading 
import pdb
from time import *
from util import mods
from lxml import etree
from subprocess import *
from util.debug import Dbg
from util.timing import timecall
from ConfigParser import ConfigParser


class Watcher(threading.Thread):
    """ Thread to watch for GDB output and dispatch to handle it. """
    
    watchpoints = {}
    
    def __init__ (self, cfg, tree, trigger, modules):
        self.cfg = cfg
        self.trigger = trigger
        self.modules = modules
        self.dbg = Dbg()
        
        kernel = tree.xpath('/domain/os/kernel/text()')[0]
        kernel += ".gdb"
        name = tree.xpath('/domain/name/text()')[0]
                
        self.port = cfg.get('Domains', name).split()[1]
        macros = cfg.get('Watcher', 'macros')
        
        # Load kernel symbols
        self.dbg.cmd('file %s' % (kernel), feed=1)

        # Load macros
        self.dbg.cmd('source %s' % (macros))
                
        threading.Thread.__init__(self)

    @timecall
    def handle(self, line):
        
        flag = False
	if "SIGINT" in line:
		self.dbg.cmd('detach')
		exit()

        # Find the module for the event
        # name = self.watchpoints[line]
        for wp,name in self.watchpoints.iteritems():
            if wp in line:
                flag = True
                break
            else:
                pass
        if not flag:
            return
        
        if self.modules[name].Callback(self.dbg):
            # Check the module against the criteria
            self.trigger(name)
        
        # Resume the VM
        self.dbg.cmd('continue',feed=1)


    def run(self):


        # Connect to the running VM.  This will halt it.
        self.dbg.cmd('target extended-remote 127.0.0.1:' + self.port, feed=3)

        # Each module registers watchpoints
        for (name, module) in self.modules.items():
            for watch in module.Initialize(self.dbg):
                self.watchpoints[watch] = name

        # Resume VM
        self.dbg.cmd('continue',feed=1)
        
        # The main loop
        while(True):
#            print "Done: %f" % time()
            self.handle(self.dbg.readline().strip())
    

class Monitor():
    """ Integrity Monitor for a VM
        
        The Monitor class contains a set of integrity modules that gather 
        measurements of the VM's integrity.  The life cycle of the
        integrity monitor is as follows:
        
        1) Pre-launch Static Measurement:
            The monitor first registers static modules, which perform their 
            init functions to measure any load time values.
        2) Launch VM
            The monitor starts the VM
        3) Initializes watcher thread
            The watcher thread is given a dispatch function to select the
            module callback function associated with the GDB watchpoint tripped
            by the VM.
        4) Init Dynamic Measurements:
            Registers the dynamic modules and sets up their watchpoints.
        5) Wait for VM terminate / pause / etc command
    """

    static = {}     # Static Module
    dynamic = {}    # Dynamic Modules
    clients = {}    # Criteria to client list
    criteria = {}   # Criteria file to criteria object
   
    def __init__ (self, cfg, dom, pxy):
        self.cfg = cfg
        self.dom = dom
        self.pxy = pxy
        self.state = "__init__"

        # Get some info about the domain
        self.tree = etree.ElementTree(etree.XML(self.dom.XMLDesc(0)))
        self.name = self.tree.xpath('/domain/name/text()')[0]
        self.ip = cfg.get('Domains', self.name).split()[0]
        
        # Asynchronously triggers the VM start function.  
        threading.Timer(0, self.start).start()

    def start(self):
        """ Start the VM """
        
        self.state = "Registering Static Modules"
        # 1) Register Static Modules
        for m in self.cfg.get('Monitor', 'static').split():
            module = getattr(mods, m)
            self.static[m] = module(self.cfg, self.dom)
            self.static[m].Initialize()
                    
        # 2) Launch VM
        self.dom.create()
        self.state = "Domain created.  Pausing for startup."
        
        # Wait for domain to load kernel into memory
        sleep(self.cfg.getint('Monitor', 'pause'))

        # Register dynamic modules
        for m in self.cfg.get('Monitor', 'dynamic').split():
            module = getattr(mods, m)
            self.dynamic[m] = module()

        # 3) Start watcher thread
        self.watcher = Watcher(self.cfg, self.tree, self.trigger, 
            self.dynamic)
        self.watcher.daemon = True  # Ensure it dies when we do.
        self.watcher.start()
        self.state = "Domain running."

    def destroy(self):
        """ Destroy the running VM """
        
        self.dom.destroy()

        # Kill lingering connections
        for key in self.clients:
            for ip in self.clients[key]:
                self.pxy.kill(ip, self.ip)
                
        return True

    def detach(self):
	""" Detach GDB from running VM """ 
	self.watcher.dbg.interrupt()

    @timecall
    def trigger(self, module):
        """ Checks all criteria against a dynamic module 
        
        This should be called as a callback by the watcher thread when an 
        event triggers a change in a dynamic module's state.
        """

        m = self.dynamic[module]
        for (key, crt) in self.criteria.items():
            if not m.Check(crt):
                # Need to kill all connections for that criteria
                for ip in self.clients.pop(key):
                    self.pxy.kill(ip, self.ip)
                self.criteria.pop(key)

    @timecall
    def check(self, crt):
        """ Checks a criteria against all modules """
        
        for (name, module) in self.static.items():
            if not module.Check(crt):
#                print name
                return False
        
        for (name, module) in self.dynamic.items():
            if not module.Check(crt):
#                print name
                return False
        
        return True
        
    @timecall
    def register(self,ip):
        """ Register client and returns whether criteria is satisfied. """

        crt_file = self.cfg.get("Clients",ip)

        # Lookup criteria file
        crt = self.criteria.get(crt_file,None)
        
        if crt is None:
            crt = ConfigParser()
            crt.read(crt_file)
        else:            
            # Add client since criteria is satisfied
            if ip not in self.clients[crt_file]:
                self.clients[crt_file] += [ip]
            return True
            
        if self.check(crt):
            # Add client to the satisfied criteria list.
            self.clients[crt_file] = [ip]

            # Add running criteria
            self.criteria[crt_file] = crt
            
            # success
            return True
        else:
            return False

    def unregister(self,ip):
        """ Unregister client. """

        crt_file = self.cfg.get("Clients",ip)

        if self.clients.get(crt_file,None) is None:
            return False
            
        if ip not in self.clients[crt_file]:
            return False

        self.clients[crt_file].remove(ip)
        if len(self.clients[crt_file]) == 0:
            self.clients.pop(crt_file)
            self.criteria.pop(crt_file)
        return True
            

    def status(self):
        """ Dump status of monitor """
        
        return [self.state, self.clients.items(), self.static.keys(), self.dynamic.keys()]
