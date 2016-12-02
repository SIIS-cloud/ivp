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
Introspection Modules

Filename:    monitor.py
Author:      Joshua Schiffman <jschiffm@cse.psu.edu>
             Hayawardh Vijayakumar <huv101@cse.psu.edu>
            
Description: Introspection modules for the VM Integrity Monitor.

"""

import pickle
from debug import Dbg
from lxml import etree
from hashlib import sha1
from util.timing import timecall
from ConfigParser import ConfigParser


class Introspection_Module:
    """ Abstract module interface 
    
    Introspection modules for the Monitor class should subclass this interface.
    """ 
    
    name = "Abstract Introspection Module"
    kind = None # Either "Static" or "Dynamic"
    
    def Callback(self, event, dbg): 
        """ Introspection Callback function for the GDB Watcher 
        
        Callback is invoked by the Monitor's watcher thread when an 
        integrity-event occurs.  The callback should quickly assess whether the
        event is relevant to the module and do any additional work necessary.
        
        Returns True if state has changed (should call Check).
        """

        if kind != "Static" and kind != "Dynamic":
            raise Exception("Introspection Module must be either 'Static' or" 
            "'Dynamic'.")

        if kind == "Dynamic":
            raise NotImplementedError("Dynamic modules should implement"
                 "Callback.")
        return False

    def Initialize(self): 
        """ Called once when the module is initialized; used to perform
        module-specific actions e.g., register watchpoints. 
        
        Static modules will do most if not all work here."""

        raise NotImplementedError("Modules should implement Initialize.")

    def Check(self, criteria): 
        """ Called to re-evaluate client-specific conditions when 
        state changes or there is a new connection. Returns True if criteria
        is satisfied.
        
        """

        raise NotImplementedError("Modules should implement Check.")


class Hash(Introspection_Module):
    """ Load-Time Hash module 
    
    This module measures hashes of configuration specific files before the
    VM is started.
    """

    name = "Hash"
    kind = "Static"
    hashes = {}
    
    def __init__(self,cfg,dom):

        self.cfg = cfg
        self.dom = dom

    def Initialize(self):
        """ Gather hashes 
        
        This parses the VM's domain xml file for the necessary file paths.
        Provide an xpath query in the config file to obtain the path.
        """
        
        tree = etree.ElementTree(etree.XML(self.dom.XMLDesc(0)))

        for (k,v) in self.cfg.items(self.name):
            self.hashes[k]=sha1(open(tree.xpath(v)[0],'rb').read()).hexdigest()

    def Check(self, criteria):
        if not criteria.has_section(self.name):
            return True
            
        for (k,v) in criteria.items(self.name):
            if self.hashes.get(k, None) != v:
#                print k, v, self.hashes.get(k,"None")
                return False
        return True

class SELinux_Enforce(Introspection_Module):
    """ Run-time SELinux enforcing monitoring module """
    
    name = "SELinux_Enforce"
    kind = "Dynamic"
    watchpoint = "selinux_enforcing"
    
    @timecall
    def Callback(self, dbg):
        """ This will always return True """
        
        # clear the watchpoint info
        dbg.feed(5)
        if self.enforcing == '0':
            self.enforcing = '1'
        else:
            self.enforcing = '0'
        return True
        
    def Initialize(self, dbg):
        # Get current selinux state
        self.enforcing = dbg.cmd("get_selinux_enforcing", feed=1)[0][6:].strip()
        
        # Register watchpoint and return the value to the watcher
        return [dbg.cmd('watch ' + self.watchpoint, feed=1)[0][6:].strip()]
        
    def Check(self, criteria):
        if not criteria.has_section(self.name):
            return True

        enforcing = criteria.get(self.name,'enforcing')
        return enforcing == self.enforcing



class Prima(Introspection_Module):
    """ Run-time PRIMA measurement-list monitoring module """

    name = "Prima"
    kind = "dynamic"
    watchpoint = "ima_measurements->prev"
    
    # Measurement List
    mlist = set()
    sets = {}    

    def __init__(self):
        
        # Load criteria hash sets for fast lookup
        cfg = ConfigParser()
        cfg.read("cfg/hashes.cfg")

        for (k, v) in cfg.items("Sets"):
            self.sets[k] = pickle.load(open(v,'r'))
                
    @timecall
    def Callback(self, dbg):

        # clear the watchpoint info
        dbg.feed(5)

        # Get the most recent measurement
        feed = dbg.cmd('last_hash',feed=1)
        self.mlist.add(feed[0][6:].strip())
        #feed = dbg.cmd('xlast_hash',feed=2)
        #print "feed is",feed
        #h = "".join([w[2:] for w in feed[0][6:].strip()[1:]])
        #h += feed[1].split()[1][2:]
        #self.mlist.add(h)
        print "last added hash is---",feed[0][6:].strip()
        # Always return true
        return True 

    def Initialize(self, dbg):
        """ Gets the current measurement list and returns watchpoint trigger"""
                
        # Get the list of prima measurements into the measurement_list
        num = int(dbg.cmd("print_mlist", feed=1)[0][6:].strip())

        # Parse list
        for line in dbg.feed(num):
            self.mlist.add(line.strip())
        
        # Register watchpoint and return the value to the watcher
        return [dbg.cmd('watch ' + self.watchpoint, feed=1)[0][6:].strip()]

    @timecall
    def Check(self, criteria):

        if not criteria.has_section(self.name):
            return True
        # only looking for trusted sets now. 
        # TODO: add other set types
        trusted = set()
        trusted.add("0"*40)
        if criteria.has_option(self.name, 'trusted'):
            trusted.update(self.sets[criteria.get(self.name, 'trusted')])
        # Check if mlist is contained within the trusted set
#        print self.mlist.difference(trusted)
        if trusted.issuperset(self.mlist):
            return True
        else:
            return False
            
            
class Timing(Introspection_Module):
    """ Timing module """

    name = "Timing"
    kind = "dynamic"
    watchpoint = "printk_ratelimit_state.interval"
                    
    @timecall
    def Callback(self, dbg):

        # clear the watchpoint info
        dbg.feed(5)

        return True

    def Initialize(self, dbg):
        """ Gets the current measurement list and returns watchpoint trigger"""
                
        # Register watchpoint and return the value to the watcher
        return [dbg.cmd('watch ' + self.watchpoint, feed=1)[0][6:].strip()]

    def Check(self, criteria):
        print "timing triggered"
        return True
