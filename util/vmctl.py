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
VM Control Server

Filename:    vmctl.py
Author:      Joshua Schiffman <jschiffm@cse.psu.edu>
            
Description: Defines an XMLRPC server to manage VMs and attach its integrity 
             monitor.

"""
from SimpleXMLRPCServer import SimpleXMLRPCServer
from util.monitor import Monitor
import libvirt
from util.netproxy import Proxy

class VMServer(SimpleXMLRPCServer):
        """ VM Management Server
        
        Accepts XML-RPC requests to start and stop VMs.  
        Also register's criteria in the VM's integrity monitor.
        """
        
        kvm = None
        monitors = {}
        ip_to_dom = {}
                    
        def __init__(self, cfg):
            self.cfg = cfg
            host = cfg.get("VMServer","host")
            port = cfg.getint("VMServer","port")

            self.kvm=libvirt.open("qemu:///system")
            if self.kvm is None:
                print "No hypervisor found!"
                exit()

            self.pxy = Proxy(cfg.get('VMServer','netproxy'))
                
            SimpleXMLRPCServer.__init__(self, (host, port))
    
        def _dispatch(self, method, params):
            try:
                # We are forcing the 'export_' prefix on methods that are
                # callable through XML-RPC to prevent potential security
                # problems
                func = getattr(self, 'export_' + method)
            except AttributeError:
                raise Exception('method "%s" is not supported' % method)
            else:
                return func(*params)
    
        def export_disconnect(self, src_ip, dom_ip):
            """ Unregisters a client's criteria for a connection. 
            """
            
            monitor = self.ip_to_dom.get(dom_ip, None)
            if monitor is None:
                # No Domain is running.
                return False
            
            if monitor.state != "Domain running.":
                return False
                
            return monitor.unregister(src_ip)

        
        def export_connect(self, src_ip, dom_ip):
            """ Registers a client's criteria for a connection. 
            
            This registers the client's criteria in the domain's monitor.  
            Returns True if the criteria is satisfied and False otherwise.
            """
            
            monitor = self.ip_to_dom.get(dom_ip, None)
            if monitor is None:
                # No Domain is running.
                return False
            
            if monitor.state != "Domain running.":
                return False
                
            return monitor.register(src_ip)
            
    
        def export_start(self, domain):
            """ Start a VM Monitor """
            
            # Check if its managed
            if domain in self.monitors.keys():
                return domain + " is already active."
            try:
                dom = self.kvm.lookupByName(domain)
            except libvirt.libvirtError as e:
                return e.get_error_message()

            # Check if its running unmanaged
            if dom.isActive():
                return domain + " is running unmanaged."

            # Setup our Domain's monitor object
            self.monitors[domain] = Monitor(self.cfg, dom, self.pxy)
            
            # Set IP lookup table
            ip = self.cfg.get("Domains",domain).split()[0]
            self.ip_to_dom[ip] = self.monitors[domain]
            
            return domain + " is starting."

        def export_stop(self, domain):
            """ Stop a VM Monitor """
            
            mon = self.monitors.get(domain,None)
            if mon is None:
                try:
                    dom = self.kvm.lookupByName(domain)
                except libvirt.libvirtError as e:
                    return e.get_error_message()

                if dom.isActive():
                    return domain + " is running unmanaged."
                else:
                    return domain + " is not running."
            else:
                if mon.destroy():
                    # clean up time.
                    self.monitors.pop(domain)
                    return domain + " destroyed."
                else:
                    # This really should not happen.
                    return "An error occured."

        def export_force_stop(self, domain):
            """ Forcibly stop a VM even if unmanaged """
            
            mon = self.monitors.get(domain,None)
            if mon is None:
                try:
                    dom = self.kvm.lookupByName(domain)
                except libvirt.libvirtError as e:
                    return e.get_error_message()
                if dom.isActive():
                    dom.destroy()
                    return domain + " destroyed."
                else:
                    return domain + " is not running."
            else:
                if mon.destroy():
                    self.monitors.pop(domain)
                    return domain + " destroyed."
                else:
                    return "An error occured."

        def export_detach(self,domain):
            mon = self.monitors.get(domain,None)
            if mon is None:
                try:
                    dom = self.kvm.lookupByName(domain)
                except libvirt.libvirtError as e:
                    return e.get_error_message()

	    mon.detach()
	    self.monitors.pop(mon)
	    return "GDB detached from VM"
        
        def export_status(self,domain):
            mon = self.monitors.get(domain,None)
            if mon is None:
                try:
                    dom = self.kvm.lookupByName(domain)
                except libvirt.libvirtError as e:
                    return e.get_error_message()

                if dom.isActive():
                    return domain + " is running unmanaged."
                else:
                    return domain + " is not running."

            return mon.status()
