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

Filename: ivc.py
Author:      Joshua Schiffman <jschiffm@cse.psu.edu>
            
Description: VM Integrity Monitor for Integrity Verified Channels (IVC) project.
             This server accepts connections from the IKE daemon to register
             client criteria and sends a accept / reject notice on registration
             if the conditions are met.  The server also flushes the client's
             integrity association (IA) when its conditions are violated.
             
             The monitor registers integrity monitoring modules that are 
             specified in its local configuration file "modules.cfg".  Modules
             subclass the Introspection_Module and have three functions: 
             Initialize, Callback, and Check.  The modules can be registered on
             two different hooks, HOOK_LOADPARAMS and           
             HOOK_WATCHPOINT_TRIGGER.  

"""

import subprocess
from util import *
from ConfigParser import ConfigParser
CONF_FILE = "cfg/monitor.cfg"


if __name__ == "__main__":

    cfg = ConfigParser()
    cfg.read(CONF_FILE)
    
    server = vmctl.VMServer(cfg)
    server.register_introspection_functions()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()