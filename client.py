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






#!/usr/bin/env python
from xmlrpclib import ServerProxy

def pxy():
	return  ServerProxy('http://localhost:9001')

c = pxy()
ctab = {}
ctab['start'] = c.start
ctab['stop'] = c.stop
ctab['force_stop'] = c.force_stop
ctab['status'] = c.status
ctab['detach'] = c.detach

if __name__ == "__main__":
	import sys

	usage =  "client [start|stop|force_stop|status|detach] [domain]"


	if len(sys.argv) < 3:
		print	usage
		exit()

	dom = sys.argv[2].strip()
	cmd = ctab.get(sys.argv[1], None)
	if cmd is None:
		print usage
	else:
		print cmd(dom)
	exit()
