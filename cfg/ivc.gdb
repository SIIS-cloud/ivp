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






# PRIMA Module functions

define print_sha1
set $i=0
while $i<20
    printf "%02x", (u8 *) $arg0[$i++]
    end
printf "\n"
end
document print_sha1
Prints a hexdump of a 20 byte sha1sum at location $arg0
end

define last_hash
set $a =  ((struct ima_queue_entry*) ((char*) (((struct ima_queue_entry*) ((char*) &ima_measurements - (char*) 0x10)).later->prev) - (char*) 0x10)).entry.template.digest
set $i=0
while $i < 20 
    printf "%02x", $a[$i++]
    end
printf "\n"
end
document last_hash
Returns the SHA1 Hash of the last measurement.
end

define xlast_hash
set $a =  ((struct ima_queue_entry*) ((char*) (((struct ima_queue_entry*) ((char*) &ima_measurements - (char*) 0x10)).later->prev) - (char*) 0x10)).entry.template.digest
x/5wx $a
end
document xlast_hash
Returns the SHA1 Hash of the last measurement.
end

define print_mlist
set $length = ima_htable.len.counter
printf "%d\n", $length
set $a = ((struct ima_queue_entry*) ((char*) &ima_measurements - (char*) 0x10)).later

set $n=0

while $n < ($length) 
    set $a = $a.next    
    set $b = ((struct ima_queue_entry*)(char*)((char*)$a - (char*) 0x10)).entry.template.digest
    print_sha1 $b
    set $n = $n + 1
    end
end
document print_mlist
Returns the length followed by the measurement list
end


define get_lim_len
printf "%d\n", ima_htable.len.counter
end
document get_lim_len
Returns length of the LIM measurement list
end

# Hash Module Functions
define get_selinux_enforcing
printf "%d\n", selinux_enforcing
end
document get_selinux_enforcing
Returns current value of selinux_enforcing
