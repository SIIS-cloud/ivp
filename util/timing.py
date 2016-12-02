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






import atexit
import time
import numpy
import sys

disable = False

def timecall(fn=None, immediate=False, timer=time.time):
    """Wrap `fn` and print its execution time.

    Example::

        @timecall
        def somefunc(x, y):
            time.sleep(x * y)

        somefunc(2, 3)

    will print the time taken by somefunc on every call.  If you want just
    a summary at program termination, use

        @timecall(immediate=False)

    You can also choose a timing method other than the default ``time.time()``,
    e.g.:

        @timecall(timer=time.clock)

    """
    if fn is None: # @timecall() syntax -- we are a decorator maker
        def decorator(fn):
            return timecall(fn, immediate=immediate, timer=timer)
        return decorator
    # @timecall syntax -- we are a decorator.
    fp = FuncTimer(fn, immediate=immediate, timer=timer)
    # We cannot return fp or fp.__call__ directly as that would break method
    # definitions, instead we need to return a plain function.
    def new_fn(*args, **kw):
        return fp(*args, **kw)
    new_fn.__doc__ = fn.__doc__
    new_fn.__name__ = fn.__name__
    new_fn.__dict__ = fn.__dict__
    new_fn.__module__ = fn.__module__
    return new_fn


class FuncTimer(object):

    def __init__(self, fn, immediate, timer):
        self.fn = fn
        self.sample = []
        self.immediate = immediate
        self.timer = timer
        if not immediate:
            atexit.register(self.atexit)

    def __call__(self, *args, **kw):
        """Profile a singe call to the function."""
        fn = self.fn
        timer = self.timer
        try:
            start = timer()
            return fn(*args, **kw)
        finally:
            duration = timer() - start
            self.sample += [duration]
            if self.immediate and not disable:
                funcname = fn.__name__
                filename = fn.func_code.co_filename
                lineno = fn.func_code.co_firstlineno
                print >> sys.stderr, "\n  %s (%s:%s):\n    %.6f seconds\n" % (
                                        funcname, filename, lineno, duration)
    def atexit(self):
        if not len(self.sample) or disable:
            return
        funcname = self.fn.__name__
        filename = self.fn.func_code.co_filename
        lineno = self.fn.func_code.co_firstlineno
        print ("\n  %s (%s:%s) [time in ms]:\n"
               "    n: %d calls\t mean: %.6f\t std: %.6f\n"
               "    min: %.6f\t max: %.6f\n" % (
                funcname, filename, lineno, len(self.sample), 
                1000*numpy.mean(self.sample), 1000*numpy.std(self.sample), 
                1000*min(self.sample), 1000*max(self.sample)))
