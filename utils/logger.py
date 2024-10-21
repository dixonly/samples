#/usr/bin/env python3
import sys
from datetime import datetime

class Logger():
    def __init__(self, filename):
        try:
            self.fp = open(filename, "a")
        except Excdeption as e:
            print("Error in opening log file: %s - %s" %(filename, e))
            exit()
        self.ERROR="ERROR"
        self.WARN="WARNING"
        self.INFO="INFO"

    def info(self, msg):
        self.log(level=self.INFO, msg=msg)
    def warn(self, msg):
        self.log(level=self.WARN, msg=msg)
    def error(self, msg):
        self.log(level=self.ERROR, msg=msg)
        
    def log(self, level, msg):
        try:
            self.fp.write("%s %s - %s\n" %(datetime.now(), level, msg))
        except Exception as e:
            print("Failure to write log entry to file - %s" %e)
            exit()
            
        if level == self.ERROR:
            sys.stderr.write("Error encountered, exiting.  Check log file for more info\n")
            self.fp.close()
            exit()
        
