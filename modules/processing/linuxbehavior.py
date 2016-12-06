import os
import re
import logging

from lib.cuckoo.common.abstracts import Processing, BehaviorHandler
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

#class processtree(object):
#    def __init__(self):
#
#    def run(self):
#        results = {}
#        return results
#class summary(object):
#    def __init__(self):
#        self.actions = ["file_opened", "file_written", "file_read", "file_deleted", "file_exists", "file_failed"]
#    def run(self):
#        results = {}
#        return results
#
class Processes(object):
    def __init__(self, root):
        self.root_path = root
    def run(self):
        results = [] 
        process = {}
        process["process_path"] = "12345"
        process["calls"] = [{"category":"system","status":1,"stacktrace":[],"api":"sys_open","return_value":0,"arguments":{"path":"/etc/profile", "mode":0x00}, "time":14712312321321, "tid":123, "flags":{}}]
        process["track"] = False
        process["pid"] = 123
        process["process_name"] = "1234"
        process["command_line"] = "ls -l"
        process["modules"] = [{"basename":"Baby","imgsize":9527,"baseaddr":0x12345678,"filepath":"/bin/ls"}] 
        process["time"] = 20
        process["tid"] = 1
        process["ppid"] = 1
        process["type"] = "process"
        results.append(process)
        return results

class Apistats(object):
    def __init__(self, logs):
        self.ktrace_path = os.path.join(logs, "ktrace.log")
    def run(self):
        results = {}
        if not os.path.exists(self.ktrace_path):
            return results 
        ktrace = open(self.ktrace_path)
        lines = ktrace.readlines()
        for l in lines:
            start = l.find('[KTRACE]')
            if start == -1:
                continue
            kstring = l[start:]
            items = kstring.split(':')
            pid = items[1]
            api = items[3].split('(')[0]

            if not results.has_key(pid):
                results[pid] = {}
                results[pid][api] = 1
            else:
                if results[pid].has_key(api):
                    results[pid][api] += 1
                else:
                    results[pid][api] = 1
        ktrace.close()
        return results

class LinuxBehaviorAnalysis(Processing):

    key = "linuxbehavior"

    def run(self):
        self.cfg = Config()
        self.state = {}
        behavior = {}
        behavior["apistats"] = Apistats(self.logs_path).run() 
        behavior["processes"] = Processes(self.analysis_path).run()
        return behavior
