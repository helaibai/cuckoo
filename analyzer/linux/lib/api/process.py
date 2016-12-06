# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import random 
import logging
import tempfile

from lib.common.execution import CuckooError
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

class Process:
    """Linux process."""
    first_process = True
    first_process_pid = None
    dumpmem = {}

    def __init__(self, pid=0):
        """@param pid: PID.
        """
        self.pid = pid
        self.process_name = "null"

    def is_alive(self):
        if not os.path.exists("/proc/%u" % self.pid): return False
        status = self.get_proc_status()
        if not status: return False
        if "zombie" in status.get("State:", ""): return False
        return True

    def get_parent_pid(self):
        return self.get_proc_status().get("PPid", None)

    def get_proc_status(self):
        try:
            status = open("/proc/%u/status" % self.pid).readlines()
            status_values = dict((i[0], i[1]) for i in [j.strip().split(None, 1) for j in status])
            return status_values
        except:
            log.critical("could not get process status for pid %u", self.pid)
        return {}
    def dump_memory(self):
        """ Dump process memory for linux
        """
        if not self.pid:
            log.warning("No vaild pid specified memory dump aborted")
            return False
        if not self.is_alive():
            log.warning("The process with pid %d not alive , memory dump aborted", self.pid)
            return False
        bin_path = os.path.join("bin", "procmem")
        dump_path = tempfile.mktemp()
        idx = self.dumpmem[self.pid] = self.dumpmem.get(self.pid, 0) + 1
        file_name = os.path.join("memory", "%s-%s.dmp" % (self.pid, idx))
        cmd = [bin_path, "--pid", self.pid, "--ouput", file_name]
        log.info("linux process dump memory ")
        try:
           procmem = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE) 
        except Exception: 
            log.error("Failed to dump process %s and process_name %s", self.pid, self.process_name)
        upload_to_host(dump_path, file_name)
        os.unlink(dump_path)
        log.info("Memory dump of process with pid %d completed", self.pid)
        return True

    def execute(self, cmd):
        self.proc = proc = subprocess.Popen(cmd)
        self.pid = proc.pid
        return True
