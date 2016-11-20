# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import time
import logging
import platform

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)

class KTRACE(Auxiliary):
    """ktrace catch all syscall."""
    priority = -5 # low prio to wrap tightly around the analysis

    def __init__(self):
        self.config = Config(cfg="analysis.conf")
        self.fallback_strace = False

    def start(self):
        pid = os.getpid()
        log.info(">>>>>>>>>> ktrace start: %d <<<<<<<<<<",pid)
        f = open("/proc/self/cmdline","rb")
        t = f.read()
        f.close()
        log.info("current run [%s]", t)
        return True

    def get_pids(self):
        return []

    def stop(self):
        klog = "/var/log/kern.log"
        if os.path.exists(klog):
            # now upload the logfile
            log.info("Guest send kernel log -> Host")
            nf = NetlogFile("logs/kern.log")
            fd = open(klog, "rb")
            for chunk in fd:
                nf.sock.sendall(chunk) # dirty direct send, no reconnecting
            fd.close()
            nf.close()
        log.info(">>>>>>>>>> ktrace stop  %d <<<<<<<<<<",os.getpid())

