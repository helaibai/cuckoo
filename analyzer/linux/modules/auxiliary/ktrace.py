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
klog = "/var/log/kern.log"

class KTRACE(Auxiliary):
    """ktrace catch all syscall."""
    priority = -5 # low prio to wrap tightly around the analysis

    def __init__(self):
        self.config = Config(cfg="analysis.conf")
        self.fallback_strace = False

    def start(self):
        pid = os.getpid()
        log.info(">>>>>>>>>> ktrace start: %d <<<<<<<<<<",pid)
        f = open(klog, "rw+")
        f.truncate()
        f.close()
        return True

    def get_pids(self):
        return []

    def stop(self):
        if os.path.exists(klog):
            # now upload the logfile
            log.info("Guest send kernel log -> Host")
            nf = NetlogFile("logs/kern.log")
            fd = open(klog, "rb")
            for chunk in fd:
                nf.sock.sendall(chunk)
            fd.close()
            nf.close()
        log.info(">>>>>>>>>> ktrace stop  %d <<<<<<<<<<",os.getpid())

