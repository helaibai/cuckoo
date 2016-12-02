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
from lib.common.results import upload_to_host 
from lib.core.config import Config

log = logging.getLogger(__name__)

class KTRACE(Auxiliary):
    """ktrace catch all syscall."""
    priority = -5 

    def __init__(self):
        self.config = Config(cfg="analysis.conf")
        self.fallback_strace = False
    def start(self):
        log.info("ktrace start() %d" % os.getpid())
        os.system("/bin/dmesg -c &>/dev/null")
        root_path = os.getcwd()
        bin_path = os.path.join(root_path,"bin")
        module_path = os.path.join(bin_path, "ktrace.ko")
        if os.path.exists(module_path):
            os.system("/sbin/insmod %s analyzer=%d" % (module_path,os.getpid()))
            log.info("insmod command execute")
        else:
            log.info("kernel module not there")
        log.info("analyzer path:%s" % module_path)
        log.info("ktrace start() return versin 0.01")
        return True

    def get_pids(self):
        return []

    def stop(self):
        log.info("ktrace stop() %d" % os.getpid())
        os.system("/sbin/rmmod ktrace")
        os.system("/bin/dmesg > /var/log/ktrace.log")
        upload_to_host("/var/log/ktrace.log","logs/ktrace.log")
        upload_to_host("/proc/version","files/version")
        upload_to_host("/proc/modules","files/modules")
