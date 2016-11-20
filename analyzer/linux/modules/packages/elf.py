# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# shenjunwei@
import os
import stat
import sys

from lib.common.abstracts import Package

class ELF(Package):
    """python analysis package for linux."""
    def start(self, path):
        os.chmod(path, stat.S_IXUSR)
        return self.execute([path])
