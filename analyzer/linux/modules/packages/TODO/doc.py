# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# shenjunwei@

from lib.common.abstracts import Package

class DOC(Package):
    """Word analysis package for linux."""
    def start(self, path):
        return self.execute(["/usr/bin/libreoffice", "--writer", path])
