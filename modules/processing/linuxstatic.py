import os
import re
import subprocess
import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)

class ELF(object):
    """ ELF analysis """
    def __init__(self, file_path):
        self.file_path = file_path
    def __get_relocations(self):
        """Gets relocations.
        @return: relocations dict or None.
        """
        relocs = []
        
        process = subprocess.Popen(["/usr/bin/objdump",self.file_path, "-R"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # take output
        dump_result = process.communicate()[0]
        # format output
        dump_result = re.split("\n[ ]{0,}", dump_result)
        
        for i in range(0,len(dump_result)):
            if re.search("00", dump_result[i]):
                relocs.append(filter(None, re.split("\s", dump_result[i])))
        
        return relocs
    
    def _get_symbols(self):
        """Gets symbols.
        @return: symbols dict or None.
        """
        
        libs = []
        entry = []
        
        # dump dynamic symbols using 'objdump -T'
        process = subprocess.Popen(["/usr/bin/objdump",self.file_path, "-T"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        elf = process.communicate()[0]
        
        # Format to lines by splitting at '\n'
        elf = re.split("\n[ ]{0,}", elf)
            
        for i in range(0,len(elf)):
            if re.search("DF \*UND\*", elf[i]):
                entry.append(filter(None, re.split("\s", elf[i])))
        
        # extract library names
        lib_names = set()
        for e in entry:
            # check for existing library name
            if len(e) > 5:
                # add library to set
                lib_names.add(e[4])
        lib_names.add("None")
        
        # fetch relocation addresses
        relocs = self.__get_relocations()
        
        # find all symbols for each lib
        for lib in lib_names:
            symbols = []
            for e in entry:
                if lib == e[4]:
                    symbol = {}
                    symbol["address"] = "0x{0}".format(e[0])
                    symbol["name"] = e[5]
                    
                    # fetch the address from relocation sections if possible
                    for r in relocs:
                        if symbol["name"] in r:
                            symbol["address"] = "0x{0}".format(r[0])
                    symbols.append(symbol)
                
            if symbols:
                symbol_section = {}
                symbol_section["lib"] = lib
                symbol_section["symbols"] = symbols
                libs.append(symbol_section)
                
        return libs
            
    def _get_sections(self):
        """Gets sections.
        @return: sections dict or None.
        """

        sections = []
        entry = []
        
        process = subprocess.Popen(["/usr/bin/readelf", self.file_path, "-s", "--wide"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        elf = process.communicate()[0]
        
        # Format to lines by splitting at '\n'
        tmp = re.split("\n[ ]{0,}", elf)
        for i in range(0,len(tmp)):
            # Filter lines containing [xx]
            if re.search("^\[[ 0-9][1-9]\]", tmp[i]):
                # Regex: Split all whitespaces '\s' if they are not proceeded '(?<!\[)' by a '['
                # remove all splitted whitespaces from the list filter()'
                entry.append(filter(None, re.split("(?<!\[)\s", tmp[i])))
                
        for e in entry:
            try:
                section = {}
                section["name"] = e[1]
                section["type"] = e[2]
                section["virtual_address"] = "0x{0}".format(e[3])
                section["virtual_size"] = "0x{0}".format(e[4])
                sections.append(section)
                
            except:
                continue
            
        return sections
        
    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        results = {}
        results["elf_sections"] = self._get_sections()
        results["elf_symbols"] = self._get_symbols()
        return results

class Linuxstatic(Processing):
    def run(self):
        """Run linux static"""
        self.key = "linuxstatic"
        static = {}
        log.debug("Run into linux static")
        if "ELF" in File(self.file_path).get_type():
            static.update(ELF(self.file_path).run())
        #print static
        log.debug("Leave off linux static")
        return static
