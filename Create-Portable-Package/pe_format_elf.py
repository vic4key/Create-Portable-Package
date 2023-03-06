from .pe_format import PEPackage

import os
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
import PyVutils as vu

class ELFPackage(PEPackage):
  ''' PE ELF Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)
    try:
      self.m_file = ELFFile(open(self.m_file_path, "rb"))
      if self.m_file is None: raise RuntimeError("Could not load the ELF file.")
    except Exception as e: print(str(e))

  def _find_shared_libraries(self, object, recursive) -> map:
    shared_libraries = {}

    for section in object.iter_sections():
      if not isinstance(section, DynamicSection):
        continue
      if section.num_tags() > 0:
        for tag in section.iter_tags():
          if tag.entry.d_tag == "DT_NEEDED":
            shared_library = self._find_shared_library(tag.needed) 
            shared_libraries[tag.needed] = shared_library

    if recursive:
      recursive_shared_libraries = {}
      for e in shared_libraries.values():
        file_path = os.path.join(e["file_dir"], e["file_name"])
        object = ELFFile(open(file_path, 'rb'))
        l = self._find_shared_libraries(object, recursive)
        recursive_shared_libraries.update(l)
      shared_libraries.update(recursive_shared_libraries)

    return shared_libraries
