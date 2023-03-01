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
      self.m_object = ELFFile(open(self.m_file_path, "rb"))
      if self.m_object is None: raise ("Could not load the ELF file.")
      self.m_ready = True
    except Exception as e: print(str(e))

  def _find_shared_library(self, file_name: str) -> dict:
    assert self.m_ready, "the elf file is not loaded"

    if file_name in self.m_loaded_libraries.keys(): return self.m_loaded_libraries[file_name]

    # print(f"Walking: {file_name}")

    lines = []
    output = self._run_cli_command(f"lsof -p {self.m_process_id}")
    for line in output.split("\n"):
      if file_name in line: lines.append(line)
    assert len(lines), "more than one loaded module"

    line_parts = list(filter(lambda e: len(e) > 0, lines[0].split(' ')))
    assert len(line_parts) >= 9 # 9 columns

    shared_library_file_path = line_parts[8]
    if os.path.islink(shared_library_file_path):
      assert False, "resolve symbolic link here"

    tmp = vu.extract_file_name(shared_library_file_path)

    result = {
      "symbolic": file_name != tmp,
      "file_name": tmp,
      "file_dir": vu.extract_file_directory(shared_library_file_path),
      "symbolic_name": file_name,
    }

    self.m_loaded_libraries[file_name] = result

    return result

  def _find_shared_libraries(self, object, recursive) -> map:
    assert self.m_ready, "the elf file is not loaded"

    shared_libraries = {}

    for section in object.iter_sections():
      if not isinstance(section, DynamicSection):
        continue

      if section.num_tags() > 0:
        for tag in section.iter_tags():
          if tag.entry.d_tag == 'DT_NEEDED':
            shared_library = self._find_shared_library(tag.needed) 
            shared_libraries[tag.needed] = shared_library

    if recursive and len(shared_libraries) > 0:
      recursive_shared_libraries = {}
      for e in shared_libraries.values():
        file_path = os.path.join(e["file_dir"], e["file_name"])
        object = ELFFile(open(file_path, 'rb'))
        l = self._find_shared_libraries(object, recursive)
        recursive_shared_libraries.update(l)
      shared_libraries.update(recursive_shared_libraries)

    return shared_libraries
