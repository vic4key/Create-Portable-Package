from .pe_format import PEPackage

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

class ELFPackage(PEPackage):
  ''' PE ELF Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)

  def _list_shared_libraries(self, file_path: str) -> list:
    result = []
    pe = ELFFile(open(file_path, "rb"))
    for section in pe.iter_sections():
      if not isinstance(section, DynamicSection):
        continue
      if section.num_tags() > 0:
        for tag in section.iter_tags():
          if tag.entry.d_tag == "DT_NEEDED":
            result.append(tag.needed)
    return result
