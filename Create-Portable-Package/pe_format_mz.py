from .pe_format import PEPackage

import pefile

class MZPackage(PEPackage):
  ''' PE MZ Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)

  def _list_shared_libraries(self, file_path: str) -> list:
    result = []
    pe = pefile.PE(file_path, fast_load=True)
    dd = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
    pe.parse_data_directories([dd])
    for item in pe.DIRECTORY_ENTRY_IMPORT:
      file_name = item.dll.decode("utf-8")
      if not self.m_parent._is_excluded_file(file_name):
        result.append(file_name)
    return result
