from .pe_format import PEPackage
from .pe_format_mz import MZPackage
from .pe_format_mo import MOPackage
from .pe_format_elf import ELFPackage

import PyVutils as vu

class PEPortablePackage:
  ''' PE Portable Package
  '''
  m_pe_object: PEPackage = None

  def __init__(self, file_path: str) -> None:
    pe_format = vu.determine_file_format(file_path)
    if pe_format == vu.FileFormat.PE_WIN:
      self.m_pe_object = MZPackage(file_path)
    elif pe_format == vu.FileFormat.PE_LINUX:
      self.m_pe_object = ELFPackage(file_path)
    elif pe_format == vu.FileFormat.PE_MACHO:
      self.m_pe_object = MOPackage(file_path)
    else:
      raise NotImplementedError("The PE file format is not supported")

  def create_portable_package(self, directory: str = ".", exclusion_files: str = None, force: bool = True):
    self.m_pe_object.create_portable_package(directory, exclusion_files, force)
