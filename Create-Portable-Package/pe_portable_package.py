from .pe_format import PEPackage
from .pe_format_mz import MZPackage
from .pe_format_mo import MOPackage
from .pe_format_elf import ELFPackage

from enum import Enum

class pe_format_t(int, Enum):
  unknown = -1
  win     = 0
  linux   = 1
  macho   = 2

class PEPortablePackage:
  ''' PE Portable Package
  '''
  m_pe_object: PEPackage = None

  def __init__(self, file_path: str) -> None:
    pe_format = self.determine_pe_format(file_path)
    if pe_format == pe_format_t.win:
      self.m_pe_object = MZPackage(file_path)
    elif pe_format == pe_format_t.linux:
      self.m_pe_object = ELFPackage(file_path)
    elif pe_format == pe_format_t.macho:
      self.m_pe_object = MOPackage(file_path)
    else:
      raise NotImplementedError("The PE file format is not supported")

  def determine_pe_format(self, file_path: str) -> pe_format_t:
    result = pe_format_t.unknown
    try:
      with open(file_path, "rb") as f:
        data = f.read(10)
        if data.startswith(bytearray.fromhex("4D5A90")):     # MZ
          result = pe_format_t.win
        elif data.startswith(bytearray.fromhex("7F454C46")): # ELF
          result = pe_format_t.linux
        elif data.startswith(bytearray.fromhex("CFFAEDFE")): # Mach-O
          result = pe_format_t.macho
    except Exception as e:
      print(e)
    return result

  def create_portable_package(self, directory: str = ".", force: bool = False):
    self.m_pe_object.create_portable_package(directory, force)