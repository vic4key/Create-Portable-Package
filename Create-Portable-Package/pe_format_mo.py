from .pe_format import PEPackage

class MOPackage(PEPackage):
  ''' PE Mach-O Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)
