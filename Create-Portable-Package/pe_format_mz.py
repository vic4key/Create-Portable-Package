from .pe_format import PEPackage

class MZPackage(PEPackage):
  ''' PE MZ Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)
