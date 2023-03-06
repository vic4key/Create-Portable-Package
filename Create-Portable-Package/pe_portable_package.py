import os, psutil, shutil
import PyVutils as vu

from .pe_format import PEPackage

class PEPortablePackage:
  ''' PE Portable Package
  '''
  m_pe_object: PEPackage = None
  m_exclusion_patterns = set()

  def __init__(self, process_id: int, file_path: str) -> None:

    if file_path is None:
      assert process_id is not None, "The process id must be specified"
      for process in psutil.process_iter():
        if process.pid == process_id:
          file_path = process.exe()
          break

    assert file_path is not None, "The file path must be specified"

    pe_format = vu.determine_file_format(file_path)
    if pe_format == vu.FileFormat.PE_WIN:
      from .pe_format_mz import MZPackage
      self.m_pe_object = MZPackage(file_path)
    elif pe_format == vu.FileFormat.PE_LINUX:
      from .pe_format_elf import ELFPackage
      self.m_pe_object = ELFPackage(file_path)
    elif pe_format == vu.FileFormat.PE_MAC:
      from .pe_format_mo import MOPackage
      self.m_pe_object = MOPackage(file_path)
    else:
      raise NotImplementedError("The PE file format is not supported")
    self.m_pe_object.set_parent(self)

  def _load_exclusion_files(self, exclusion_files: list):
    for exclusion_file in exclusion_files:
      try:
        with open(exclusion_file, "r") as f:
          patterns = f.read().split("\n")
          patterns = list(map(
            lambda line: line.strip(), patterns))
          patterns = list(filter(
            lambda line: len(line) > 0 and not line.startswith("#"), patterns))
          self.m_exclusion_patterns.update(patterns)
      except: pass

    for i, e in enumerate(self.m_exclusion_patterns): print(f"\t{i:3}. Pattern\t'{e}'")

  def _is_excluded_file(self, file_name: str) -> bool:
    for exclusion_pattern in self.m_exclusion_patterns:
      l = vu.regex(file_name, exclusion_pattern)
      if len(l) > 0: return True
    return False

  def create_portable_package(self, directory: str = ".", exclusion_files: str = None, force: bool = True):

    print("Loading exclusion files ...")
    if type(exclusion_files) is str: self._load_exclusion_files(exclusion_files.split(';'))

    print("Looking for searching directories ...")
    self.m_pe_object.load_seaching_directories()

    print("Finding for dependency shared libraries ...")

    pe_file_path = self.m_pe_object.get_file_path()
    pe_file_name = vu.extract_file_name(pe_file_path)
    package_dir = os.path.join(directory, pe_file_name)
    package_dir += "_package"
    if force and os.path.isdir(package_dir): shutil.rmtree(package_dir)
    if not os.path.isdir(package_dir): os.makedirs(package_dir)

    shared_libraries = self.m_pe_object._find_shared_libraries(pe_file_path, True)

    num_file_libraries = len(shared_libraries)
    num_sym_libraries  = len([e for e in shared_libraries.values() if e["symbolic_name"]])
    print(f"\t  Total {num_file_libraries} shared libraries ({num_sym_libraries} symbolics) are found ...")

    print("Copying dependency shared libraries ...")

    index = 0

    if len(shared_libraries) > 0:
      src = self.m_pe_object.get_file_path()
      dst = os.path.join(package_dir, pe_file_name)
      shutil.copyfile(src, dst)

      print(f"\t{index:3}. Copying\t'{src}' => '{dst}'")
      index += 1

    for e in shared_libraries.values():
      if e is None: continue

      msg = f"\t{index:3}. "
      file_name = e["file_name"]
      if self._is_excluded_file(file_name):
        msg += f"Ignored\t'{file_name}'"
      else:
        msg += f"Copying\t'{file_name}'"

        src = os.path.join(e["file_dir"], file_name)
        dst = os.path.join(package_dir, file_name)
        shutil.copyfile(src, dst)

        symbolic_name = e["symbolic_name"]
        if symbolic_name:
          msg += f" ('{symbolic_name}')"
          dst = os.path.join(package_dir, symbolic_name)
          shutil.copyfile(src, dst)

      msg += f" from '{src}'"
      print(msg)
      index += 1

    print(f"Create portable package for '{pe_file_name}' finished.")
