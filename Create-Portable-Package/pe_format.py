import os, psutil, shutil
import subprocess as sp
import PyVutils as vu

class PEPackage:
  ''' PE Package
  '''
  m_process = None
  m_file_path = None
  m_library_dirs = set()
  m_loaded_libraries = dict()
  m_exclusion_patterns = set()

  def __init__(self, file_path: str) -> None:
    pe_file_name = vu.extract_file_name(file_path)
    print(f"Creating portable package for '{pe_file_name}'")

    if not os.path.exists(file_path): raise IOError("The PE file does not exist.")
    self.m_file_path = file_path

    process_id = self._get_process_id()
    if process_id is None: raise RuntimeError("The PE file is not running.")
    self.m_process = psutil.Process(process_id)

  def _get_file_name(self) -> str:
    return vu.extract_file_name(self.m_file_path)

  def _get_process_id(self) -> int:
    file_name = self._get_file_name()
    for process in psutil.process_iter():
      if process.name() == file_name: return process.pid
    return None

  def _load_exclusion_files(self, exclusion_files: list):
    print("Loading exclusion files ...")

    for exclusion_file in exclusion_files:
      try:
        with open(exclusion_file, "r") as f:
          exclusion_patterns = f.read().split("\n")
          exclusion_patterns = list(map(lambda line: line.strip(), exclusion_patterns))
          exclusion_patterns = list(filter(lambda line: len(line) > 0, exclusion_patterns))
          self.m_exclusion_patterns.update(exclusion_patterns)
      except: pass

    for i, e in enumerate(self.m_exclusion_patterns): print(f"\t{i:3}. Pattern\t'{e}'")

  def _is_excluded_file(self, file_name: str) -> bool:
    for exclusion_pattern in self.m_exclusion_patterns:
      l = vu.regex(file_name, exclusion_pattern)
      if len(l) > 0: return True
    return False

  def _resolve_shared_library(self, file_name: str) -> str:
    for dir in self.m_library_dirs:
      file_path = os.path.join(dir, file_name)
      if os.path.isfile(file_path):
        if os.path.islink(file_path):
          file_path = os.path.join(dir, os.readlink(file_path))
        return file_path
    return None

  def _find_shared_library(self, file_name: str) -> dict:
    if file_name in self.m_loaded_libraries.keys():
      return self.m_loaded_libraries[file_name]

    # print(f"Walking: {file_name}")

    real_file_path = self._resolve_shared_library(file_name)
    if real_file_path is None: raise RuntimeError(f"Could not find '{file_name}' library")

    real_file_name = vu.extract_file_name(real_file_path)

    result = {
      "file_name": real_file_name,
      "file_dir": vu.extract_file_directory(real_file_path),
      "symbolic_name": file_name if file_name != real_file_name else None,
    }

    self.m_loaded_libraries[file_name] = result

    return result

  def _find_shared_libraries(self, file_path: str, recursive) -> map:
    shared_libraries = {}

    for file_name in self._list_shared_libraries(file_path):
      shared_libraries[file_name] = self._find_shared_library(file_name) 

    if recursive:
      recursive_shared_libraries = {}
      for e in shared_libraries.values():
        file_path = os.path.join(e["file_dir"], e["file_name"])
        l = self._find_shared_libraries(file_path, recursive)
        recursive_shared_libraries.update(l)
      shared_libraries.update(recursive_shared_libraries)

    return shared_libraries

  def _list_shared_libraries(self, file_path: str) -> list:
    raise NotImplementedError("_list_shared_libraries")

  def create_portable_package(self, directory: str = ".", exclusion_files: str = None, force: bool = False):

    if type(exclusion_files) is str:
      self._load_exclusion_files(exclusion_files.split(';'))

    print("Looking for searching directories ...")

    for m in self.m_process.memory_maps():
      if os.path.isfile(m.path):
        self.m_library_dirs.add(vu.extract_file_directory(m.path))

    for i, e in enumerate(self.m_library_dirs): print(f"\t{i:3}. Directory\t'{e}'")

    print("Finding for dependency shared libraries ...")

    pe_file_name = self._get_file_name()
    package_dir = os.path.join(directory, pe_file_name)
    package_dir += "_package"
    if force and os.path.isdir(package_dir): shutil.rmtree(package_dir)
    if not os.path.isdir(package_dir): os.makedirs(package_dir)

    shared_libraries = self._find_shared_libraries(self.m_file_path, True)

    num_file_libraries = len(shared_libraries)
    num_sym_libraries  = len([e for e in shared_libraries.values() if e["symbolic_name"]])
    print(f"\t  Total {num_file_libraries} shared libraries ({num_sym_libraries} symbolics) are found ...")

    print("Copying dependency shared libraries ...")

    index = 0

    if len(shared_libraries) > 0:
      src = self.m_file_path
      dst = os.path.join(package_dir, pe_file_name)
      shutil.copyfile(src, dst)

      print(f"\t{index:3}. Copying\t'{src}' => '{dst}'")
      index += 1

    for e in shared_libraries.values():
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