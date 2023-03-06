import os, psutil, shutil
import subprocess as sp
import PyVutils as vu

class PEPackage:
  ''' PE Package
  '''
  m_file = None
  m_file_path = None
  m_process = None
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

  def _is_excluded_file(self, file_name: str) -> bool:
    for exclusion_pattern in self.m_exclusion_patterns:
      l = vu.regex(file_name, exclusion_pattern)
      if len(l) > 0: return True
    return False

  def _find_real_shared_library(self, file_name: str) -> str:
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

    real_file_path = self._find_real_shared_library(file_name)
    real_file_name = vu.extract_file_name(real_file_path)

    result = {
      "file_name": real_file_name,
      "file_dir": vu.extract_file_directory(real_file_path),
      "symbolic_name": file_name if file_name != real_file_name else None,
    }

    self.m_loaded_libraries[file_name] = result

    return result

  def _find_shared_libraries(self, object, recursive) -> map:
    raise NotImplementedError("_find_shared_libraries")

  def create_portable_package(self, directory: str = ".", exclusion_files: str = None, force: bool = False):

    # Loading exclusion files ...

    if exclusion_files and type(exclusion_files) is str:
      print("Loading the exclusion files ...")
      for exclusion_file in exclusion_files.split(';'):
        try:
          with open(exclusion_file, "r") as f:
            exclusion_patterns = f.read().split("\n")
            exclusion_patterns = list(map(lambda line: line.strip(), exclusion_patterns))
            exclusion_patterns = list(filter(lambda line: len(line) > 0, exclusion_patterns))
            self.m_exclusion_patterns.update(exclusion_patterns)
        except: pass

    print("Looking for searching directories ...")

    for m in self.m_process.memory_maps():
      if os.path.isfile(m.path):
        self.m_library_dirs.add(vu.extract_file_directory(m.path))

    print("Looking for dependency shared libraries ...")

    pe_file_name = self._get_file_name()
    package_dir = os.path.join(directory, pe_file_name)
    package_dir += "_package"
    if force and os.path.isdir(package_dir): shutil.rmtree(package_dir)
    if not os.path.isdir(package_dir): os.makedirs(package_dir)

    shared_libraries = self._find_shared_libraries(self.m_file, True)

    print("Copying the dependency shared libraries ...")

    index = 0

    if len(shared_libraries) > 0:
      src = self.m_file_path
      dst = os.path.join(package_dir, pe_file_name)
      shutil.copyfile(src, dst)

      print(f"\t{index:3}. Copying '{src}' => '{dst}'")
      index += 1

    for _, e in shared_libraries.items():
      msg = f"\t{index:3}. "
      file_name = e["file_name"]
      if self._is_excluded_file(file_name):
        msg += f"Ignored '{file_name}'"
      else:
        msg += f"Copying '{file_name}' from '{src}'"

        src = os.path.join(e["file_dir"], file_name)
        dst = os.path.join(package_dir, file_name)
        shutil.copyfile(src, dst)

        if e["symbolic_name"]:
          symbolic_name = e["symbolic_name"]
          dst = os.path.join(package_dir, symbolic_name)
          shutil.copyfile(src, dst)
          msg += f" ('{symbolic_name}')"

      print(msg)
      index += 1

    print(f"Create portable package for '{pe_file_name}' finished.")