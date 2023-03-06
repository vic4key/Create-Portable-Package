import os, psutil
import subprocess as sp
import PyVutils as vu

# from .pe_portable_package import PEPortablePackage

class PEPackage:
  ''' PE Package
  '''
  m_process = None
  m_file_path = None
  m_library_dirs = set()
  m_loaded_libraries = dict()
  m_parent = None

  def __init__(self, file_path: str) -> None:
    pe_file_name = vu.extract_file_name(file_path)
    print(f"Creating portable package for '{pe_file_name}'")

    if not os.path.exists(file_path): raise IOError("The PE file does not exist.")
    self.m_file_path = file_path

    process_id = self.get_process_id()
    if process_id is None: raise RuntimeError("The PE file is not running.")
    self.m_process = psutil.Process(process_id)

  def set_parent(self, parent):
    self.m_parent = parent

  def get_process_path(self) -> str:
    return self.m_file_path

  def get_process_id(self) -> int:
    file_name = vu.extract_file_name(self.m_file_path)
    for process in psutil.process_iter():
      if process.name().lower() == file_name.lower():
        return process.pid
    return None

  def get_file_name(self) -> str:
    return vu.extract_file_name(self.m_file_path)

  def load_seaching_directories(self):
    for m in self.m_process.memory_maps():
      if os.path.isfile(m.path):
        self.m_library_dirs.add(vu.extract_file_directory(m.path))

    for i, e in enumerate(self.m_library_dirs): print(f"\t{i:3}. Directory\t'{e}'")

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

    print(f"\t  Walking '{file_name}'")

    real_file_path = self._resolve_shared_library(file_name)
    if real_file_path:
      real_file_name = vu.extract_file_name(real_file_path)
      result = {
        "file_name": real_file_name,
        "file_dir": vu.extract_file_directory(real_file_path),
        "symbolic_name": file_name if file_name != real_file_name else None,
      }
    else:
      result = None # raise RuntimeError(f"Could not find '{file_name}' library")

    self.m_loaded_libraries[file_name] = result

    return result

  def _find_shared_libraries(self, file_path: str, recursive) -> map:
    shared_libraries = {}

    for file_name in self._list_shared_libraries(file_path):
      if not file_name in self.m_loaded_libraries.keys():
        shared_library = self._find_shared_library(file_name)
        if shared_library: shared_libraries[file_name] = shared_library

    if recursive:
      recursive_shared_libraries = {}
      for e in shared_libraries.values():
        file_name = e["file_name"]
        if not self.m_parent._is_excluded_file(file_name):
          file_path = os.path.join(e["file_dir"], file_name)
          items = self._find_shared_libraries(file_path, recursive)
          recursive_shared_libraries.update(items)
      shared_libraries.update(recursive_shared_libraries)

    return shared_libraries

  def _list_shared_libraries(self, file_path: str) -> list:
    raise NotImplementedError("_list_shared_libraries")
