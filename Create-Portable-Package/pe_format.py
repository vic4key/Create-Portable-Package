import os, psutil, shutil
import subprocess as sp
import PyVutils as vu

class PEPackage:
  ''' PE Package
  '''
  m_object = None
  m_file_path = None
  m_process_id = None
  m_loaded_libraries = dict()
  m_exclusion_patterns = set()

  def __init__(self, file_path: str) -> None:
    pe_file_name = vu.extract_file_name(file_path)
    print(f"Creating portable package for '{pe_file_name}'")

    if not os.path.exists(file_path): raise IOError("The PE file does not exist.")
    self.m_file_path = file_path

    process_id = self._get_process_id()
    if process_id is None: raise RuntimeError("The PE file is not running.")
    self.m_process_id = process_id

  def _get_file_name(self) -> str:
    return vu.extract_file_name(self.m_file_path)

  def _get_process_id(self) -> int:
    file_name = self._get_file_name()
    for process in psutil.process_iter():
      if process.name() == file_name: return process.pid
    return None

  def _run_cli_command(self, command) -> str:
    result = sp.run(command.split(" "), stdout=sp.PIPE)
    return result.stdout.decode("utf-8")

  def _find_shared_library(self, file_name: str) -> dict:
    raise NotImplementedError("_find_shared_library")

  def _find_shared_libraries(self, object, recursive) -> map:
    raise NotImplementedError("_find_shared_libraries")

  def create_portable_package(self, directory: str = ".", exclusion_files: str = None, force: bool = False):
    if exclusion_files and type(exclusion_files) is str:
      for exclusion_file in exclusion_files.split(';'):
        try:
          with open(exclusion_file, "r") as f:
            exclusion_patterns = f.read().split("\n")
            exclusion_patterns = list(map(lambda line: line.strip(), exclusion_patterns))
            exclusion_patterns = list(filter(lambda line: len(line) > 0, exclusion_patterns))
            self.m_exclusion_patterns.update(exclusion_patterns)
        except: pass
    
    print("Looking for the dependency shared libraries ...")

    pe_file_name = self._get_file_name()
    package_dir = os.path.join(directory, pe_file_name)
    package_dir += "_package"
    if force and os.path.isdir(package_dir): shutil.rmtree(package_dir)
    if not os.path.isdir(package_dir): os.makedirs(package_dir)

    shared_libraries = self._find_shared_libraries(self.m_object, True)

    print("Copying the dependency shared libraries ...")

    index = 0

    if len(shared_libraries) > 0:
      src = self.m_file_path
      dst = os.path.join(package_dir, pe_file_name)
      shutil.copyfile(src, dst)

      print(f"\t{index}. '{src}' => '{dst}'")
      index += 1

    for _, e in shared_libraries.items():
      file_name = e["file_name"]
      src = os.path.join(e["file_dir"], file_name)
      dst = os.path.join(package_dir, file_name)
      shutil.copyfile(src, dst)

      msg = f"\t{index}. '{file_name}' -> '{src}'"

      if e["symbolic"]:
        symbolic_name = e["symbolic_name"]
        dst = os.path.join(package_dir, symbolic_name)
        shutil.copyfile(src, dst)
        msg += f" ('{symbolic_name}')"

      print(msg)
      index += 1

    print(f"Create portable package for '{pe_file_name}' finished.")