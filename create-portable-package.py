import os, sys, psutil, shutil
import subprocess as sp
import PyVutils as vu

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

# import pprint
# pp = pprint.PrettyPrinter(indent=2)
# print = pp.pprint

# PE Package

class PEPackage:
  ''' PE Package
  '''
  m_ready = False
  m_object = None
  m_file_path = None
  m_process_id = None
  m_loaded_libraries = {}

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

  def create_portable_package(self, directory=".", force=False):
    assert self.m_ready, "the elf file is not loaded"

    print("Looking for the dependency shared libraries ...")

    pe_file_name = self._get_file_name()
    package_dir = os.path.join(directory, pe_file_name)
    package_dir += "_package"
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

# ELF Package

class ELFPackage(PEPackage):
  ''' PE ELF Package
  '''
  def __init__(self, file_path: str) -> None:
    PEPackage.__init__(self, file_path)
    try:
      self.m_object = ELFFile(open(self.m_file_path, "rb"))
      if self.m_object is None: raise ("Could not load the ELF file.")
      self.m_ready = True
    except Exception as e: print(str(e))

  def _find_shared_library(self, file_name: str) -> dict:
    assert self.m_ready, "the elf file is not loaded"

    if file_name in self.m_loaded_libraries.keys(): return self.m_loaded_libraries[file_name]

    # print(f"Walking: {file_name}")

    lines = []
    output = self._run_cli_command(f"lsof -p {self.m_process_id}")
    for line in output.split("\n"):
      if file_name in line: lines.append(line)
    assert len(lines), "more than one loaded module"

    line_parts = list(filter(lambda e: len(e) > 0, lines[0].split(' ')))
    assert len(line_parts) >= 9 # 9 columns

    shared_library_file_path = line_parts[8]
    if os.path.islink(shared_library_file_path):
      assert False, "resolve symbolic link here"

    tmp = vu.extract_file_name(shared_library_file_path)

    result = {
      "symbolic": file_name != tmp,
      "file_name": tmp,
      "file_dir": vu.extract_file_directory(shared_library_file_path),
      "symbolic_name": file_name,
    }

    self.m_loaded_libraries[file_name] = result

    return result

  def _find_shared_libraries(self, object, recursive) -> map:
    assert self.m_ready, "the elf file is not loaded"

    shared_libraries = {}

    for section in object.iter_sections():
      if not isinstance(section, DynamicSection):
        continue

      if section.num_tags() > 0:
        for tag in section.iter_tags():
          if tag.entry.d_tag == 'DT_NEEDED':
            shared_library = self._find_shared_library(tag.needed) 
            shared_libraries[tag.needed] = shared_library

    if recursive and len(shared_libraries) > 0:
      recursive_shared_libraries = {}
      for e in shared_libraries.values():
        file_path = os.path.join(e["file_dir"], e["file_name"])
        object = ELFFile(open(file_path, 'rb'))
        l = self._find_shared_libraries(object, recursive)
        recursive_shared_libraries.update(l)
      shared_libraries.update(recursive_shared_libraries)

    return shared_libraries

# MZ Package

class MZPackage(PEPackage):
  ''' PE MZ Package
  '''
  pass

# Mach-O Package

class MOPackage(PEPackage):
  ''' PE Mach-O Package
  '''
  pass

# PE Portable Package

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
    self.m_file_path = file_path

    pe_format = self.determine_pe_format(file_path)
    if pe_format == pe_format_t.win:
      raise NotImplementedError("missing implementation for windows os")
    elif pe_format == pe_format_t.linux:
      self.m_pe_object = ELFPackage(file_path)
    else:
      raise NotImplementedError("this pe file format is not supported")

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

  def create_portable_package(self, directory=".", force=False):
    self.m_pe_object.create_portable_package(directory, force)

# main

def main(argc, argv):
  if argc < 2:
    name = vu.extract_file_name(__file__, False)
    print(f"ERROR:  Invalid arguments.\n\tUsage: {name} path\\to\\executable\\file")
    return
  pp = PEPortablePackage(argv[1])
  pp.create_portable_package(".")

if __name__ == "__main__":
  main(len(sys.argv), sys.argv)