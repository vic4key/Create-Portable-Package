import argparse

from .pe_portable_package import PEPortablePackage

def main():
  parser = argparse.ArgumentParser(description="Create Portable Package")
  group  = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("-f", "--pe-file", type=str, default=None, help="The path of a specified executable file")
  group.add_argument("-p", "--pe-pid", type=int, default=None, help="The pid of a specified executable file")
  parser.add_argument("-d", "--package-directory", type=str, required=False, default=".", help="The package directory")
  parser.add_argument("-e", "--exclusion-files", type=str, required=False, default=None, help="The exclusion files (separate by semicolon).")
  parser.add_argument("-c", "--clean-up", type=bool, required=False, default=True, help="Clean-up before creating portable package")
  args = parser.parse_args()
  pp = PEPortablePackage(args.pe_pid, args.pe_file)
  pp.create_portable_package(args.package_directory, args.exclusion_files, args.clean_up)

main()