import sys, argparse

from .pe_portable_package import PEPortablePackage

def main(argc, argv):
  parser = argparse.ArgumentParser(description="Create Portable Package")
  parser.add_argument("-p", "--pe-file", type=str, required=True, help="The path to an executable file")
  parser.add_argument("-d", "--package-directory", type=str, required=False, default=".", help="The package directory")
  parser.add_argument("-c", "--clean-up", type=bool, required=False, default=True, help="Clean-up before creating portable package")
  args = parser.parse_args()
  pp = PEPortablePackage(args.pe_file)
  pp.create_portable_package(args.package_directory, args.clean_up)

main(len(sys.argv), sys.argv)