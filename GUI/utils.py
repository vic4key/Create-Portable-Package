import os, sys, platform
from PyQt5.QtGui import QFont

import PyVutils as vu

def get_current_directory():
	result = ""
	try: result = sys._MEIPASS
	except: result = os.path.dirname(os.path.realpath(__file__))
	return vu.normalize_path(result)

def resources(file):
	return os.path.join(get_current_directory(), os.path.join("resources", file))

def get_default_font():
	if platform.system() == "Windows": return QFont("Courier New", 9)
	else: return QFont("Courier New", 10)
