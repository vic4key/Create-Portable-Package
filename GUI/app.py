import os, sys

os.environ["PATH"] += os.pathsep if os.environ["PATH"][-1] != os.pathsep else ""
os.environ["PATH"] += os.pathsep.join([os.getcwd()])

from PyQt5.QtWidgets import QApplication

# auto compile resources .qrc
import pyqt5ac
pyqt5ac.main(
	initPackage=False,
	force=False,
	ioPaths=[
	["resources/resources.qrc", "resources.py"]
])
import resources

from main import Window

# pip install QDarkStyle
# import qdarkstyle

# pip install qtmodern
# import qtmodern.styles
# import qtmodern.windows

# pip install qtstylish
# import qtstylish

# pip install qt_material
# from qt_material import apply_stylesheet

# # hook I/O print to redirect output to debugviewer
# from win32api import OutputDebugString
# class LogWrapper:
# 	def flush(self): pass
# 	def write(self, s):
# 		for line in s.replace('\t', '  ').split('\n'):
# 			line = line.strip()
# 			if len(line) > 0:
# 				OutputDebugString(line)
# sys.stdout = LogWrapper()
# sys.stderr = LogWrapper()

def main():
	app = QApplication(sys.argv)
	win = Window(app)

	app.setStyle("fusion")

	# app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())

	# qtmodern.styles.dark(app)
	# win = qtmodern.windows.ModernWindow(win)

	# app.setStyleSheet(qtstylish.light())

	# apply_stylesheet(app, theme='dark_teal.xml')

	win.show()

	sys.exit(app.exec_())

if __name__ == "__main__":
	main()
