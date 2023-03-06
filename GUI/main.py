import os
from enum import Enum

from PyQt5 import uic as UiLoader
from PyQt5.QtGui import QColor, QIcon, QPalette
from PyQt5.QtCore import Qt, QSize, pyqtSignal as Signal, pyqtSlot as Slot
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidgetItem, QMessageBox

from utils import *
from picker import Picker
from about import AboutDlg

class color_t(str, Enum):
	# status
	success = "green"
	normal  = "black"
	warn 		= "orange"
	error 	= "red"
	# color
	red = "red"
	orange = "orange"

class WSClient: pass

class Window(QMainWindow, WSClient):

	m_signal_update_ui = Signal(bool)
	m_signal_log = Signal(str, color_t)

	def __init__(self, app):
		super(Window, self).__init__()
		super(WSClient, self).__init__()
		self.app = app
		self.setup_ui()
		return

	def setup_ui(self):
		# load ui from file
		UiLoader.loadUi(resources("main.ui"), self)
		# signal & slot
		self.actionAbout.triggered.connect(self.on_triggered_menu_help_about)
		self.m_signal_update_ui.connect(self.slot_update_ui)
		self.m_signal_log.connect(self.slot_log)
		# others
		# self.list_log.setIconSize(QSize(16, 16))

	def is_default_style(self):
		return QApplication.instance().style().metaObject().className() == "QWindowsVistaStyle"

	def closeEvent(self, event):
		event.accept()

	def log(self, text, color=color_t.normal):
		self.m_signal_log.emit(text, color)

	@Slot(str, color_t)
	def slot_log(self, text, color=color_t.normal):
		item = QListWidgetItem(text)
		item.setFont(get_default_font())
		item.setForeground(QColor(color))
		# item.setData(Qt.UserRole, data)
		self.list_log.addItem(item)
		self.list_log.scrollToBottom()

	def update_ui(self, update_values=False):
		self.m_signal_update_ui.emit(update_values)

	@Slot(bool)
	def slot_update_ui(self, update_values=False):
		if update_values:
			pass

	def on_triggered_menu_help_about(self):
		AboutDlg(self.app).exec_()
