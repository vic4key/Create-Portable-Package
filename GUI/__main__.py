import os, sys

GUI_folder = os.path.join(os.getcwd(), "GUI")
sys.path.append(GUI_folder)

import app
app.main()