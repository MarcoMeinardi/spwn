from code import InteractiveConsole
import os
import shutil
import sys

from spwn.filemanager import FileManager
from spwn.analyzer import Analyzer
from spwn.scripter import Scripter

DEBUG_DIR     = "debug"
SCRIPT_FILE   = "a.py"
TEMPLATE_FILE = f"/home/{os.getlogin()}/.local/lib/python3.10/site-packages/spwn/template.py"

class Spwn:
	def __init__(self, create_interactions: bool):
		self.create_interactions = create_interactions
		self.files = FileManager()
		self.files.auto_recognize()

		print("[*] Binary: ", self.files.binary.name)
		if self.files.libc: print("[*] Libc:   ", self.files.libc.name)
		else: print("[!] No libc")
		if self.files.loader: print("[*] Loader: ", self.files.loader.name)
		else: print("[!] No loader")
		if self.files.other_libraries: print("[*] Other:  ", self.files.other_libraries)
		print()

	def run(self) -> None:
		analyzer = Analyzer(self.files)
		analyzer.pre_analisys()
		if self.files.libc:
			self.create_debug_dir()
			self.populate_debug_dir()
			self.files.libc.maybe_unstrip()

			if self.files.loader is None:
				if self.files.get_loader(DEBUG_DIR):
					self.files.loader.set_executable()

			self.files.patchelf(DEBUG_DIR)

		self.files.binary.set_executable()
		analyzer.post_analisys()

		self.scripter = Scripter(self.files, TEMPLATE_FILE, create_interactions=self.create_interactions)
		self.scripter.create_script(DEBUG_DIR)
		self.create_script_file()
		self.scripter.save_script(SCRIPT_FILE)

	def create_debug_dir(self) -> None:
		global DEBUG_DIR
		while os.path.exists(DEBUG_DIR):
			if os.path.isdir(DEBUG_DIR):
				print(f"[!] {DEBUG_DIR} directory already exists, enter a new name or press enter to use it anyways")
				new_dir = input("> ").strip()
				if not new_dir:
					break
				DEBUG_DIR = new_dir
			else:
				print(f"[!] {DEBUG_DIR} file already exists, enter a new name")
				new_dir = input("> ").strip()
				if not new_dir:
					print(f"[!] {DEBUG_DIR} is not a directory and cannot be overwritten")
				else:
					DEBUG_DIR = new_dir

		if not os.path.exists(DEBUG_DIR):
			os.mkdir(DEBUG_DIR)

	def create_script_file(self) -> None:
		global SCRIPT_FILE
		while os.path.exists(SCRIPT_FILE):
			if os.path.isfile(SCRIPT_FILE):
				print(f"[!] {SCRIPT_FILE} file already exists, enter a new name or press enter to overwrite")
				new_file = input("> ").strip()
				if not new_file:
					break
				SCRIPT_FILE = new_file
			else:
				print(f"[!] {SCRIPT_FILE} already exists, enter a new name")
				new_file = input("> ").strip()
				if not new_file:
					print(f"[!] {SCRIPT_FILE} is not a file and cannot be overwritten")
				else:
					SCRIPT_FILE = new_file

	def populate_debug_dir(self) -> None:
		shutil.copy(self.files.binary.name, os.path.join(DEBUG_DIR, self.files.binary.name))
		self.files.binary.debug_name = os.path.join(DEBUG_DIR, self.files.binary.name)

		shutil.copy(self.files.libc.name, os.path.join(DEBUG_DIR, "libc.so.6"))
		self.files.libc.debug_name = os.path.join(DEBUG_DIR, "libc.so.6")

		if self.files.loader:
			shutil.copy(self.files.loader.name, os.path.join(DEBUG_DIR, "ld-linux.so.2"))
			self.files.loader.debug_name = os.path.join(DEBUG_DIR, "ld-linux.so.2")

		for library in self.files.other_libraries:
			shutil.copy(library, os.path.join(DEBUG_DIR, library))
		
help_msg = r"""
spwn is a tool to quickly start a pwn challenge, for more informations check https://github.com/MarcoMeinardi/spwn

Usage:
    spwn [inter] [help]
	- inter:
	    Interactively create interaction functions
	- help:
	    Print this message

Bug report: https://github.com/MarcoMeinardi/spwn/issues
"""[1:-1]

def print_help_msg():
	print(help_msg)
	
def main():
	if any("help" in arg for arg in sys.argv):
		print_help_msg()
	elif any("inter" in arg for arg in sys.argv):
		Spwn(create_interactions=True).run()
	else:
		Spwn(create_interactions=False).run()

	