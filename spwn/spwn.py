from code import InteractiveConsole
import os
import shutil
import sys
import json

from spwn.filemanager import FileManager
from spwn.analyzer import Analyzer
from spwn.scripter import Scripter

CONFIG_PATH = os.path.expanduser("~/.config/spwn/config.json")
configs = json.load(open(CONFIG_PATH))
configs["template_file"] = os.path.expanduser(configs["template_file"])
configs["yara_rules"] = os.path.expanduser(configs["yara_rules"])

class Spwn:
	def __init__(self, create_interactions: bool | None =None, interactions_only: bool=False):
		if not interactions_only:
			self.create_interactions = create_interactions
			self.files = FileManager(configs)
			self.files.auto_recognize()

			print("[*] Binary: ", self.files.binary.name)
			if self.files.libc: print("[*] Libc:   ", self.files.libc.name)
			else: print("[!] No libc")
			if self.files.loader: print("[*] Loader: ", self.files.loader.name)
			else: print("[!] No loader")
			if self.files.other_libraries: print("[*] Other:  ", self.files.other_libraries)
			print()
		else:
			self.files = None

		self.run()

	def run(self) -> None:
		if self.files:
			analyzer = Analyzer(self.files)
			analyzer.pre_analysis()
			if self.files.libc:
				self.create_debug_dir()
				self.populate_debug_dir()
				self.files.libc.maybe_unstrip()

				if self.files.loader is None:
					self.files.get_loader()
				if self.files.loader is not None:
					self.files.loader.set_executable()

				self.files.patchelf()

			self.files.binary.set_executable()
			analyzer.post_analysis()

			self.scripter = Scripter(self.files, configs["template_file"], create_interactions=self.create_interactions)
			self.scripter.create_script()
			self.create_script_file()
			self.scripter.save_script()
		else:
			self.scripter = Scripter(None, None, None)
			self.scripter.create_menu_interaction_functions()
			self.scripter.dump_interactions()

	def create_debug_dir(self) -> None:
		global configs
		while os.path.exists(configs["debug_dir"]):
			if os.path.isdir(configs["debug_dir"]):
				print(f'[!] {configs["debug_dir"]} directory already exists, enter a new name or press enter to use it anyways')
				new_dir = input("> ").strip()
				if not new_dir:
					break
				configs["debug_dir"] = new_dir
			else:
				print(f'[!] {configs["debug_dir"]} file already exists, enter a new name')
				new_dir = input("> ").strip()
				if not new_dir:
					print(f'[!] {configs["debug_dir"]} is not a directory and cannot be overwritten')
				else:
					configs["debug_dir"] = new_dir

		if not os.path.exists(configs["debug_dir"]):
			os.mkdir(configs["debug_dir"])

	def create_script_file(self) -> None:
		global configs
		while os.path.exists(configs["script_file"]):
			if os.path.isfile(configs["script_file"]):
				print(f'[!] {configs["script_file"]} file already exists, enter a new name or press enter to overwrite')
				new_file = input("> ").strip()
				if not new_file:
					break
				configs["script_file"] = new_file
			else:
				print(f'[!] {configs["script_file"]} already exists, enter a new name')
				new_file = input("> ").strip()
				if not new_file:
					print(f'[!] {configs["script_file"]} is not a file and cannot be overwritten')
				else:
					configs["script_file"] = new_file

	def populate_debug_dir(self) -> None:
		shutil.copy(self.files.binary.name, os.path.join(configs["debug_dir"], self.files.binary.name))
		self.files.binary.debug_name = os.path.join(configs["debug_dir"], self.files.binary.name)

		shutil.copy(self.files.libc.name, os.path.join(configs["debug_dir"], "libc.so.6"))
		self.files.libc.debug_name = os.path.join(configs["debug_dir"], "libc.so.6")

		if self.files.loader:
			shutil.copy(self.files.loader.name, os.path.join(configs["debug_dir"], "ld-linux.so.2"))
			self.files.loader.debug_name = os.path.join(configs["debug_dir"], "ld-linux.so.2")

		for library in self.files.other_libraries:
			shutil.copy(library, os.path.join(configs["debug_dir"], library))
		
help_msg = r"""
spwn is a tool to quickly start a pwn challenge, for more informations check https://github.com/MarcoMeinardi/spwn

Usage:
    spwn [inter|i|-i] [help|h|-h] [ionly]
	- inter:
	    Interactively create interaction functions
	- help:
	    Print this message
	- ionly:
		Create the interaction functions, without doing any analysis

Bug report: https://github.com/MarcoMeinardi/spwn/issues
"""[1:-1]

def print_help_msg():
	print(help_msg)
	
def main():
	if "h" in sys.argv or "-h" in sys.argv or any("help" in arg for arg in sys.argv):
		print_help_msg()
	elif "io" in sys.argv or "-io" in sys.argv or any("ionly" in arg for arg in sys.argv):
		Spwn(interactions_only=True)
	elif "i" in sys.argv or "-i" in sys.argv or any("inter" in arg for arg in sys.argv):
		Spwn(create_interactions=True)
	else:
		Spwn(create_interactions=False)

	