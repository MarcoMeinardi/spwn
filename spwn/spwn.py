import os
import shutil
import sys

from spwn.filemanager import FileManager
from spwn.analyzer import Analyzer
from spwn.scripter import Scripter
from spwn.config_manager import ConfigManager
from spwn.prog_runner import ProgRunner
from spwn.cmd_parser import inflate_arg_parser

CONFIG_PATH = os.path.expanduser("~/.config/spwn/config.json")
configs = ConfigManager(CONFIG_PATH)

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

		self.progrunner = ProgRunner(configs, self.files.binary, self.files.libc)
		self.progrunner.execute()

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
		

def main():
	parser = inflate_arg_parser()

	args = parser.parse_args(sys.argv[1:])

	if not args.subparsers_called:
		if args.ionly:
			Spwn(interactions_only=True)
		else:
			Spwn(create_interactions=args.inter)
	else:
		if args.list:
			print("[*] Available keys:")
			print("\t\n".join(configs.keys()))
		elif args.set:
			key = args.set[0]
			value = " ".join(args.set[1:])
			configs[key] = value
			print(f"[*] {key} set to {value}")
		elif args.get:
			key = args.get[0]
			print(f"[*] {key} = {configs[key]}")
		elif args.reset:
			key = args.reset[0]
			configs.reset(key)
			print(f"[*] {key} reset to default value of {configs[key]}")



