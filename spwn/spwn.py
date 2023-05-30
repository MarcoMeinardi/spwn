import argparse
import os
import shutil
import sys

sys.argv = ["NOTERM"] + sys.argv  # HACK to prevent pwntools to messup the terminal, the added arg will be removed by pwnlib

from spwn.filemanager import FileManager
from spwn.analyzer import Analyzer
from spwn.scripter import Scripter
from spwn.configmanager import ConfigManager
from spwn.customanalyzer import CustomAnalyzer
from spwn.configgenerator import ConfigGenerator


CONFIG_PATH = os.path.expanduser("~/.config/spwn/config.json")


class Spwn:
	def __init__(self, create_interactions: bool, no_decompiler: bool, script_only: bool, interactions_only: bool):
		if not interactions_only:
			self.create_interactions = create_interactions or script_only
			self.no_decompiler = no_decompiler
			self.script_only = script_only
			self.check_dependencies()
			self.files = FileManager(configs)
			self.files.auto_recognize(self.script_only)

			print("[*] Binary:", self.files.binary.name)
			if self.files.libc: print("[*] Libc:  ", self.files.libc.name)
			else: print("[!] No libc")
			if self.files.loader: print("[*] Loader:", self.files.loader.name)
			else: print("[!] No loader")
			if self.files.other_binaries: print("[*] Other: ", self.files.other_binaries)
			print()
		else:
			self.files = None

		self.run()

	def run(self) -> None:
		if self.files:
			if not self.script_only:
				analyzer = Analyzer(configs, self.files)
				custom_analyzer = CustomAnalyzer(configs, self.files)
				analyzer.pre_analysis(open_decompiler=not self.no_decompiler)
				custom_analyzer.pre_analysis()
				print()

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
				custom_analyzer.post_analysis()

			self.scripter = Scripter(configs, self.files, create_interactions=self.create_interactions)
			self.scripter.create_script()
			self.create_script_file()
			self.scripter.save_script()
		else:
			self.scripter = Scripter(configs)
			self.scripter.create_menu_interaction_functions()
			self.scripter.dump_interactions()

	def check_dependencies(self) -> None:
		deps = ["patchelf", "file"]
		semi_deps = {
			"eu-unstrip": "elfutils",
			"seccomp-tools": "seccomp-tools",
			"cwe_checker": "cwe_checker (https://github.com/fkie-cad/cwe_checker)"
		}

		err = False
		for dep in deps:
			if not shutil.which(dep):
				print(f"[ERROR] Please install {dep}")
				err = True

		if not configs.suppress_warnings:
			for dep in semi_deps:
				if not shutil.which(dep):
					print(f"[WARNING] Please install {semi_deps[dep]}")

		if err:
			exit(1)

	def create_debug_dir(self) -> None:
		global configs
		while os.path.exists(configs.debug_dir):
			if os.path.isdir(configs.debug_dir):
				print(f'[!] {configs.debug_dir} directory already exists, enter a new name or press enter to use it anyways')
				new_dir = input("> ").strip()
				if not new_dir:
					break
				configs.debug_dir = new_dir
			else:
				print(f'[!] {configs.debug_dir} file already exists, enter a new name')
				new_dir = input("> ").strip()
				if not new_dir:
					print(f'[!] {configs.debug_dir} is not a directory and cannot be overwritten')
				else:
					configs.debug_dir = new_dir

		if not os.path.exists(configs.debug_dir):
			os.mkdir(configs.debug_dir)

	def create_script_file(self) -> None:
		global configs
		while os.path.exists(configs.script_file):
			if os.path.isfile(configs.script_file):
				print(f'[!] {configs.script_file} file already exists, enter a new name or press enter to overwrite')
				new_file = input("> ").strip()
				if not new_file:
					break
				configs.script_file = new_file
			else:
				print(f'[!] {configs.script_file} already exists, enter a new name')
				new_file = input("> ").strip()
				if not new_file:
					print(f'[!] {configs.script_file} is not a file and cannot be overwritten')
				else:
					configs.script_file = new_file

	def populate_debug_dir(self) -> None:
		shutil.copy(self.files.binary.name, os.path.join(configs.debug_dir, self.files.binary.name))
		self.files.binary.debug_name = os.path.join(configs.debug_dir, self.files.binary.name)

		shutil.copy(self.files.libc.name, os.path.join(configs.debug_dir, "libc.so.6"))
		self.files.libc.debug_name = os.path.join(configs.debug_dir, "libc.so.6")

		if self.files.loader:
			shutil.copy(self.files.loader.name, os.path.join(configs.debug_dir, "ld-linux.so.2"))
			self.files.loader.debug_name = os.path.join(configs.debug_dir, "ld-linux.so.2")

		for binary in self.files.other_binaries:
			shutil.copy(binary, os.path.join(configs.debug_dir, binary))


def main():
	parser = argparse.ArgumentParser(
		prog="spwn",
		description="spwn is a tool to quickly start a pwn challenge, for more informations check https://github.com/MarcoMeinardi/spwn"
	)

	parser.add_argument(
		"-i", "--inter",
		action="store_true",
		default=False,
		help="Interactively create interaction functions"
	)

	parser.add_argument(
		"-so", "--sonly",
		action="store_true",
		default=False,
		help="Create the interaction script without analyzing the binary"
	)

	parser.add_argument(
		"-io", "--ionly",
		action="store_true",
		default=False,
		help="Create the interaction functions, without doing any analysis"
	)

	parser.add_argument(
		"-nd", "--nodecomp",
		action="store_true",
		default=False,
		help="Don't open the decompiler"
	)

	parser.add_argument(
		"--config",
		action="store_true",
		default=False,
		help="Setup configs and quit"
	)

	parser.add_argument(
		"others",
		nargs=argparse.REMAINDER,
		help="You can avoid typing the hyphens and/or specify the template"
	)

	args = parser.parse_args(sys.argv[1:])
	others = set(args.others)

	possible_arguments = {
		"ionly": "ionly",
		"so": "sonly",
		"sonly": "sonly",
		"io": "ionly",
		"interactions": "inter",
		"inter": "inter",
		"i": "inter",
		"nodecomp": "nodecomp",
		"nd": "nodecomp"
	}

	for arg in possible_arguments:
		if arg in others:
			setattr(args, possible_arguments[arg], True)
			others.remove(arg)

	ConfigGenerator().maybe_create_config()
	if args.config or "config" in others:
		print("[*] Setup completed")
	else:
		global configs
		template = others.pop() if others else None
		configs = ConfigManager(CONFIG_PATH, template)

		Spwn(create_interactions=args.inter, no_decompiler=args.nodecomp, script_only=args.sonly, interactions_only=args.ionly)
