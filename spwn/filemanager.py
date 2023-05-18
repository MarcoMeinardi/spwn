import pwn
import shutil
import os
import tempfile
import subprocess

import spwn.utils as utils
from spwn.binary import Binary
from spwn.libc import Libc
from spwn.loader import Loader
from spwn.configmanager import ConfigManager


class FileManager:
	def __init__(self, configs: ConfigManager):
		self.configs = configs
		self.binary = None
		self.libc = None
		self.loader = None
		self.other_binaries = []

	def auto_recognize(self, maybe_has_debug: bool) -> None:
		binaries = []
		libcs = []
		loaders = []
		other_libraries = []
		files = list(filter(lambda x: pwn.platform.architecture(x)[1] == "ELF", os.listdir()))
		self.other_binaries = files
		if not files:
			raise Exception("No ELFs found")

		for file in files:
			if file.startswith("libc"):
				libcs.append(file)
			elif file.startswith("lib"):
				other_libraries.append(file)
			elif file.startswith("ld"):
				loaders.append(file)
			else:
				binaries.append(file)

		# Binary
		if len(binaries) == 1:
			self.binary = Binary(binaries[0])
		elif len(binaries) > 1:
			self.binary = utils.ask_list_delete("Select binary", binaries, can_skip=False)
			self.binary = Binary(self.binary)
			other_libraries.extend(binaries)
		else:
			self.ask_all(files)
			return
		del files[files.index(self.binary.name)]

		# Libc
		if len(libcs) == 1:
			self.libc = Libc(libcs[0])
		else:
			libcs.extend(other_libraries)
			if not libcs:
				return

			self.libc = utils.ask_list_delete("Select libc", libcs, can_skip=True)
			if self.libc is None:
				return
			self.libc = Libc(self.libc)

			other_libraries = libcs
		del files[files.index(self.libc.name)]

		if maybe_has_debug:
			if os.path.exists(self.configs.debug_dir):
				if os.path.exists(os.path.join(self.configs.debug_dir, self.binary.name)):
					self.binary.debug_name = os.path.join(self.configs.debug_dir, self.binary.name)
				if os.path.exists(os.path.join(self.configs.debug_dir, "libc.so.6")):
					self.libc.debug_name = os.path.join(self.configs.debug_dir, self.libc.name)

		# Loader
		if len(loaders) == 1:
			self.loader = Loader(loaders[0])
		else:
			if not loaders:
				return
			self.loader = utils.ask_list_delete("Select loader", loaders, can_skip=True)
			if self.loader:
				self.loader = Loader(self.loader)
		del files[files.index(self.loader.name)]

	def ask_all(self, files: list[str]) -> None:
		if not files: raise Exception("No executables found")

		self.libc = None
		self.loader = None

		self.binary = utils.ask_list_delete("Select binary", files, can_skip=False)
		self.binary = Binary(self.binary)
		if files:
			self.libc = utils.ask_list_delete("Select libc", files, can_skip=True)
			if self.libc and files:
				self.libc = Libc(self.libc)
				self.loader = utils.ask_list_delete("Select loader", files, can_skip=True)
				if self.loader:
					self.loader = Loader(self.loader)
			else:
				self.loader = None
		else:
			self.libc = None
			self.loader = None

	def get_loader(self) -> None:
		ubuntu_version = self.libc.get_ubuntu_version_string()
		if ubuntu_version is None:
			print("[!] Cannot get ubuntu packet name for loader")
			return

		package_name = f"libc6_{ubuntu_version}_{self.libc.pwnfile.get_machine_arch()}.deb"
		package_url  = f"https://launchpad.net/ubuntu/+archive/primary/+files/{package_name}"
		tempdir = tempfile.mkdtemp()

		print("[+] Downloading loader")
		if not utils.download_package(package_url, tempdir):
			shutil.rmtree(tempdir)
			return

		print("[+] Extracting loader")
		if not utils.extract_deb(tempdir):
			shutil.rmtree(tempdir)
			return

		if not utils.find_and_extract_data(tempdir):
			shutil.rmtree(tempdir)
			return

		loader_path = utils.find_loader(tempdir)
		if loader_path is None:
			shutil.rmtree(tempdir)
			return

		new_loader_path = os.path.join(self.configs.debug_dir, "ld-linux.so.2")
		shutil.copyfile(loader_path, new_loader_path)
		self.loader = Loader(new_loader_path)

		shutil.rmtree(tempdir)
		return

	def patchelf(self) -> None:
		if self.loader:
			try:
				subprocess.check_call(["patchelf", "--set-interpreter", f"./{self.loader.debug_name}", "--set-rpath", f"./{self.configs.debug_dir}", self.binary.debug_name])
			except subprocess.CalledProcessError:
				print("[!] patchelf failed")
		else:
			try:
				subprocess.check_call(["patchelf", "--set-rpath", f"./{self.configs.debug_dir}", self.binary.debug_name])
			except subprocess.CalledProcessError:
				print("[!] patchelf failed")
