#!/usr/bin/env python3
from pwn import *
import os, sys
import re
import requests
import tarfile
import shutil

DEFAULT_DEBUG_DIR_NAME = "debug"
DEFAULT_SCRIPT_NAME = "a.py"
TEXT_EDITOR_COMMAND = "subl"

# 0: binary
# 1: original libc
# 2: debug directory
script_prefix = \
'''from pwn import *
context.binary = "./{0}"
exe = ELF("./{0}", checksec = False)
'''
base_script_libc = \
'''
if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug("./{2}/{0}", """
		c
	""", aslr = False)
elif args.ORIGINAL:
	r = process("./{0}", env = {{"LD_PRELOAD": "./{1}"}})
else:
	r = process("./{2}/{0}")
\n\n\n
r.interactive()
'''
base_script_no_libc = \
'''
if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug("./{0}", """
		c
	""", aslr = False)
else:
	r = process("./{0}")
\n\n\n
r.interactive()
'''

class Spwn:
	def __init__(self, manual_file_selection):
		if not self.find_files(manual_file_selection):
			print("Aborting")
			return
		self.binary = Binary(self.binary_name)
		if self.libc_name:
			self.libc = Libc(self.libc_name)
			self.debug_directory = DEFAULT_DEBUG_DIR_NAME
			self.create_debug_directory()
			self.get_files_informations()
			if self.loader_name: self.loader = Loader(self.loader_name, self.libc)
			self.populate_debug_directory()
			self.set_executable(
				f"./{self.binary_name}",
				f"./{self.debug_directory}/{self.binary_name}",
				f"./{self.debug_directory}/ld-linux.so.2",
			)
			if self.loader_name:
				self.set_executable(f"./{self.loader_name}")
			self.binary.set_run_path_and_interpreter(f"./{self.debug_directory}")
		else:
			self.get_files_informations()
			self.set_executable(f"./{self.binary_name}")

		self.gadgets = None
		self.exploit_name = DEFAULT_SCRIPT_NAME
		self.create_script()
		self.open_script()

	def create_script(self):
		'''
		Create a default script with the informations retrived in the previous parts
		'''
		script = script_prefix

		# without libc
		if self.libc_name is None:
			# Add rop gadgets
			if self.gadgets is not None:
				script += "\n" + self.gadgets
			script += base_script_no_libc
			script = script.format(self.binary_name)

		# with libc
		else:
			script += 'libc = ELF("./{2}/libc.so.6", checksec = False)\n'
			# Add rop gadgets
			if self.gadgets is not None:
				script += "\n" + self.gadgets
			script += base_script_libc
			script = script.format(self.binary_name, self.libc_name, self.debug_directory)
			
		while os.path.exists(f"./{self.exploit_name}"):
			print(f"[!] \"{self.exploit_name}\" already exists, type in a new name or press enter to overwrite it")
			inp = input("> ").strip()
			if not inp:
				break
			self.exploit_name = inp

		with open(f"./{self.exploit_name}", "w") as f:
			f.write(script)

	def open_script(self):
		os.system(f"{TEXT_EDITOR_COMMAND} ./{self.exploit_name}")

	def find_files(self, manual_selection):
		'''
		Attempt to automatically detect binary, libc and loader
		This is based on standard naming (ex: loader name starts with ld), if this is not the case, just use manual_selection
		It will also fall in manual selection in case of strange behaviors
		'''
		# Get ELFs in current directory
		files = list(filter(lambda file_name: platform.architecture(file_name)[1] == "ELF", os.listdir()))
		if len(files) == 0:
			print("[ERROR] No ELFs found")
			return False

		if manual_selection:
			return self.manual_selection(files)

		self.libc_name = None
		self.loader_name = None
		self.binary_name = None
		binaries = []

		for file_name in files:
			# Check if libc
			if file_name.startswith("libc"): self.libc_name = file_name
			# Check if loader
			elif file_name.startswith("ld.") or file_name.startswith("ld-"): self.loader_name = file_name
			# Else add to binary candidates
			else: binaries.append(file_name)

		# No binary candidates, fall in manual selection
		if len(binaries) == 0:
			print("[!] Binary not found, continuing with manual selection")
			return self.manual_selection(files)

		if len(binaries) == 1:
			self.binary_name = binaries[0]
		else:
			print("[!] More than one candidate for binary:")
			index = self.ask_option(binaries, False)
			if index == -1:
				print("[ERROR] Binary is needed")
				return False
			self.binary_name = binaries[index]
			del binaries[index]
			if self.libc_name is None and len(binaries) > 0:
				print("[!] There might be a undetected libc")
				index = self.ask_option(binaries, True)
				if index != -1:
					self.libc_name = binaries[index]
					del binaries[index]
			if self.libc_name is not None and self.loader_name is None and len(binaries) > 0:
				print("[!] There might be a undetected loader")
				index = self.ask_option(binaries, True)
				if index != -1:
					self.loader_name = binaries[index]

		print(f"[+] Binary: {self.binary_name}")
		if self.libc_name is not None: print(f"[+] Libc: {self.libc_name}")
		if self.loader_name is not None: print(f"[+] Loader: {self.libc_name}")
		return True

	def manual_selection(self, files):
		'''
		If autodetection fails, you will have to select the files manually (and I'm trying my best to make this function pointless)
		'''
		print("[*] Enter binary")
		index = self.ask_option(files, False)
		if index == -1:
			print("[ERROR] Binary is needed")
			return False
		self.binary_name = files[index]
		del files[index]

		if len(files) == 0:
			return True
		print("[*] Enter libc")
		index = self.ask_option(files, True)
		if index == -1:
			return True
		self.libc_name = files[index]
		del files[index]

		if len(files) == 0:
			return True
		print("[*] Enter Loader")
		index = self.ask_option(files, True)
		if index == -1:
			return True
		self.loader_name = files[index]
		return True

	def ask_option(self, options, skippable):
		'''
		Ask user to chose between numbered options
		'''
		for i, option in enumerate(options):
			print(f"[{i + 1}]: {option}")
		while True:
			try:
				inp = input("(Enter to skip) > " if skippable else "> ").strip()
				if not inp:
					return -1
				index = int(inp)
				if index < 1 or index > len(options):
					print("[!] Invalid index")
				else:
					return index - 1
			except KeyboardInterrupt:
				print("Aborting")
				quit()

	def create_debug_directory(self):
		while os.path.exists(f"./{self.debug_directory}"):
			print(f"[!] \"{self.debug_directory}\" directory already exists, type in a new name or press enter to use it anyways")
			inp = input("> ").strip()
			if not inp:
				return
			self.debug_directory = inp

		os.mkdir(self.debug_directory)

	def get_files_informations(self):
		'''
		Print basic files informations:
			file binary
			pwn checksec binary
			libc version
		You can add whatever you want with "self.binary.run_command(command)"
		'''
		self.binary.run_command("file")
		print(f"[*] pwn checksec ./{self.binary_name}")
		print(self.binary.pwn_binary.checksec(banner = False))
		if self.libc_name is not None:
			self.libc_version = self.libc.get_libc_version()
			if self.libc_version is not None:
				print(f"[*] Libc version: {self.libc_version}")
			else:
				print("[!] Cannot get libc version")
				self.libc_version = None
		self.binary.find_possible_vulnerabilities()

	def populate_debug_directory(self):
		'''
		Copy binary, unstripped libc and loader in the debug directory
		'''
		# Just copy the binary
		shutil.copyfile(f"./{self.binary_name}", f"./{self.debug_directory}/{self.binary_name}")

		if self.libc_name is not None:
			# Check if libc is unstripped, otherwise try to download from ubuntu packages
			if self.libc.has_debug_info():
				shutil.copyfile(f"./{self.libc_name}", f"./{self.debug_directory}/libc.so.6")
			else:
				if not self.libc.download_libc_with_debug_symbols(f"./{self.debug_directory}"):
					# In case of failure
					shutil.copyfile(f"./{self.libc_name}", f"./{self.debug_directory}/libc.so.6")
			
			# Check if we already have the loader
			if self.loader_name is not None:
				self.has_loader = True
				shutil.copyfile(f"./{self.loader_name}", f"./{self.debug_directory}/ld-linux.so.2")
			else:
				self.loader = Loader("ld-linux.so.2", self.libc)
				self.has_loader = self.loader.download_loader(f"./{self.debug_directory}")

	def set_executable(self, *args):
		'''
		Set every file rwx
		'''
		for file_name in args:
			if os.path.exists(file_name):
				os.chmod(file_name, 0o777)


class Binary:
	def __init__(self, file_name):
		self.file_name = file_name
		self.pwn_binary = ELF(self.file_name, checksec = False)

	def run_command(self, command):
		'''
		Run {command} ./{filename}
		Used to get basic information about the binary
		'''
		full_command = f"{command} ./{self.file_name}"
		# Little injection check, just for you ;)
		if not all(c in string.ascii_letters + string.digits + "_-." for c in command + self.file_name):
			class DetectedInjectionError(Exception): pass
			raise DetectedInjectionError("You're getting injected little boy")
		print(f"[*] {command} ./{self.file_name}")
		os.system(f"{command} ./{self.file_name}")

	def find_possible_vulnerabilities(self):
		'''
		Print functions that might lead to a vulnerability
		'''
		maybe_vulnerable = ["gets", "execve", "system", "printf", "__isoc99_scanf"]
		found = []
		for function in maybe_vulnerable:
			if function in self.pwn_binary.symbols:
				found.append(function)
		
		if found:
			print("[*] There are some risky functions:")
			print(*found)

	def set_run_path_and_interpreter(self, debug_directory):
		'''
		Use patchelf to tell the binary to use the libc and the loader in the debug directory
		'''
		if os.path.exists(f"{debug_directory}/ld-linux.so.2"):
			# If the loader has been downloaded correctly
			command = f"patchelf {debug_directory}/{self.file_name} --set-rpath {debug_directory}/ --set-interpreter {debug_directory}/ld-linux.so.2"
		else:
			# Just use the libc
			command = f"patchelf {debug_directory}/{self.file_name} --set-rpath {debug_directory}/"

		if os.system(command) != 0:
			print("[ERROR] Cannot set run path or interpreter")
			return False
		else:
			return True

	def check_possible_seccomp(self):
		for symbol in self.pwn_binary.symbols:
			if "seccomp" in symbol or "prctl" in symbol:
				print("[*] There might be seccomps")
				print(f"[*] timeout 1 seccomp-tools dump ./{self.file_name}")
				os.system(f"timeout 1 seccomp-tools dump ./{self.file_name}")

class Library:
	def __init__(self, file_name):
		self.file_name = file_name

	def download_package(self, output_directory, package_name, package_url, file_to_extract, output_file):
		'''
		Download a (ubuntu) package
		Used to get libc symbols and loader
		'''
		# Download package from ubuntu
		r = requests.get(package_url)
		if r.status_code != 200:
			print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
			return False

		with open(f"{output_directory}/{package_name}", "wb") as f:
			f.write(r.content)

		# Extract everything and throw away what we don't need (I could have done it with libarchive, but it's borken)
		os.system(f"ar x {output_directory}/{package_name} --output={output_directory}")
		if os.path.exists(f"{output_directory}/control.tar.gz"):
			os.remove(f"{output_directory}/control.tar.gz")
		if os.path.exists(f"{output_directory}/control.tar.xz"):
			os.remove(f"{output_directory}/control.tar.xz")
		os.remove(f"{output_directory}/debian-binary")
		os.remove(f"{output_directory}/{package_name}")

		# Extract the needed file from the data.tar.xz sub-archive
		data_archive = tarfile.open(f"{output_directory}/data.tar.xz", "r")
		for file_name in data_archive.getnames():
			if file_to_extract in file_name:
				extracted_file = data_archive.extractfile(file_name)
				break
		else:
			print(f"[ERROR] Cannot find {file_to_extract} in ubuntu package")
			return False
		
		with open(f"{output_directory}/{output_file}", "wb") as f:
			f.write(extracted_file.read())

		# Delete the sub-archive from which we extracted the file
		os.remove(f"{output_directory}/data.tar.xz")

		return True

class Libc(Library):
	def __init__(self, file_name):
		super().__init__(file_name)
		self.pwn_libc = ELF(self.file_name, checksec = False)

	def get_libc_version(self):
		'''
		Extract version from libc binary
		For most libraries the libc version is written near the string "ubuntu"
		'''
		with open(self.file_name, "r", encoding = "latin-1") as f:
			match = re.search(r"\d+\.\d+-\d+ubuntu\d+(\.\d+)?", f.read())
			if match:
				self.ubuntu_version = match.group()
				self.libc_number = re.search(r"\d\.\d+", self.ubuntu_version).group()
			else:
				print("[ERROR] Cannot get libc version")
				return None
		return self.libc_number

	def has_debug_info(self):
		return bool(self.pwn_libc.get_section_by_name(".debug_info"))

	def download_libc_with_debug_symbols(self, output_directory):
		'''
		Download libc debug symbols from ubuntu packages and create an unstripped version of the libc in the debug directory
		'''
		package_name = f"libc6-dbg_{self.ubuntu_version}_{self.pwn_libc.get_machine_arch()}.deb"
		package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name
		libc_debug_name = f"libc-{self.libc_number}.so"
		if not self.download_package(output_directory, package_name, package_url, libc_debug_name, "libc.so.6"):
			return False

		# unstrip the libc
		result =  os.system(f"eu-unstrip ./{self.file_name} {output_directory}/libc.so.6") == 0
		if not result:
			print("[ERROR] Cannot unstrip libc")
			return False
		else:
			return True

class Loader(Library):
	def __init__(self, file_name, libc):
		super().__init__(file_name)
		self.libc = libc

	def download_loader(self, output_directory):
		'''
		Download a loader from ubuntu packages to run the binary with the given libc
		'''
		package_name = f"libc6_{self.libc.ubuntu_version}_{self.libc.pwn_libc.get_machine_arch()}.deb"
		package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name
		loader_name = f"ld-{self.libc.libc_number}.so"
		return self.download_package(output_directory, package_name, package_url, loader_name, "ld-linux.so.2")


Spwn("manual" in sys.argv)