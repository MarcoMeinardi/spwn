from pwn import *
import os
import shutil

from binary import Binary
from libc import Libc
from loader import Loader
from rop import ROP

TEXT_EDITOR_COMMAND = "xdg-open"

DEFAULT_DEBUG_DIR_NAME = "debug"
DEFAULT_SCRIPT_NAME = "a.py"
BINARY_GADGETS_OUTPUT_FILE = "gadgets"
LIBC_GADGETS_OUTPUT_FILE = "libc_gadgets"
LIBC_GADGETS_PREFIX = "LIBC_"

BINARY_GADGET_REGEXS = [
    r"0x[0-9a-fA-F]+ : pop [a-z0-9]{3} ; ret\n", # single pop
    r"0x[0-9a-fA-F]+ : pop [a-z0-9]{3} ; pop [a-z0-9]{3} ; ret\n", # double pop
    r"0x[0-9a-fA-F]+ : ret\n", # ret (always remember to align the stack before calling system)
    [r"0x[0-9a-fA-F]+ : syscall ; ret\n", r"0x[0-9a-fA-F]+ : syscall\n"] # syscall (if the first is present, don't search for the second)
]

LIBC_GADGET_REGEXS = [
    r"0x[0-9a-fA-F]+ : pop [a-z0-9]{3} ; ret\n", # single pop is enough for a libc
    r"0x[0-9a-fA-F]+ : ret\n",
    [r"0x[0-9a-fA-F]+ : syscall ; ret\n", r"0x[0-9a-fA-F]+ : syscall\n"]
]

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
	def __init__(self, manual_file_selection, get_gadgets):
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
			self.binary.check_possible_seccomp()
		else:
			self.get_files_informations()
			self.set_executable(f"./{self.binary_name}")
			self.binary.check_possible_seccomp()

		if get_gadgets:
			rop_binary = ROP(self.binary_name, BINARY_GADGETS_OUTPUT_FILE)
			self.script_gadgets = rop_binary.extract_basic_gadgets(BINARY_GADGET_REGEXS)
			if self.libc_name is not None:
				rop_libc = ROP(self.libc_name, LIBC_GADGETS_OUTPUT_FILE, LIBC_GADGETS_PREFIX)
				self.script_gadgets += rop_libc.extract_basic_gadgets(LIBC_GADGET_REGEXS)
			if not self.script_gadgets:
				self.script_gadgets = "# Wow that's so unlucky! I found no gadgets\n"
		else:
			self.script_gadgets = None

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
			if self.script_gadgets is not None:
				script += "\n" + self.script_gadgets
			script += base_script_no_libc
			script = script.format(self.binary_name)

		# with libc
		else:
			script += 'libc = ELF("./{2}/libc.so.6", checksec = False)\n'
			# Add rop gadgets
			if self.script_gadgets is not None:
				script += "\n" + self.script_gadgets
			script += base_script_libc
			script = script.format(self.binary_name, self.libc_name, self.debug_directory)
			
		while os.path.exists(f"./{self.exploit_name}"):
			print(f'[!] "{self.exploit_name}" already exists, type in a new name or press enter to overwrite it')
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