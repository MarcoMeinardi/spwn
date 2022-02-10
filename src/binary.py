from pwn import *
import os

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
		'''
		Check if there are seccomp related functions and eventually run seccom-tools to detect them
		'''
		for symbol in self.pwn_binary.symbols:
			if "seccomp" in symbol or "prctl" in symbol:
				print("[*] There might be seccomps")
				print(f"[*] timeout 1 seccomp-tools dump ./{self.file_name}")
				os.system(f"timeout 1 seccomp-tools dump ./{self.file_name}")