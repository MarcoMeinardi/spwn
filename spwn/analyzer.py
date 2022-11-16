import subprocess
import os, signal
import re
import yara

from spwn.filemanager import FileManager

dangerous_functions_check = ["system", "execve", "gets", "ptrace", "memfrob"]
# Long term TODO: analyze the code to understand if printf and scanf are properly used (constant first arg)

class Analyzer:
	def __init__(self, configs: dict, files: FileManager):
		self.configs = configs
		self.files = files

	def pre_analysis(self) -> None:
		self.run_file()
		self.run_checksec()
		self.print_libc_version()
		self.print_dangerous_functions()
		self.run_yara()
		self.run_custom_commands(self.configs["preanalysis_commands"])
		print()

	def post_analysis(self) -> None:
		self.check_and_print_seccomp()
		self.run_custom_commands(self.configs["postanalysis_commands"])

	def run_file(self) -> None:
		print(f"[*] file {self.files.binary.name}")
		file_output = subprocess.check_output(["file", self.files.binary.name], encoding="latin1")
		type_and_arch = re.search(r"(ELF.*?), (.*?),", file_output)
		linking = re.search(r"(dynamically linked|statically linked)", file_output)
		debug_info = re.search(r"with debug_info", file_output)
		stripped = re.search(r"(not )?stripped", file_output)

		if not type_and_arch or not linking or not stripped:
			print(file_output.strip())
		else:
			print(type_and_arch.group(1))
			print(type_and_arch.group(2))
			print(linking.group())
			if debug_info:
				print(debug_info.group())
			print(stripped.group())
	
	def run_checksec(self) -> None:
		print(f"[*] checksec {self.files.binary.name}")
		print(self.files.binary.pwnfile.checksec(banner=False))

	def print_libc_version(self) -> None:
		if self.files.libc:
			print(f"Libc version: {self.files.libc.version}")

	def print_dangerous_functions(self) -> None:
		dangerous_functions = list(filter(lambda x: x in dangerous_functions_check, self.files.binary.pwnfile.sym))
		
		if dangerous_functions:
			print("[!] There are some dangerous functions:")
			print(" ".join(dangerous_functions))

	def run_yara(self) -> None:
		rules = yara.compile(self.configs["yara_rules"])
		with open(self.files.binary.name, "rb") as f:
			matches = rules.match(data=f.read())

		if matches:
			print("[!] yara found something")
			for match in matches:
				print(match)

	def check_and_print_seccomp(self) -> None:
		for function in self.files.binary.pwnfile.sym:
			if "seccomp" in function or "prctl" in function:
				self.run_seccomptools()
				break

	def run_seccomptools(self) -> None:
		print("[!] Possible seccomp found")
		print(f"[*] seccomp-tools dump ./{self.files.binary.debug_name} < /dev/null")
		try:
			print(subprocess.check_output(["seccomp-tools", "dump", f"./{self.files.binary.debug_name}"], timeout=1, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT, encoding="latin1"))
		except subprocess.TimeoutExpired as e:
			print(f"[!] {e}")

	def run_custom_commands(self, commands: list[str]) -> None:
		for command, timeout in commands:
			command = command.format(binary=self.files.binary.name, debug_binary=self.files.binary.debug_name)
			if timeout:
				print(f"[*] {command}")
				try:
					# Use exec command, otherwise, because of `shell=True`, the process wouldn't be killed on timeout
					p = subprocess.run(f"exec {command}", shell=True, timeout=1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="latin-1")
					print(p.stdout)
				except subprocess.TimeoutExpired:
					print("[!] Timeout")
			else:
				subprocess.Popen(command, shell=True)