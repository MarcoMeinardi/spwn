import subprocess
import shutil
import re
import yara

from spwn.filemanager import FileManager
from spwn.configmanager import ConfigManager

dangerous_functions_check = ["system", "execve", "gets", "ptrace", "memfrob", "strfry"]


class Analyzer:
	def __init__(self, configs: ConfigManager, files: FileManager):
		self.configs = configs
		self.files = files

	def pre_analysis(self, open_decompiler: bool) -> None:
		self.run_file()
		self.run_checksec()
		self.print_libc_version()
		self.print_dangerous_functions()
		self.run_yara()
		if open_decompiler:
			self.open_decompiler()
		self.run_cwe_checker()

	def post_analysis(self) -> None:
		self.check_and_print_seccomp()

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
		rules = yara.compile(self.configs.yara_rules)
		matches = rules.match(self.files.binary.name)

		if matches:
			print("[!] yara found something")
			for match in matches:
				addresses = [instance.offset for string_match in match.strings for instance in string_match.instances]
				print(f'[*] {match.rule} at {", ".join(map(hex, addresses))}')
			print()

	def open_decompiler(self) -> None:
		if self.configs.idafree_command and self.files.binary.pwnfile.arch in ["amd64", "i386"]:
			subprocess.Popen(self.configs.idafree_command.format(binary=self.files.binary.name), shell=True, start_new_session=True)
		elif self.configs.decompiler_command:
			subprocess.Popen(self.configs.decompiler_command.format(binary=self.files.binary.name), shell=True, start_new_session=True)

	def check_and_print_seccomp(self) -> None:
		for function in self.files.binary.pwnfile.sym:
			if "seccomp" in function or "prctl" in function:
				self.run_seccomptools()
				break

	def run_seccomptools(self) -> None:
		print("[!] Possible seccomp found")
		if not shutil.which("seccomp-tools"):
			if not self.configs.suppress_warnings:
				print("[ERROR] seccomp-tools not found, either it is not installed or is not in your $PATH")
		else:
			print(f"[*] seccomp-tools dump ./{self.files.binary.debug_name} < /dev/null")
			try:
				print(subprocess.check_output(["seccomp-tools", "dump", f"./{self.files.binary.debug_name}"], timeout=1, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT, encoding="latin1"))
			except subprocess.TimeoutExpired as e:
				print(f"[!] {e}")

	def run_cwe_checker(self) -> None:
		if not shutil.which("cwe_checker"):
			if not self.configs.suppress_warnings:
				print("[ERROR] cwe_checker not found, either it is not installed or is not in your $PATH")
		else:
			print(f"[*] cwe_checker {self.files.binary.name} (press Ctrl+C to stop)")
			try:
				print(subprocess.check_output(["cwe_checker", self.files.binary.name], encoding="latin1"))
			except KeyboardInterrupt:
				pass
