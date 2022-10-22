import subprocess

dangerous_functions_check = ["system", "execve", "gets", "memfrob"]
# Long term TODO: analyze the code to understand if printf and scanf are properly used (constant first arg)

class Analyzer:
	def __init__(self, files):
		self.files = files

	def pre_analisys(self) -> None:
		self.run_file()
		self.run_checksec()
		self.print_libc_version()
		self.print_dangerous_functions()
		print()

	def post_analisys(self) -> None:
		self.check_and_print_seccomp()

	def run_file(self) -> None:
		print(f"[*] file {self.files.binary.name}")
		print(subprocess.check_output(["file", self.files.binary.name]).decode().strip())
	
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

	def check_and_print_seccomp(self) -> None:
		for function in self.files.binary.pwnfile.sym:
			if "seccomp" in function or "prctl" in function:
				self.run_seccomptools()
				break

	def run_seccomptools(self) -> None:
		print("[!] Possible seccomp found")
		seccomp_cmd = f"seccomp-tools dump ./{self.files.binary.name} < /dev/null"
		print(f"[*] {seccomp_cmd}")
		print(subprocess.check_output(seccomp_cmd, timeout=1, shell=True, stderr=subprocess.STDOUT, encoding="utf8"))
		
		
