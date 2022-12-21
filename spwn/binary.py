import pwn
import os


class Binary:
	def __init__(self, name: str):
		self.name = name
		self.debug_name = name
		self.pwnfile = pwn.ELF(name, checksec=False)

	def set_executable(self) -> None:
		os.chmod(self.name, 0o777)
		if self.debug_name != self.name:
			os.chmod(self.debug_name, 0o777)
