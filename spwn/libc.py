import pwn
import re
import shutil

from spwn.binary import Binary


class Libc(Binary):
	def __init__(self, name: str):
		super().__init__(name)
		self.version = self.get_libc_version()

	def get_libc_version(self) -> str:
		with open(self.name, "rb") as f:
			content = f.read().decode("latin-1")
		match = re.search(r"stable release version (\d\.\d+)", content)
		if match:
			return match.group(1)

		return pwn.platform.libc_ver(self.name)[1]

	def has_debug_info(self) -> bool:
		return bool(self.pwnfile.get_section_by_name(".debug_info"))

	def maybe_unstrip(self) -> None:
		if self.has_debug_info(): return

		if not shutil.which("eu-unstrip"):
			print("[ERROR] eu-unstrip not found, please install elfutils")
			return

		print("[+] Trying to unstrip libc")
		pwn.context.log_level = "warning"
		if pwn.libcdb.unstrip_libc(self.debug_name):
			self.unstripped = True
			print("[*] Libc unstripped")
		else:
			self.unstripped = False
			print("[!] Failed to unstrip libc")
		pwn.context.log_level = "info"

	def get_ubuntu_version_string(self) -> str | None:
		with open(self.name, "rb") as f:
			content = f.read()
		match = re.search(r"\d+\.\d+-\d+ubuntu\d+(\.\d+)?".encode(), content)

		if match:
			return match.group().decode()

		if not self.unstripped:
			return None

		with open(self.debug_name, "rb") as f:
			content = f.read()
		match = re.search(r"\d+\.\d+-\d+ubuntu\d+(\.\d+)?".encode(), content)

		if match:
			return match.group().decode()
		else:
			return None
