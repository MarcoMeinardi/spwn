from pwn import *
import os
import re

from library import Library

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
