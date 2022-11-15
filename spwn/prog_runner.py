import subprocess
import os

from spwn.binary import Binary
from spwn.config_manager import ConfigManager
from spwn.utils import strtobool


# this doesn't really need to be a class, but meh
class ProgRunner:
	def __init__(self, configs: ConfigManager, binary: Binary, libc: Binary) -> None:
		self.configs = configs
		self.binary = binary
		self.libc = libc

	def execute(self):
		if strtobool(self.configs["autorun_ropper"]):
			self.run_ropper()
		if strtobool(self.configs["autorun_ropgadget"]):
			self.run_ropgadget()
		if strtobool(self.configs["autorun_ghidra"]):
			self.run_ghidra()
		if strtobool(self.configs["autorun_ida"]):
			self.run_ida()
		if self.libc and strtobool(self.configs["autorun_one_gadget"]):
			self.run_one_gadget()


	def run_ropper(self):
		print("[+] Running ropper")
		additional_args = self.configs["ropper_additional_args"]
		if additional_args is None:
			additional_args = ""
		cmd = f"ropper -f {self.binary.name} {additional_args}"
		subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL)

	def run_ropgadget(self):
		print("[+] Running ROPgadget")
		additional_args = self.configs["ropgadget_additional_args"]
		if additional_args is None:
			additional_args = ""
		cmd = f"ROPgadget --binary {self.binary.name} {additional_args}"
		subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL)

	def run_ghidra(self):
		print("[+] Running Ghidra")
		# TODO figure out how to add binary to project and analyse it
		ghidra_path = self.configs["ghidra_path"]
		assert ghidra_path is not None, "Please set ghidra_path in config"
		cmd = f"{ghidra_path}"
		subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	def run_ida(self):
		print("[+] Running IDA")
		ida_path = self.configs["ida_path"]
		assert ida_path is not None, "Please set ida_path in config"
		cmd = f"{ida_path} {self.binary.name}"
		subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	def run_one_gadget(self):
		print("[+] Running one_gadget")
		additional_args = self.configs["one_gadget_additional_args"]
		if additional_args is None:
			additional_args = ""
		cmd = f"one_gadget {self.libc.name} {additional_args}"
		subprocess.run(cmd, shell=True)
