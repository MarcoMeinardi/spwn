import subprocess
import importlib
import os

from spwn.configmanager import ConfigManager
from spwn.filemanager import FileManager


class CustomAnalyzer:
	def __init__(self, configs: ConfigManager, files: FileManager):
		self.configs = configs
		self.files = files

	def pre_analysis(self) -> None:
		for command, timeout in self.configs.preanalysis_commands:
			self.run_command(command, timeout)
		for script in self.configs.preanalysis_scripts:
			self.run_script(script)

	def post_analysis(self) -> None:
		for command, timeout in self.configs.postanalysis_commands:
			self.run_command(command, timeout)
		for script in self.configs.postanalysis_scripts:
			self.run_script(script)

	def run_command(self, command: str, timeout: int | bool | None) -> None:
		command = command.format(binary=self.files.binary.name, debug_binary=self.files.binary.debug_name)
		if timeout is not False:
			print(f"[*] {command}")
			if timeout:
				try:
					# Use `exec command`, otherwise, because of `shell=True`, the process won't get killed on timeout
					p = subprocess.run(f"exec {command}", shell=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="latin-1")
					print(p.stdout)
				except subprocess.TimeoutExpired:
					print("[!] Timeout")
			else:
				p = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="latin-1")
				print(p.stdout)
		else:
			subprocess.Popen(command, shell=True, start_new_session=True)

	def run_script(self, script: str):
		if script.startswith("~"):
			script = os.path.expanduser(script)
		elif not script.startswith("/"):
			script = os.path.join(self.configs.config_path, script)

		if not os.path.isfile(script):
			raise FileNotFoundError(f"Cannot find custom script {script}")

		spec = importlib.util.spec_from_file_location("main", script)
		module = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(module)
		module.main(self.files)
