import subprocess

from spwn.configmanager import ConfigManager
from spwn.filemanager import FileManager

class CustomAnalyzer:
    def __init__(self, configs: ConfigManager, files: FileManager):
        self.configs = configs
        self.files = files
    
    def pre_analysis(self) -> None:
        for command, timeout in self.configs.preanalysis_commands:
            self.run_command(command, timeout)

    def post_analysis(self) -> None:
        for command, timeout in self.configs.postanalysis_commands:
            self.run_command(command, timeout)

    def run_command(self, command: str, timeout: int | bool | None) -> None:
        command = command.format(binary=self.files.binary.name, debug_binary=self.files.binary.debug_name)
        if timeout is not False:
            print(f"[*] {command}")
            if timeout:
                try:
                    # Use `exec command``, otherwise, because of `shell=True`, the process wouldn't be killed on timeout
                    p = subprocess.run(f"exec {command}", shell=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="latin-1")
                    print(p.stdout)
                except subprocess.TimeoutExpired:
                    print("[!] Timeout")
            else:
                p = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="latin-1")
                print(p.stdout)
        else:
            subprocess.Popen(command, shell=True, start_new_session=True)
