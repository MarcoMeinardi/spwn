import os
import requests
import json
import shutil


default_configs = {
	"debug_dir": "debug",
	"script_file": "a.py",
	"template_file": "~/.config/spwn/template.py",
	"yara_rules": "~/.config/spwn/findcrypt3.rules",
	"preanalysis_commands": [],
	"postanalysis_commands": [],
	"preanalysis_scripts": [],
	"postanalysis_scripts": [],
	"idafree_command": "",
	"decompiler_command": ""
}

default_template = '''
from pwn import *

binary_name = "{binary}"
exe  = ELF(binary_name, checksec=True)
libc = ELF("{libc}", checksec=False)
context.binary = exe

ru  = lambda *x: r.recvuntil(*x)
rl  = lambda *x: r.recvline(*x)
rc  = lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa  = lambda *x: r.sendafter(*x)
sl  = lambda *x: r.sendline(*x)
sn  = lambda *x: r.send(*x)

if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug(f"{debug_dir}/{{binary_name}}", """
		c
	""", aslr=False)
else:
	r = process(f"{debug_dir}/{{binary_name}}")

{interactions}


r.interactive()
'''[1:-1]


class ConfigGenerator:
	def maybe_create_config(self):
		self.check_dependencies()
		self.create_config_files()
		self.download_yara_rules()

	def check_dependencies(self):
		deps = ["patchelf", "file"]
		semi_deps = { "eu-unstrip": "elfutils", "seccomp-tools": "seccomp-tools" }

		err = False
		for dep in deps:
			if not shutil.which(dep):
				print(f"[ERROR] Please install {dep}")
				err = True

		for dep in semi_deps:
			if not shutil.which(dep):
				print(f"[WARNING] Please install {semi_deps[dep]}")

		if err:
			exit(1)

	def create_config_files(self):
		config_dir = os.path.expanduser("~/.config")
		if not os.path.exists(config_dir):
			os.mkdir(config_dir)

		configs_dir = os.path.expanduser("~/.config/spwn")
		if not os.path.exists(configs_dir):
			os.mkdir(configs_dir)

		configs_file = os.path.expanduser("~/.config/spwn/config.json")
		template_file = os.path.expanduser("~/.config/spwn/template.py")

		if not os.path.exists(configs_file):
			with open(configs_file, "w") as f:
				json.dump(default_configs, f, indent='\t')
		else:
			with open(configs_file) as f:
				user_configs = json.load(f)
			new_configs = default_configs | user_configs
			with open(configs_file, "w") as f:
				json.dump(new_configs, f, indent='\t')

		if not os.path.exists(template_file):
			with open(template_file, "w") as f:
				f.write(default_template)

	def download_yara_rules(self):
		rules_path = os.path.expanduser("~/.config/spwn/findcrypt3.rules")
		if not os.path.exists(rules_path):
			r = requests.get("https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules")
			assert r.status_code == 200, "Cannot download yara rules"

			with open(rules_path, "w") as f:
				f.write(r.text)
