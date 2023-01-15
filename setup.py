import setuptools
from setuptools.command.install import install
import os
import requests
import json


default_configs = {
	"debug_dir": "debug",
	"script_file": "a.py",
	"template_file": "~/.config/spwn/template.py",
	"yara_rules": "~/.config/spwn/findcrypt3.rules",
	"preanalysis_commands": [
		["true {binary} &> /dev/null", 1],
		["sleep 0", None]
	],
	"postanalysis_commands": [
		["false {debug_binary} &> /dev/null", False]
	],
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


# Copy configurations in ~/.config/spwn
class CreateConfigs(install):
	def run(self, *args, **kwargs):
		super().run(*args, **kwargs)
		self.create_config_files()
		self.download_yara_rules()

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


with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name="spwn",
	version="1.2",
	author="Chino",
	description="Automatic tool to quickly start a pwn CTF challenge",
	long_description=long_description,
	long_description_content_type="text/markdown",
	classifiers=[
		"Environment :: Console",
		"Operating System :: POSIX :: Linux",
		"Programming Language :: Python :: 3",
		"Topic :: Security",
		"Topic :: Software Development :: Code Generators"
	],
	packages=["spwn"],
	install_requires=[
		"pwntools",
		"yara-python"
	],
	entry_points={
		"console_scripts": ["spwn = spwn.spwn:main"]
	},
	cmdclass={
		"install": CreateConfigs
	},

	url="https://github.com/MarcoMeinardi/spwn"
)
