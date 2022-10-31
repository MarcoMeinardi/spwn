import setuptools

with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name="spwn",
	version="0.1",
	author="Chino",
	description="Automatic tool to quickly start a pwn CTF challenge",
	long_description=long_description,
	packages=["spwn"],
	install_requires=[
		"pwntools",
	],
	entry_points={
		"console_scripts": ["spwn = spwn.spwn:main"]
	},
	url="https://github.com/MarcoMeinardi/spwn"
)

import os
# Copy configurations in ~/.config/spwn
DEFAULT_CONFIGURATIONS = '''
{
	"debug_dir": "debug",
	"script_file": "a.py",
	"template_file": "~/.config/spwn/template.py"
}
'''[1:]
config_dir = os.path.expanduser("~/.config/spwn")
if not os.path.exists(config_dir):
	os.mkdir(config_dir)

config_file = os.path.expanduser("~/.config/spwn/config.json")
template_file = os.path.expanduser("~/.config/spwn/template.py")
if not os.path.exists(config_file):
	with open(config_file, "w") as f:
		f.write(DEFAULT_CONFIGURATIONS)
if not os.path.exists(template_file):
	default_template_path = os.path.join(os.path.dirname(__file__), "spwn/default-template.py")
	with open(default_template_path) as f:
		template = f.read()
	with open(template_file, "w") as f:
		f.write(template)