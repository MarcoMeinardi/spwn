import setuptools
from setuptools.command.install import install
import os
import requests

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
			default_configs_path = os.path.join(os.path.dirname(__file__), "default-config.json")
			with open(default_configs_path) as f:
				configs = f.read()
			with open(configs_file, "w") as f:
				f.write(configs)
		if not os.path.exists(template_file):
			default_template_path = os.path.join(os.path.dirname(__file__), "default-template.py")
			with open(default_template_path) as f:
				template = f.read()
			with open(template_file, "w") as f:
				f.write(template)
			
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
	version="1.1",
	author="Chino",
	description="Automatic tool to quickly start a pwn CTF challenge",
	long_description=long_description,
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

