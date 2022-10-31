import setuptools
from setuptools.command.install import install
import os

# Copy configurations in ~/.config/spwn
class CreateConfigs(install):
	def run(self, *args, **kwargs):
		super().run(*args, **kwargs)
		config_dir = os.path.expanduser("~/.config/spwn")
		if not os.path.exists(config_dir):
			os.mkdir(config_dir)

		config_file = os.path.expanduser("~/.config/spwn/config.json")
		template_file = os.path.expanduser("~/.config/spwn/template.py")
		if not os.path.exists(config_file):
			default_config_path = os.path.join(os.path.dirname(__file__), "default-config.json")
			with open(default_config_path) as f:
				config = f.read()
			with open(config_file, "w") as f:
				f.write(config)
		if not os.path.exists(template_file):
			default_template_path = os.path.join(os.path.dirname(__file__), "default-template.py")
			with open(default_template_path) as f:
				template = f.read()
			with open(template_file, "w") as f:
				f.write(template)
		
		return True

with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name="spwn",
	version="1.0",
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
	cmdclass={
		"install": CreateConfigs
	},
	
	url="https://github.com/MarcoMeinardi/spwn"
)

