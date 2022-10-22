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
