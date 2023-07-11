import setuptools


with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name="spwn",
	version="1.2.5",
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

	url="https://github.com/MarcoMeinardi/spwn"
)
