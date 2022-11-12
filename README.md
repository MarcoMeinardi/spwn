# Spwn

This repository started as a tranlation of
[pwninit](https://github.com/io12/pwninit). It has been created because I
love the utilities provided by pwninit, but I'm to lazy to learn Rust and
I wanted to customize it, so I rewrote it in python (and added
some more features).

## Features
 * Auto detect files (binary, libc, loader)
 * Get loader from libc version (if missing)
 * Unstrip the libc with `pwn.libcdb.unstrip_libc`
 * Set binary and loader executable
 * Set runpath and interpreter for the debug binary
 * Generate a basic script from a template
 * Interactively generate functions to interact with the binary
 * Print basic info about the files:
   * `file`
   * `checksec`
   * libc version
   * potentially vulnerable functions
   * cryptographic constants
   * seccomp rules

## Usage
```
spwn [inter|i|-i] [help|h|-h] [ionly|io|-io]
	- inter:
	    Interactively create interaction functions
	- help:
	    Print this message
	- ionly:
		Create the interaction functions, without doing any analisy
```

If the files have weird namings (such as the libc name not starting with
libc), the autodetection will fail and fall in the manual selection,
the best fix for this is to rename the files.

To understand how the interactions creation works, I suggest to just try
it out. It should be pretty straight forward, but if you want to pwn
as fast as possible, you cannot waste any time :)

## Installation
Non python tools:
```bash
sudo apt update
sudo apt install patchelf elfutils ruby-dev
sudo gem install seccomp-tools
```
Main package:
```
pip install git+https://github.com/MarcoMeinardi/spwn
```
You might need to add `~/.local/bin/spwn` to your `$PATH`

## Customization
This tool is written because I wanted to customize `pwninit` as much
as possible. If you want to customize your own `spwn` you can:
 - Clone this repo
 - Modify whatever you want
 - In the repository's root directory: `pip install -U .`

or directly modify the files in:
`~/.local/lib/python3.{version}/site-packages/spwn`

Note that `default-template.py` is copied only on the first installation,
thus, if you want to modify the template, you have to edit the
`template.py` file, specified in the configs.

## Configurations
You can configure some stuffs in the config file. It's default location
is `~/.config/spwn/config.json`. In the same directory you can also find
`template.py`, the template of the script generated by `spwn`, which
you can modify to your liking.

The template path can be directly edited in the config file, however,
if you want to change the location of the config file, you have to
edit the source code. The variable is `CONFIG_PATH` in `spwn.py`.
It's location should be
`~/.local/lib/python3.{python-version}/site-packages/spwn/spwn.py`.
Note that if you reinstall or update `spwn`,
this variable will be overwritten.


If you have any question or feature request, feel free to ask
[here](https://github.com/MarcoMeinardi/spwn/issues).
