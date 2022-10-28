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
 * Generate a basic script to launch the files in different ways
 * Interactively generate functions to interact with the binary
 * Print basic info about the files (`file`, `checksec`, libc
 version, potentially vulnerable functions)
 * Check if there might be seccomp and run `seccomp-tools dump`

## Usage
Go into the directory with the challenge files and run `spwn` or `spwn inter`
if you want to create the interaction funcitons or `spwn help` to view the
help message.

If the files have weird namings (such as the libc name not starting with
libc), the autodetection will fail and fall in the manual selection,
the best fix for this is to rename the files.

To understand how the interactions creation works, I suggest to just try
it out. It should be pretty straight forward, but if you want to pwn
as fast as possible, you cannot waste any time :)

## Installation
Non python tools:
```bash
sudo apt install patchelf gem
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

Easiest customizations:
 - Template script: `template.py` or whatever you want by modifying
 the `TEMPLATE_FILE` in `spwn.py`
 - Debug directory and script default name: `DEBUG_DIR` and `SCRIPT_FILE`
 in `spwn.py`

If you have any questions or feature requests, feel free to ask
[here](https://github.com/MarcoMeinardi/spwn/issues).
