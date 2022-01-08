# Spwn

This repository is just the translation of [pwninit](https://github.com/io12/pwninit).
It has been created because I love the utilities provided by pwninit, but I'm to lazy to learn Rust and I wanted to customize it, so I rewrote it in python.

## Features
 * Auto detect files (binary, libc, loader)
 * Get loader from libc version (if missing)
 * Get an unstripped version of the libc
 * Set everything executable
 * Set runpath and interpreter for the debug binary
 * Generate a basic script with all the information about the files
 * Print basic info about the files (`file`, `checksec`, libc version, usually vulnerable functions)
 * Check if there might be seccomp and run `seccomp-tools dump`
 * Get gadgets with `ROPgadget`
 * Search basic gadgets with overcomplicated regex and put them in the base script

## Usage
Go into the directory with the challenge file and run:
`spwn` or `spwn rop` to get rop gadgets

## Installation
```
sudo apt install elfutils
sudo apt install binutils
sudo apt install patchelf
gem install seccomp-tools
pip install -r requirementes.txt
chmod +x spwn.py
sudo cp spwn.py /usr/bin/spwn
```
If you get errors with libarchive try following [this](https://stackoverflow.com/questions/29225812/libarchive-public-error-even-after-installing-libarchive-in-python) stackoverflow post or ignore them, since spwn can extract the needed files anyways.

You should modify the last line of `spwn.py` (`os.system(f"subl {exploit_name}")`) to launch the text editor you want to use to write the exploit (in my case sublime text).