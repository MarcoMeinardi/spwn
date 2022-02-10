# Spwn

This repository is just the translation of [pwninit](https://github.com/io12/pwninit).
It has been created because I love the utilities provided by pwninit, but I'm to lazy to learn Rust and I wanted to customize it, so I rewrote it in python (and added some more features).

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
If the files have weird namings (such as the libc name not starting with libc), the autodetection will probably fail, so just use `spwn manual [rop]` to immediately switch to manual selection.

## Installation
```
sudo apt install elfutils
sudo apt install binutils
sudo apt install patchelf
sudo gem install seccomp-tools

git clone https://github.com/MarcoMeinardi/spwn.git
cd spwn
pip install -r requirements.txt
cd src
zip spwn.zip *
echo '#!/usr/bin/env python3' | cat - spwn.zip > spwn
rm spwn.zip
chmod +x spwn
sudo mv spwn /usr/bin/spwn
```