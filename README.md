# Spwn

This repository is just the translation of
[pwninit](https://github.com/io12/pwninit). It has been created because I
love the utilities provided by pwninit, but I'm to lazy to learn Rust and
I wanted to customize it, so I rewrote it in python (and added
some more features).

## Features
 * Auto detect files (binary, libc, loader)
 * Get loader from libc version (if missing)
 * Unstrip the libc with `pwn.libcdb.unstrip_libc`
 * Set everything executable
 * Set runpath and interpreter for the debug binary
 * Generate a basic script with all the information about the files
 * Interactively generate functions to interact with the binary
 * Print basic info about the files (`file`, `checksec`, libc
 version, potentially vulnerable functions)
 * Check if there might be seccomp and run `seccomp-tools dump`

## Usage
Go into the directory with the challenge file and run: `spwn`
If the files have weird namings (such as the libc name not starting with
libc), the autodetection will fail and fall in the manual selection,
the best fix for this is to rename the files.

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
You might need to add `~/.local/bin/spwn` to your `PATH`